package com.kcops.mcp.approval;

import com.kcops.mcp.audit.AuditDirection;
import com.kcops.mcp.config.KcopsProperties;
import com.kcops.mcp.detector.PolicyCategory;
import com.kcops.mcp.policy.Action;
import com.kcops.mcp.policy.PolicyDecision;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.List;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class PendingApprovalStoreTest {

    private final PendingApprovalStore store = storeWithLimit(1000);

    @Test
    void addExposesOnlyPendingMetadataAndApproveTransitionsStatus() {
        store.add("trace-1", AuditDirection.AGENT_TO_MCP_SERVER, "execute_shell", decision());

        assertThat(store.pending()).singleElement().satisfies(approval -> {
            assertThat(approval.traceId()).isEqualTo("trace-1");
            assertThat(approval.direction()).isEqualTo(AuditDirection.AGENT_TO_MCP_SERVER);
            assertThat(approval.tool()).isEqualTo("execute_shell");
            assertThat(approval.reason()).isEqualTo("DESTRUCTIVE_OR_CODE_EXECUTION_REQUEST");
            assertThat(approval.detectors()).containsExactly("destructive_command", "high_risk_tool");
            assertThat(approval.categories()).containsExactly("DESTRUCTIVE", "TOOL_CALL");
            assertThat(approval.createdAt()).isNotBlank();
            assertThat(approval.status()).isEqualTo(ApprovalStatus.PENDING);
        });

        assertThat(store.approve("trace-1"))
                .get()
                .extracting(PendingApproval::status)
                .isEqualTo(ApprovalStatus.APPROVED);
        assertThat(store.pending()).isEmpty();
        assertThat(store.approve("trace-1")).isEmpty();
    }

    @Test
    void storesRequestBodyAndHashAndPreservesThemAcrossStatusTransitions() {
        String body = "{\"command\":\"rm -rf /tmp/work\"}";
        store.add(
                "trace-body",
                AuditDirection.AGENT_TO_MCP_SERVER,
                "execute_shell",
                decision(),
                body
        );

        PendingApproval pending = store.find("trace-body").orElseThrow();
        assertThat(pending.requestBody()).isEqualTo(body);
        assertThat(pending.bodyHash()).isEqualTo(PendingApprovalStore.sha256Hex(body));

        PendingApproval approved = store.approve("trace-body").orElseThrow();
        assertThat(approved.requestBody()).isEqualTo(body);
        assertThat(approved.bodyHash()).isEqualTo(pending.bodyHash());
    }

    @Test
    void consumesApprovedMatchingRequestExactlyOnce() {
        String body = "{\"command\":\"rm -rf /tmp/work\"}";
        store.add(
                "trace-consume",
                AuditDirection.AGENT_TO_MCP_SERVER,
                "execute_shell",
                decision(),
                body
        );
        store.approve("trace-consume");

        assertThat(store.consumeApproved("trace-consume", PendingApprovalStore.sha256Hex(body)))
                .contains(body);
        assertThat(store.find("trace-consume"))
                .get()
                .extracting(PendingApproval::status)
                .isEqualTo(ApprovalStatus.CONSUMED);
        assertThat(store.consumeApproved("trace-consume", PendingApprovalStore.sha256Hex(body)))
                .isEmpty();
    }

    @Test
    void rejectsHashMismatchPendingDeniedAndMissingApprovals() {
        String body = "{\"command\":\"rm -rf /tmp/work\"}";
        store.add("approved", AuditDirection.AGENT_TO_MCP_SERVER, "execute_shell", decision(), body);
        store.approve("approved");
        store.add("pending", AuditDirection.AGENT_TO_MCP_SERVER, "execute_shell", decision(), body);
        store.add("denied", AuditDirection.AGENT_TO_MCP_SERVER, "execute_shell", decision(), body);
        store.deny("denied");

        assertThat(store.consumeApproved("approved", PendingApprovalStore.sha256Hex(body + " changed")))
                .isEmpty();
        assertThat(store.find("approved"))
                .get()
                .extracting(PendingApproval::status)
                .isEqualTo(ApprovalStatus.APPROVED);
        assertThat(store.consumeApproved("pending", PendingApprovalStore.sha256Hex(body))).isEmpty();
        assertThat(store.consumeApproved("denied", PendingApprovalStore.sha256Hex(body))).isEmpty();
        assertThat(store.consumeApproved("missing", PendingApprovalStore.sha256Hex(body))).isEmpty();
    }

    @Test
    void denyTransitionsStatusAndMissingTraceIdReturnsEmpty() {
        store.add("trace-2", AuditDirection.MCP_SERVER_TO_AGENT, null, decision());

        assertThat(store.deny("trace-2"))
                .get()
                .extracting(PendingApproval::status)
                .isEqualTo(ApprovalStatus.DENIED);
        assertThat(store.find("trace-2"))
                .get()
                .extracting(PendingApproval::status)
                .isEqualTo(ApprovalStatus.DENIED);
        assertThat(store.deny("missing")).isEmpty();
        assertThat(store.approve("missing")).isEmpty();
    }

    @Test
    void supportsConcurrentAdds() {
        int count = 200;

        IntStream.range(0, count).parallel().forEach(index ->
                store.add(
                        "trace-" + index,
                        AuditDirection.AGENT_TO_MCP_SERVER,
                        "execute_shell",
                        decision()
                ));

        assertThat(store.pending()).hasSize(count);
        assertThat(IntStream.range(0, count)
                .allMatch(index -> store.find("trace-" + index).isPresent())).isTrue();
    }

    @Test
    void evictsOldestCompletedBeforePendingAndKeepsConfiguredLimit() {
        PendingApprovalStore limited = storeWithLimit(2);
        limited.add("trace-1", AuditDirection.AGENT_TO_MCP_SERVER, "tool", decision());
        limited.approve("trace-1");
        limited.add("trace-2", AuditDirection.AGENT_TO_MCP_SERVER, "tool", decision());
        limited.add("trace-3", AuditDirection.AGENT_TO_MCP_SERVER, "tool", decision());

        assertThat(limited.find("trace-1")).isEmpty();
        assertThat(limited.pending()).extracting(PendingApproval::traceId)
                .containsExactly("trace-2", "trace-3");

        limited.add("trace-4", AuditDirection.AGENT_TO_MCP_SERVER, "tool", decision());

        assertThat(limited.pending()).hasSize(2);
        assertThat(IntStream.rangeClosed(1, 4)
                .filter(index -> limited.find("trace-" + index).isPresent())
                .count()).isEqualTo(2);
    }

    @Test
    void expiresPendingAfterTtlButKeepsApproved() {
        TestClock clock = new TestClock(Instant.parse("2026-06-19T00:00:00Z"));
        PendingApprovalStore ttlStore = storeWithTtl(60, clock);
        ttlStore.add("pending", AuditDirection.AGENT_TO_MCP_SERVER, "tool", decision());
        ttlStore.add("approved", AuditDirection.AGENT_TO_MCP_SERVER, "tool", decision());
        ttlStore.approve("approved");

        clock.advance(Duration.ofSeconds(61));

        assertThat(ttlStore.pending()).isEmpty();
        assertThat(ttlStore.find("pending")).isEmpty();
        assertThat(ttlStore.find("approved"))
                .get()
                .extracting(PendingApproval::status)
                .isEqualTo(ApprovalStatus.APPROVED);
    }

    @Test
    void nonPositiveTtlDoesNotExpirePending() {
        TestClock clock = new TestClock(Instant.parse("2026-06-19T00:00:00Z"));
        PendingApprovalStore ttlStore = storeWithTtl(0, clock);
        ttlStore.add("pending", AuditDirection.AGENT_TO_MCP_SERVER, "tool", decision());

        clock.advance(Duration.ofDays(365));

        assertThat(ttlStore.pending()).extracting(PendingApproval::traceId)
                .containsExactly("pending");
        assertThat(ttlStore.find("pending")).isPresent();
    }

    private PolicyDecision decision() {
        return new PolicyDecision(
                Action.REQUIRE_APPROVAL,
                "DESTRUCTIVE_OR_CODE_EXECUTION_REQUEST",
                List.of("destructive_command", "high_risk_tool"),
                List.of(PolicyCategory.DESTRUCTIVE, PolicyCategory.TOOL_CALL)
        );
    }

    private PendingApprovalStore storeWithLimit(int maxPending) {
        KcopsProperties properties = new KcopsProperties();
        properties.getApproval().setMaxPending(maxPending);
        return new PendingApprovalStore(properties);
    }

    private PendingApprovalStore storeWithTtl(int ttlSeconds, Clock clock) {
        KcopsProperties properties = new KcopsProperties();
        properties.getApproval().setTtlSeconds(ttlSeconds);
        return new PendingApprovalStore(properties, clock);
    }

    private static final class TestClock extends Clock {
        private Instant instant;

        private TestClock(Instant instant) {
            this.instant = instant;
        }

        private void advance(Duration duration) {
            instant = instant.plus(duration);
        }

        @Override
        public ZoneId getZone() {
            return ZoneId.of("Asia/Seoul");
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return Clock.fixed(instant, zone);
        }

        @Override
        public Instant instant() {
            return instant;
        }
    }
}
