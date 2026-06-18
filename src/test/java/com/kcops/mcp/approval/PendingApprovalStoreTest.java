package com.kcops.mcp.approval;

import com.kcops.mcp.audit.AuditDirection;
import com.kcops.mcp.config.KcopsProperties;
import com.kcops.mcp.detector.PolicyCategory;
import com.kcops.mcp.policy.Action;
import com.kcops.mcp.policy.PolicyDecision;
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
}
