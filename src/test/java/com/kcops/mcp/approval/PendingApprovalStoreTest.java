package com.kcops.mcp.approval;

import com.kcops.mcp.audit.AuditDirection;
import com.kcops.mcp.detector.PolicyCategory;
import com.kcops.mcp.policy.Action;
import com.kcops.mcp.policy.PolicyDecision;
import java.util.List;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class PendingApprovalStoreTest {

    private final PendingApprovalStore store = new PendingApprovalStore();

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

    private PolicyDecision decision() {
        return new PolicyDecision(
                Action.REQUIRE_APPROVAL,
                "DESTRUCTIVE_OR_CODE_EXECUTION_REQUEST",
                List.of("destructive_command", "high_risk_tool"),
                List.of(PolicyCategory.DESTRUCTIVE, PolicyCategory.TOOL_CALL)
        );
    }
}
