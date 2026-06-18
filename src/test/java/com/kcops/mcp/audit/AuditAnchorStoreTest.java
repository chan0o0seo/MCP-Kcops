package com.kcops.mcp.audit;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kcops.mcp.config.KcopsProperties;
import com.kcops.mcp.policy.Action;
import com.kcops.mcp.policy.PolicyDecision;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.assertj.core.api.Assertions.assertThat;

class AuditAnchorStoreTest {

    @TempDir
    Path tempDir;

    @Test
    void publishesEmptyAndLatestLogStateWithoutOverwritingExistingAnchors() throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();
        Path auditPath = tempDir.resolve("audit.jsonl");
        Path anchorPath = tempDir.resolve("audit-anchor.jsonl");
        KcopsProperties properties = new KcopsProperties();
        properties.setAuditLogPath(auditPath.toString());
        properties.setAuditAnchorPath(anchorPath.toString());
        AuditAnchorStore store = new AuditAnchorStore(properties, objectMapper);

        AnchorEntry empty = store.publish();
        assertThat(empty.recordCount()).isZero();
        assertThat(empty.latestHash()).isEqualTo(AuditLogger.GENESIS);

        AuditLogger logger = new AuditLogger(properties, objectMapper);
        AuditRecord record = logger.log(
                "trace-1",
                AuditDirection.AGENT_TO_MCP_SERVER,
                "mock",
                "tool",
                new PolicyDecision(Action.ALLOW, "NO_FINDINGS", List.of(), List.of()),
                1
        );
        AnchorEntry populated = store.publish();

        assertThat(populated.recordCount()).isEqualTo(1);
        assertThat(populated.latestHash()).isEqualTo(record.hash());
        List<String> anchors = Files.readAllLines(anchorPath, StandardCharsets.UTF_8);
        assertThat(anchors).hasSize(2);
        assertThat(objectMapper.readValue(anchors.get(0), AnchorEntry.class)).isEqualTo(empty);
        assertThat(objectMapper.readValue(anchors.get(1), AnchorEntry.class)).isEqualTo(populated);
    }
}
