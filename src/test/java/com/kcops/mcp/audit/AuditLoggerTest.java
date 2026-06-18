package com.kcops.mcp.audit;

import com.fasterxml.jackson.databind.JsonNode;
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

class AuditLoggerTest {

    @TempDir
    Path tempDir;

    @Test
    void chainsHashesAndDetectsTampering() throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();
        Path auditPath = tempDir.resolve("audit.jsonl");
        KcopsProperties properties = new KcopsProperties();
        properties.setAuditLogPath(auditPath.toString());
        AuditLogger logger = new AuditLogger(properties, objectMapper);

        AuditRecord first = logger.log("trace-1", AuditDirection.AGENT_TO_MCP_SERVER, "mock", "tool",
                new PolicyDecision(Action.ALLOW, "NO_FINDINGS", List.of(), List.of()), 1);
        AuditRecord second = logger.log("trace-2", AuditDirection.MCP_SERVER_TO_AGENT, "mock", "tool",
                new PolicyDecision(Action.BLOCK, "PROMPT_INJECTION",
                        List.of("PromptInjectionResponseDetector"), List.of()), 2, true, true);

        List<String> lines = Files.readAllLines(auditPath, StandardCharsets.UTF_8);
        JsonNode secondNode = objectMapper.readTree(lines.get(1));
        assertThat(first.prevHash()).isEqualTo(AuditLogger.GENESIS);
        assertThat(second.prevHash()).isEqualTo(first.hash());
        assertThat(secondNode.path("prevHash").asText()).isEqualTo(first.hash());
        assertThat(secondNode.path("piiMasked").asBoolean()).isTrue();
        assertThat(secondNode.path("fingerprintChanged").asBoolean()).isTrue();
        assertThat(lines.get(1).indexOf("\"detectors\""))
                .isLessThan(lines.get(1).indexOf("\"piiMasked\""));
        assertThat(lines.get(1).indexOf("\"piiMasked\""))
                .isLessThan(lines.get(1).indexOf("\"fingerprintChanged\""));
        assertThat(lines.get(1).indexOf("\"fingerprintChanged\""))
                .isLessThan(lines.get(1).indexOf("\"latencyMs\""));
        assertThat(AuditLogger.verify(auditPath, objectMapper)).isTrue();

        Files.writeString(auditPath, Files.readString(auditPath).replace("PROMPT_INJECTION", "ALTERED"),
                StandardCharsets.UTF_8);

        assertThat(AuditLogger.verify(auditPath, objectMapper)).isFalse();
    }
}
