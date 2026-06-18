package com.kcops.mcp.audit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.kcops.mcp.config.KcopsProperties;
import com.kcops.mcp.policy.Action;
import com.kcops.mcp.policy.PolicyDecision;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
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

    @Test
    void detailedVerificationReportsFirstTamperedLine() throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();
        Path auditPath = createLog(objectMapper, 3);

        VerificationResult valid = AuditLogger.verifyDetailed(auditPath, null, objectMapper);
        assertThat(valid).isEqualTo(new VerificationResult(true, -1, true));

        List<String> lines = Files.readAllLines(auditPath, StandardCharsets.UTF_8);
        lines.set(1, lines.get(1).replace("NO_FINDINGS", "ALTERED"));
        Files.write(auditPath, lines, StandardCharsets.UTF_8);

        VerificationResult tampered = AuditLogger.verifyDetailed(auditPath, null, objectMapper);
        assertThat(tampered.valid()).isFalse();
        assertThat(tampered.brokenAtLine()).isEqualTo(2);
    }

    @Test
    void detailedVerificationDetectsRemovedMiddleRecord() throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();
        Path auditPath = createLog(objectMapper, 3);
        List<String> lines = Files.readAllLines(auditPath, StandardCharsets.UTF_8);
        lines.remove(1);
        Files.write(auditPath, lines, StandardCharsets.UTF_8);

        VerificationResult result = AuditLogger.verifyDetailed(auditPath, null, objectMapper);

        assertThat(result.valid()).isFalse();
        assertThat(result.brokenAtLine()).isEqualTo(2);
    }

    @Test
    void detailedVerificationAcceptsMatchingAnchor() throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();
        Path auditPath = createLog(objectMapper, 2);
        Path anchorPath = tempDir.resolve("anchor.jsonl");
        String latestHash = objectMapper.readTree(
                Files.readAllLines(auditPath, StandardCharsets.UTF_8).get(1)
        ).path("hash").asText();
        Files.writeString(
                anchorPath,
                objectMapper.writeValueAsString(new AnchorEntry("2026-06-18T12:00:00+09:00", 2, latestHash)),
                StandardCharsets.UTF_8
        );

        VerificationResult result = AuditLogger.verifyDetailed(auditPath, anchorPath, objectMapper);

        assertThat(result.valid()).isTrue();
        assertThat(result.brokenAtLine()).isEqualTo(-1);
        assertThat(result.anchorConsistent()).isTrue();
    }

    @Test
    void detailedVerificationDetectsRecalculatedChainAgainstPublishedAnchor() throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();
        Path auditPath = createLog(objectMapper, 3);
        Path anchorPath = tempDir.resolve("anchor.jsonl");
        List<String> original = Files.readAllLines(auditPath, StandardCharsets.UTF_8);
        String originalLatestHash = objectMapper.readTree(original.get(2)).path("hash").asText();
        Files.writeString(
                anchorPath,
                objectMapper.writeValueAsString(
                        new AnchorEntry("2026-06-18T12:00:00+09:00", 3, originalLatestHash)
                ),
                StandardCharsets.UTF_8
        );

        rechainWithChangedReason(auditPath, objectMapper, 1);

        VerificationResult result = AuditLogger.verifyDetailed(auditPath, anchorPath, objectMapper);
        assertThat(result.valid()).isTrue();
        assertThat(result.brokenAtLine()).isEqualTo(-1);
        assertThat(result.anchorConsistent()).isFalse();
    }

    private Path createLog(ObjectMapper objectMapper, int count) {
        Path auditPath = tempDir.resolve("audit-" + count + "-" + System.nanoTime() + ".jsonl");
        KcopsProperties properties = new KcopsProperties();
        properties.setAuditLogPath(auditPath.toString());
        AuditLogger logger = new AuditLogger(properties, objectMapper);
        for (int i = 1; i <= count; i++) {
            logger.log(
                    "trace-" + i,
                    AuditDirection.AGENT_TO_MCP_SERVER,
                    "mock",
                    "tool",
                    new PolicyDecision(Action.ALLOW, "NO_FINDINGS", List.of(), List.of()),
                    i
            );
        }
        return auditPath;
    }

    private void rechainWithChangedReason(Path auditPath, ObjectMapper objectMapper, int changedIndex)
            throws Exception {
        List<String> lines = Files.readAllLines(auditPath, StandardCharsets.UTF_8);
        String previous = AuditLogger.GENESIS;
        for (int i = 0; i < lines.size(); i++) {
            AuditRecord original = objectMapper.readValue(lines.get(i), AuditRecord.class);
            AuditRecord withoutHash = new AuditRecord(
                    original.traceId(),
                    original.timestamp(),
                    original.direction(),
                    original.server(),
                    original.tool(),
                    original.decision(),
                    i == changedIndex ? "ALTERED_AND_RECALCULATED" : original.reason(),
                    original.detectors(),
                    original.piiMasked(),
                    original.fingerprintChanged(),
                    original.latencyMs(),
                    previous,
                    null
            );
            String hash = sha256Hex(previous + canonicalJsonWithoutHash(withoutHash, objectMapper));
            AuditRecord recalculated = new AuditRecord(
                    withoutHash.traceId(),
                    withoutHash.timestamp(),
                    withoutHash.direction(),
                    withoutHash.server(),
                    withoutHash.tool(),
                    withoutHash.decision(),
                    withoutHash.reason(),
                    withoutHash.detectors(),
                    withoutHash.piiMasked(),
                    withoutHash.fingerprintChanged(),
                    withoutHash.latencyMs(),
                    withoutHash.prevHash(),
                    hash
            );
            lines.set(i, objectMapper.writeValueAsString(recalculated));
            previous = hash;
        }
        Files.write(auditPath, lines, StandardCharsets.UTF_8);
    }

    private String canonicalJsonWithoutHash(AuditRecord record, ObjectMapper objectMapper) throws Exception {
        Map<String, Object> values = new LinkedHashMap<>();
        values.put("traceId", record.traceId());
        values.put("timestamp", record.timestamp());
        values.put("direction", record.direction());
        values.put("server", record.server());
        values.put("tool", record.tool());
        values.put("decision", record.decision());
        values.put("reason", record.reason());
        values.put("detectors", record.detectors() == null ? List.of() : record.detectors());
        values.put("piiMasked", record.piiMasked());
        values.put("fingerprintChanged", record.fingerprintChanged());
        values.put("latencyMs", record.latencyMs());
        values.put("prevHash", record.prevHash());
        return objectMapper.writeValueAsString(values);
    }

    private String sha256Hex(String value) throws Exception {
        byte[] bytes = MessageDigest.getInstance("SHA-256")
                .digest(value.getBytes(StandardCharsets.UTF_8));
        StringBuilder builder = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            builder.append(String.format("%02x", b));
        }
        return builder.toString();
    }
}
