package com.kcops.mcp.audit;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.kcops.mcp.config.KcopsProperties;
import com.kcops.mcp.policy.PolicyDecision;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

@Component
public class AuditLogger {

    public static final String GENESIS = "GENESIS";
    private static final ZoneId SEOUL = ZoneId.of("Asia/Seoul");
    private final ObjectMapper objectMapper;
    private final Path path;
    private String previousHash;

    public AuditLogger(KcopsProperties properties, ObjectMapper objectMapper) {
        this.objectMapper = objectMapper.copy()
                .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, false);
        this.path = Path.of(properties.getAuditLogPath());
        this.previousHash = readLastHash(path);
    }

    public synchronized AuditRecord log(
            String traceId,
            AuditDirection direction,
            String server,
            String tool,
            PolicyDecision decision,
            long latencyMs
    ) {
        String prev = previousHash == null ? GENESIS : previousHash;
        AuditRecord withoutHash = new AuditRecord(
                traceId,
                OffsetDateTime.now(SEOUL).format(DateTimeFormatter.ISO_OFFSET_DATE_TIME),
                direction,
                server,
                tool,
                decision.action(),
                decision.reason(),
                decision.detectors(),
                latencyMs,
                prev,
                null
        );
        String hash = sha256Hex(prev + canonicalJsonWithoutHash(withoutHash));
        AuditRecord record = new AuditRecord(
                withoutHash.traceId(),
                withoutHash.timestamp(),
                withoutHash.direction(),
                withoutHash.server(),
                withoutHash.tool(),
                withoutHash.decision(),
                withoutHash.reason(),
                withoutHash.detectors(),
                withoutHash.latencyMs(),
                withoutHash.prevHash(),
                hash
        );
        append(record);
        previousHash = hash;
        return record;
    }

    public static boolean verify(Path path, ObjectMapper objectMapper) {
        if (!Files.exists(path)) {
            return true;
        }
        String previous = GENESIS;
        try {
            for (String line : Files.readAllLines(path, StandardCharsets.UTF_8)) {
                if (line.isBlank()) {
                    continue;
                }
                JsonNode node = objectMapper.readTree(line);
                String prevHash = node.path("prevHash").asText();
                String hash = node.path("hash").asText();
                AuditRecord record = objectMapper.treeToValue(node, AuditRecord.class);
                String expected = sha256Hex(prevHash + canonicalJsonWithoutHash(record, objectMapper));
                if (!previous.equals(prevHash) || !expected.equals(hash)) {
                    return false;
                }
                previous = hash;
            }
            return true;
        } catch (IOException ex) {
            return false;
        }
    }

    private void append(AuditRecord record) {
        try {
            Path parent = path.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Files.writeString(path, objectMapper.writeValueAsString(record) + System.lineSeparator(),
                    StandardCharsets.UTF_8,
                    Files.exists(path)
                            ? new java.nio.file.OpenOption[]{java.nio.file.StandardOpenOption.APPEND}
                            : new java.nio.file.OpenOption[]{java.nio.file.StandardOpenOption.CREATE_NEW});
        } catch (IOException ex) {
            throw new IllegalStateException("Failed to append audit log: " + path, ex);
        }
    }

    private String readLastHash(Path target) {
        if (!Files.exists(target)) {
            return GENESIS;
        }
        try {
            String last = null;
            for (String line : Files.readAllLines(target, StandardCharsets.UTF_8)) {
                if (!line.isBlank()) {
                    last = line;
                }
            }
            if (last == null) {
                return GENESIS;
            }
            return objectMapper.readTree(last).path("hash").asText(GENESIS);
        } catch (IOException ex) {
            return GENESIS;
        }
    }

    private String canonicalJsonWithoutHash(AuditRecord record) {
        return canonicalJsonWithoutHash(record, objectMapper);
    }

    private static String canonicalJsonWithoutHash(AuditRecord record, ObjectMapper mapper) {
        Map<String, Object> values = new LinkedHashMap<>();
        values.put("traceId", record.traceId());
        values.put("timestamp", record.timestamp());
        values.put("direction", record.direction());
        values.put("server", record.server());
        values.put("tool", record.tool());
        values.put("decision", record.decision());
        values.put("reason", record.reason());
        values.put("detectors", record.detectors() == null ? List.of() : record.detectors());
        values.put("latencyMs", record.latencyMs());
        values.put("prevHash", record.prevHash());
        try {
            return mapper.writeValueAsString(values);
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException("Failed to serialize audit record", ex);
        }
    }

    private static String sha256Hex(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] bytes = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder builder = new StringBuilder(bytes.length * 2);
            for (byte b : bytes) {
                builder.append(String.format("%02x", b));
            }
            return builder.toString();
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is not available", ex);
        }
    }
}
