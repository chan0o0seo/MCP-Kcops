package com.kcops.mcp.audit;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kcops.mcp.config.KcopsProperties;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class AuditAnchorStore {

    private static final Logger log = LoggerFactory.getLogger(AuditAnchorStore.class);
    private static final ZoneId SEOUL = ZoneId.of("Asia/Seoul");

    private final Path auditLogPath;
    private final Path anchorPath;
    private final ObjectMapper objectMapper;

    public AuditAnchorStore(KcopsProperties properties, ObjectMapper objectMapper) {
        this.auditLogPath = Path.of(properties.getAuditLogPath());
        this.anchorPath = Path.of(properties.getAuditAnchorPath());
        this.objectMapper = objectMapper;
    }

    public synchronized AnchorEntry publish() {
        int recordCount = 0;
        String latestHash = AuditLogger.GENESIS;
        try {
            if (Files.exists(auditLogPath)) {
                for (String line : Files.readAllLines(auditLogPath, StandardCharsets.UTF_8)) {
                    if (line.isBlank()) {
                        continue;
                    }
                    recordCount++;
                    latestHash = objectMapper.readTree(line).path("hash").asText(AuditLogger.GENESIS);
                }
            }
        } catch (IOException | RuntimeException ex) {
            log.warn("감사 로그 앵커 계산 실패: path={}", auditLogPath, ex);
            recordCount = 0;
            latestHash = AuditLogger.GENESIS;
        }

        AnchorEntry entry = new AnchorEntry(
                OffsetDateTime.now(SEOUL).format(DateTimeFormatter.ISO_OFFSET_DATE_TIME),
                recordCount,
                latestHash
        );
        try {
            Path parent = anchorPath.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Files.writeString(
                    anchorPath,
                    objectMapper.writeValueAsString(entry) + System.lineSeparator(),
                    StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.APPEND
            );
        } catch (IOException ex) {
            log.warn("감사 로그 앵커 게시 실패: path={}", anchorPath, ex);
        }
        return entry;
    }
}
