package com.kcops.mcp.audit;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kcops.mcp.config.KcopsProperties;
import java.nio.file.Path;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

@Component
@Profile("!mock")
public class AuditStartupVerifier implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(AuditStartupVerifier.class);

    private final KcopsProperties properties;
    private final ObjectMapper objectMapper;

    public AuditStartupVerifier(KcopsProperties properties, ObjectMapper objectMapper) {
        this.properties = properties;
        this.objectMapper = objectMapper;
    }

    @Override
    public void run(ApplicationArguments args) {
        VerificationResult result = AuditLogger.verifyDetailed(
                Path.of(properties.getAuditLogPath()),
                Path.of(properties.getAuditAnchorPath()),
                objectMapper
        );
        if (!result.valid()) {
            log.warn("감사 로그 무결성 검증 실패: brokenAtLine={}", result.brokenAtLine());
        }
        if (!result.anchorConsistent()) {
            log.warn("감사 로그 앵커 불일치 — 전체 재계산 정황: anchorPath={}",
                    properties.getAuditAnchorPath());
        }
        if (result.valid() && result.anchorConsistent()) {
            log.info("감사 로그 무결성 검증 성공");
        }
    }
}
