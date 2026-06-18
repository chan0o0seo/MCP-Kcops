package com.kcops.mcp.audit;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kcops.mcp.config.KcopsProperties;
import java.nio.file.Path;
import org.springframework.context.annotation.Profile;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/admin/audit")
@Profile("!mock")
public class AuditAdminController {

    private final AuditAnchorStore anchorStore;
    private final KcopsProperties properties;
    private final ObjectMapper objectMapper;

    public AuditAdminController(
            AuditAnchorStore anchorStore,
            KcopsProperties properties,
            ObjectMapper objectMapper
    ) {
        this.anchorStore = anchorStore;
        this.properties = properties;
        this.objectMapper = objectMapper;
    }

    @GetMapping("/verify")
    public VerificationResult verify() {
        return AuditLogger.verifyDetailed(
                Path.of(properties.getAuditLogPath()),
                Path.of(properties.getAuditAnchorPath()),
                objectMapper
        );
    }

    @PostMapping("/anchor")
    public AnchorEntry publishAnchor() {
        return anchorStore.publish();
    }
}
