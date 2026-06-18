package com.kcops.mcp.audit;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kcops.mcp.config.KcopsProperties;
import java.nio.file.Path;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

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
    public Mono<ResponseEntity<VerificationResult>> verify() {
        return Mono.fromCallable(() -> ResponseEntity.ok(AuditLogger.verifyDetailed(
                        Path.of(properties.getAuditLogPath()),
                        Path.of(properties.getAuditAnchorPath()),
                        objectMapper
                )))
                .subscribeOn(Schedulers.boundedElastic());
    }

    @PostMapping("/anchor")
    public Mono<ResponseEntity<AnchorEntry>> publishAnchor() {
        return Mono.fromCallable(() -> ResponseEntity.ok(anchorStore.publish()))
                .subscribeOn(Schedulers.boundedElastic());
    }
}
