package com.kcops.mcp.approval;

import com.kcops.mcp.audit.AuditLogger;
import com.kcops.mcp.config.KcopsProperties;
import com.kcops.mcp.policy.Action;
import com.kcops.mcp.policy.PolicyDecision;
import java.util.List;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

@RestController
@RequestMapping("/admin/approvals")
@Profile("!mock")
public class ApprovalController {

    private final PendingApprovalStore store;
    private final AuditLogger auditLogger;
    private final KcopsProperties properties;

    public ApprovalController(
            PendingApprovalStore store,
            AuditLogger auditLogger,
            KcopsProperties properties
    ) {
        this.store = store;
        this.auditLogger = auditLogger;
        this.properties = properties;
    }

    @GetMapping
    public List<PendingApproval> pending() {
        return store.pending();
    }

    @PostMapping("/{traceId}/approve")
    public Mono<ResponseEntity<PendingApproval>> approve(@PathVariable String traceId) {
        return Mono.fromCallable(() -> store.approve(traceId)
                        .map(approval -> {
                            audit(approval, Action.ALLOW, "APPROVAL_GRANTED");
                            return ResponseEntity.ok(approval);
                        })
                        .orElseGet(() -> ResponseEntity.notFound().build()))
                .subscribeOn(Schedulers.boundedElastic());
    }

    @PostMapping("/{traceId}/deny")
    public Mono<ResponseEntity<PendingApproval>> deny(@PathVariable String traceId) {
        return Mono.fromCallable(() -> store.deny(traceId)
                        .map(approval -> {
                            audit(approval, Action.BLOCK, "APPROVAL_DENIED");
                            return ResponseEntity.ok(approval);
                        })
                        .orElseGet(() -> ResponseEntity.notFound().build()))
                .subscribeOn(Schedulers.boundedElastic());
    }

    private void audit(PendingApproval approval, Action action, String reason) {
        auditLogger.log(
                approval.traceId(),
                approval.direction(),
                properties.getUpstreamUrl(),
                approval.tool(),
                new PolicyDecision(action, reason, approval.detectors(), List.of()),
                0
        );
    }
}
