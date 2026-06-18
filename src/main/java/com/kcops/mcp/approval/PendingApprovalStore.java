package com.kcops.mcp.approval;

import com.kcops.mcp.audit.AuditDirection;
import com.kcops.mcp.policy.PolicyDecision;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicReference;
import org.springframework.stereotype.Component;

@Component
public class PendingApprovalStore {

    private static final ZoneId SEOUL = ZoneId.of("Asia/Seoul");
    private final ConcurrentMap<String, PendingApproval> approvals = new ConcurrentHashMap<>();

    public void add(
            String traceId,
            AuditDirection direction,
            String tool,
            PolicyDecision decision
    ) {
        List<String> categories = decision.categories() == null
                ? List.of()
                : decision.categories().stream().map(Enum::name).toList();
        PendingApproval approval = new PendingApproval(
                traceId,
                direction,
                tool,
                decision.reason(),
                decision.detectors(),
                categories,
                OffsetDateTime.now(SEOUL).format(DateTimeFormatter.ISO_OFFSET_DATE_TIME),
                ApprovalStatus.PENDING
        );
        approvals.put(traceId, approval);
    }

    public List<PendingApproval> pending() {
        return approvals.values().stream()
                .filter(approval -> approval.status() == ApprovalStatus.PENDING)
                .sorted(java.util.Comparator.comparing(PendingApproval::createdAt)
                        .thenComparing(PendingApproval::traceId))
                .toList();
    }

    public Optional<PendingApproval> approve(String traceId) {
        return transition(traceId, ApprovalStatus.APPROVED);
    }

    public Optional<PendingApproval> deny(String traceId) {
        return transition(traceId, ApprovalStatus.DENIED);
    }

    public Optional<PendingApproval> find(String traceId) {
        return Optional.ofNullable(approvals.get(traceId));
    }

    private Optional<PendingApproval> transition(String traceId, ApprovalStatus status) {
        AtomicReference<PendingApproval> updated = new AtomicReference<>();
        approvals.computeIfPresent(traceId, (key, current) -> {
            if (current.status() != ApprovalStatus.PENDING) {
                return current;
            }
            PendingApproval transitioned = current.withStatus(status);
            updated.set(transitioned);
            return transitioned;
        });
        return Optional.ofNullable(updated.get());
    }
}
