package com.kcops.mcp.approval;

import com.kcops.mcp.audit.AuditDirection;
import com.kcops.mcp.config.KcopsProperties;
import com.kcops.mcp.policy.PolicyDecision;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicReference;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class PendingApprovalStore {

    private static final ZoneId SEOUL = ZoneId.of("Asia/Seoul");
    private final ConcurrentMap<String, PendingApproval> approvals = new ConcurrentHashMap<>();
    private final int maxPending;
    private final int ttlSeconds;
    private final Clock clock;

    @Autowired
    public PendingApprovalStore(KcopsProperties properties) {
        this(properties, Clock.system(SEOUL));
    }

    public PendingApprovalStore(KcopsProperties properties, Clock clock) {
        this.maxPending = Math.max(0, properties.getApproval().getMaxPending());
        this.ttlSeconds = properties.getApproval().getTtlSeconds();
        this.clock = clock;
    }

    public synchronized void add(
            String traceId,
            AuditDirection direction,
            String tool,
            PolicyDecision decision
    ) {
        add(traceId, direction, tool, decision, null);
    }

    public synchronized void add(
            String traceId,
            AuditDirection direction,
            String tool,
            PolicyDecision decision,
            String requestBody
    ) {
        purgeExpired();
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
                OffsetDateTime.now(clock).format(DateTimeFormatter.ISO_OFFSET_DATE_TIME),
                ApprovalStatus.PENDING,
                requestBody,
                requestBody == null ? null : sha256Hex(requestBody)
        );
        approvals.put(traceId, approval);
        trimToLimit();
    }

    public synchronized List<PendingApproval> pending() {
        purgeExpired();
        return approvals.values().stream()
                .filter(approval -> approval.status() == ApprovalStatus.PENDING)
                .sorted(java.util.Comparator.comparing(PendingApproval::createdAt)
                        .thenComparing(PendingApproval::traceId))
                .toList();
    }

    public synchronized Optional<PendingApproval> approve(String traceId) {
        purgeExpired();
        return transition(traceId, ApprovalStatus.APPROVED);
    }

    public synchronized Optional<PendingApproval> deny(String traceId) {
        purgeExpired();
        return transition(traceId, ApprovalStatus.DENIED);
    }

    public synchronized Optional<PendingApproval> find(String traceId) {
        purgeExpired();
        return Optional.ofNullable(approvals.get(traceId));
    }

    public synchronized Optional<String> consumeApproved(String approvalId, String incomingBodyHash) {
        purgeExpired();
        PendingApproval current = approvals.get(approvalId);
        if (current == null
                || current.status() != ApprovalStatus.APPROVED
                || current.bodyHash() == null
                || !current.bodyHash().equals(incomingBodyHash)) {
            return Optional.empty();
        }
        approvals.put(approvalId, current.withStatus(ApprovalStatus.CONSUMED));
        return Optional.of(current.requestBody());
    }

    public static String sha256Hex(String value) {
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

    private synchronized Optional<PendingApproval> transition(String traceId, ApprovalStatus status) {
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

    private void purgeExpired() {
        if (ttlSeconds <= 0) {
            return;
        }
        OffsetDateTime now = OffsetDateTime.now(clock);
        approvals.entrySet().removeIf(entry -> {
            PendingApproval approval = entry.getValue();
            return approval.status() == ApprovalStatus.PENDING
                    && OffsetDateTime.parse(approval.createdAt())
                    .plusSeconds(ttlSeconds)
                    .isBefore(now);
        });
    }

    private void trimToLimit() {
        if (approvals.size() <= maxPending) {
            return;
        }
        List<PendingApproval> evictionOrder = approvals.values().stream()
                .sorted(java.util.Comparator
                        .comparing((PendingApproval approval) -> approval.status() == ApprovalStatus.PENDING)
                        .thenComparing(PendingApproval::createdAt)
                        .thenComparing(PendingApproval::traceId))
                .toList();
        int removeCount = approvals.size() - maxPending;
        for (int i = 0; i < removeCount; i++) {
            PendingApproval approval = evictionOrder.get(i);
            approvals.remove(approval.traceId(), approval);
        }
    }
}
