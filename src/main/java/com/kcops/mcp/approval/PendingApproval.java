package com.kcops.mcp.approval;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.kcops.mcp.audit.AuditDirection;
import java.util.List;

public record PendingApproval(
        String traceId,
        AuditDirection direction,
        String tool,
        String reason,
        List<String> detectors,
        List<String> categories,
        String createdAt,
        ApprovalStatus status,
        @JsonIgnore String requestBody,
        String bodyHash
) {
    public PendingApproval {
        detectors = detectors == null ? List.of() : List.copyOf(detectors);
        categories = categories == null ? List.of() : List.copyOf(categories);
    }

    public PendingApproval withStatus(ApprovalStatus newStatus) {
        return new PendingApproval(
                traceId,
                direction,
                tool,
                reason,
                detectors,
                categories,
                createdAt,
                newStatus,
                requestBody,
                bodyHash
        );
    }
}
