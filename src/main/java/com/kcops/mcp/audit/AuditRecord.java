package com.kcops.mcp.audit;

import com.kcops.mcp.policy.Decision;
import java.util.List;

public record AuditRecord(
        String traceId,
        String timestamp,
        AuditDirection direction,
        String server,
        String tool,
        Decision decision,
        String reason,
        List<String> detectors,
        long latencyMs,
        String prevHash,
        String hash
) {
}
