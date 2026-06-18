package com.kcops.mcp.audit;

import com.kcops.mcp.policy.Action;
import java.util.List;

public record AuditRecord(
        String traceId,
        String timestamp,
        AuditDirection direction,
        String server,
        String tool,
        Action decision,
        String reason,
        List<String> detectors,
        boolean piiMasked,
        boolean fingerprintChanged,
        long latencyMs,
        String prevHash,
        String hash
) {
}
