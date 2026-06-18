package com.kcops.mcp.audit;

public record VerificationResult(
        boolean valid,
        int brokenAtLine,
        boolean anchorConsistent
) {
}
