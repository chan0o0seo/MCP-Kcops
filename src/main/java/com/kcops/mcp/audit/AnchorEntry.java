package com.kcops.mcp.audit;

public record AnchorEntry(
        String timestamp,
        int recordCount,
        String latestHash
) {
}
