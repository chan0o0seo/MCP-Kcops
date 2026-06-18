package com.kcops.mcp.detector.dlp;

import com.kcops.mcp.detector.PolicyCategory;

public record SensitiveMatch(
        String detectorName,
        PolicyCategory category,
        int start,
        int end,
        char maskChar,
        String replacement,
        String value
) {
}
