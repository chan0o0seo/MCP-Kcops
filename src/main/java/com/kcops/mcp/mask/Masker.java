package com.kcops.mcp.mask;

import com.kcops.mcp.detector.Finding;
import java.util.List;

public final class Masker {

    private Masker() {
    }

    public static String mask(String source, List<Finding> findings) {
        if (source == null || source.isEmpty() || findings == null || findings.isEmpty()) {
            return source;
        }

        char[] chars = source.toCharArray();
        for (Finding finding : findings) {
            for (MaskSpan span : finding.spans()) {
                int start = Math.max(0, span.start());
                int end = Math.min(chars.length, span.end());
                if (start >= end) {
                    continue;
                }
                for (int i = start; i < end; i++) {
                    chars[i] = span.maskChar();
                }
            }
        }
        return new String(chars);
    }

    public static boolean hasSpans(List<Finding> findings) {
        return findings != null && findings.stream().anyMatch(finding -> !finding.spans().isEmpty());
    }
}
