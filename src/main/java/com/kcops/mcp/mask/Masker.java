package com.kcops.mcp.mask;

import com.kcops.mcp.detector.Finding;
import java.util.Comparator;
import java.util.List;

public final class Masker {

    private Masker() {
    }

    public static String mask(String source, List<Finding> findings) {
        if (source == null || source.isEmpty() || findings == null || findings.isEmpty()) {
            return source;
        }

        StringBuilder masked = new StringBuilder(source);
        findings.stream()
                .flatMap(finding -> finding.spans().stream())
                .sorted(Comparator.comparingInt(MaskSpan::start).reversed())
                .forEach(span -> applySpan(masked, span));
        return masked.toString();
    }

    public static boolean hasSpans(List<Finding> findings) {
        return findings != null && findings.stream().anyMatch(finding -> !finding.spans().isEmpty());
    }

    private static void applySpan(StringBuilder masked, MaskSpan span) {
        int start = Math.max(0, span.start());
        int end = Math.min(masked.length(), span.end());
        if (start >= end) {
            return;
        }
        if (span.replacement() != null) {
            masked.replace(start, end, span.replacement());
            return;
        }
        for (int i = start; i < end; i++) {
            masked.setCharAt(i, span.maskChar());
        }
    }
}
