package com.kcops.mcp.detector;

import com.kcops.mcp.mask.MaskSpan;
import java.util.List;

public record Finding(String detector, PolicyCategory category, String reason, Severity severity, List<MaskSpan> spans) {
    public Finding(String detector, PolicyCategory category, String reason, Severity severity) {
        this(detector, category, reason, severity, List.of());
    }

    public Finding {
        spans = spans == null ? List.of() : List.copyOf(spans);
    }

    public enum Severity {
        LOW, MEDIUM, HIGH
    }
}
