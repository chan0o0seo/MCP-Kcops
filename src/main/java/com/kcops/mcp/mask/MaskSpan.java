package com.kcops.mcp.mask;

public record MaskSpan(int start, int end, char maskChar, String replacement) {
    public MaskSpan(int start, int end) {
        this(start, end, '*', null);
    }

    public MaskSpan(int start, int end, char maskChar) {
        this(start, end, maskChar, null);
    }
}
