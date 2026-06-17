package com.kcops.mcp.detector;

public record Finding(String detector, String reason, Severity severity) {
    public enum Severity {
        LOW, MEDIUM, HIGH
    }
}
