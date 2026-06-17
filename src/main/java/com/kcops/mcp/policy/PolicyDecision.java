package com.kcops.mcp.policy;

import java.util.List;

public record PolicyDecision(Decision decision, String reason, List<String> detectors) {
}
