package com.kcops.mcp.policy;

import com.kcops.mcp.detector.PolicyCategory;
import java.util.List;

public record PolicyDecision(Action action, String reason, List<String> detectors, List<PolicyCategory> categories) {
}
