package com.kcops.mcp.policy;

import com.kcops.mcp.detector.Finding;
import java.util.List;
import org.springframework.stereotype.Component;

@Component
public class PolicyEngine {

    public PolicyDecision decide(List<Finding> findings) {
        if (findings == null || findings.isEmpty()) {
            return new PolicyDecision(Decision.ALLOW, "NO_FINDINGS", List.of());
        }
        Finding representative = findings.get(0);
        List<String> detectors = findings.stream().map(Finding::detector).distinct().toList();
        return new PolicyDecision(Decision.BLOCK, representative.reason(), detectors);
    }
}
