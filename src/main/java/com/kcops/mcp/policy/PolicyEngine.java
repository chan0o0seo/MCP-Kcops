package com.kcops.mcp.policy;

import com.kcops.mcp.config.KcopsProperties;
import com.kcops.mcp.detector.Finding;
import com.kcops.mcp.detector.PolicyCategory;
import java.util.Comparator;
import java.util.List;
import org.springframework.stereotype.Component;

@Component
public class PolicyEngine {

    private final KcopsProperties properties;

    public PolicyEngine(KcopsProperties properties) {
        this.properties = properties;
    }

    public PolicyDecision decide(Direction direction, List<Finding> findings) {
        if (findings == null || findings.isEmpty()) {
            return new PolicyDecision(Action.ALLOW, "NO_FINDINGS", List.of(), List.of());
        }

        Finding representative = findings.stream()
                .max(Comparator
                        .comparing((Finding finding) -> strength(configuredAction(direction, finding.category())))
                        .thenComparing(finding -> categoryPriority(finding.category())))
                .orElse(findings.get(0));
        Action action = configuredAction(direction, representative.category());
        action = applyMode(action);

        List<String> detectors = findings.stream().map(Finding::detector).distinct().toList();
        List<PolicyCategory> categories = findings.stream().map(Finding::category).distinct().toList();
        return new PolicyDecision(action, representative.reason(), detectors, categories);
    }

    private Action configuredAction(Direction direction, PolicyCategory category) {
        return switch (direction) {
            case REQUEST -> requestAction(category);
            case RESPONSE -> responseAction(category);
        };
    }

    private Action requestAction(PolicyCategory category) {
        return switch (category) {
            case EGRESS -> properties.getRequest().getEgress().getAction();
            case DESTRUCTIVE -> properties.getRequest().getDestructive().getAction();
            case SCOPE -> properties.getRequest().getScope().getAction();
            case TOOL_CALL -> properties.getRequest().getToolCall().getAction();
            case PII, SECRET -> properties.getRequest().getPii().getAction();
            case INJECTION, TOOL_METADATA, FINGERPRINT -> Action.ALLOW;
        };
    }

    private Action responseAction(PolicyCategory category) {
        return switch (category) {
            case INJECTION -> properties.getResponse().getInjection().getAction();
            case TOOL_METADATA -> properties.getResponse().getToolMetadata().getAction();
            case FINGERPRINT -> properties.getResponse().getFingerprint().getAction();
            case PII, SECRET -> properties.getResponse().getPii().getAction();
            case TOOL_CALL, EGRESS, DESTRUCTIVE, SCOPE -> Action.ALLOW;
        };
    }

    private Action applyMode(Action action) {
        if (properties.getMode() == KcopsProperties.Mode.LOG_ONLY && strength(action) > strength(Action.LOG_ONLY)) {
            return Action.LOG_ONLY;
        }
        return action;
    }

    private int strength(Action action) {
        return switch (action) {
            case ALLOW -> 0;
            case LOG_ONLY -> 1;
            case MASK -> 2;
            case REQUIRE_APPROVAL -> 3;
            case BLOCK -> 4;
        };
    }

    private int categoryPriority(PolicyCategory category) {
        return switch (category) {
            case DESTRUCTIVE -> 5;
            case EGRESS, FINGERPRINT -> 4;
            case SCOPE -> 3;
            case TOOL_CALL -> 2;
            case SECRET, TOOL_METADATA -> 1;
            case PII, INJECTION -> 0;
        };
    }
}
