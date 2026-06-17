package com.kcops.mcp.policy;

import com.kcops.mcp.config.KcopsProperties;
import com.kcops.mcp.detector.Finding;
import com.kcops.mcp.detector.PolicyCategory;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class PolicyEngineTest {

    @Test
    void choosesStrongestConfiguredActionAcrossFindings() {
        KcopsProperties properties = new KcopsProperties();
        properties.getRequest().getEgress().setAction(Action.MASK);
        properties.getRequest().getDestructive().setAction(Action.REQUIRE_APPROVAL);
        PolicyEngine engine = new PolicyEngine(properties);

        PolicyDecision decision = engine.decide(Direction.REQUEST, List.of(
                new Finding("EgressDetector", PolicyCategory.EGRESS, "EGRESS", Finding.Severity.MEDIUM),
                new Finding("DestructiveDetector", PolicyCategory.DESTRUCTIVE, "DESTRUCTIVE", Finding.Severity.HIGH)
        ));

        assertThat(decision.action()).isEqualTo(Action.REQUIRE_APPROVAL);
        assertThat(decision.reason()).isEqualTo("DESTRUCTIVE");
        assertThat(decision.categories()).containsExactly(PolicyCategory.EGRESS, PolicyCategory.DESTRUCTIVE);
    }

    @Test
    void logOnlyModeDowngradesEnforcingActions() {
        KcopsProperties properties = new KcopsProperties();
        properties.setMode(KcopsProperties.Mode.LOG_ONLY);
        PolicyEngine engine = new PolicyEngine(properties);

        PolicyDecision decision = engine.decide(Direction.RESPONSE, List.of(
                new Finding("InjectionDetector", PolicyCategory.INJECTION, "PROMPT_INJECTION", Finding.Severity.HIGH)
        ));

        assertThat(decision.action()).isEqualTo(Action.LOG_ONLY);
        assertThat(decision.reason()).isEqualTo("PROMPT_INJECTION");
    }
}
