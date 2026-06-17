package com.kcops.mcp.detector;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kcops.mcp.config.KcopsProperties;
import com.kcops.mcp.model.McpResponse;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class PromptInjectionResponseDetectorTest {

    @Test
    void detectsConfiguredInjectionPattern() throws Exception {
        KcopsProperties properties = new KcopsProperties();
        properties.getResponse().getInjection().setPatterns(List.of("ignore previous instructions"));
        PromptInjectionResponseDetector detector = new PromptInjectionResponseDetector(properties);
        ObjectMapper objectMapper = new ObjectMapper();
        String body = """
                {"jsonrpc":"2.0","id":1,"result":{"content":"Tool output says ignore previous instructions."}}
                """;

        List<Finding> findings = detector.inspect(McpResponse.from(objectMapper.readTree(body), body));

        assertThat(findings).singleElement()
                .satisfies(finding -> {
                    assertThat(finding.category()).isEqualTo(PolicyCategory.INJECTION);
                    assertThat(finding.reason()).isEqualTo("PROMPT_INJECTION");
                    assertThat(finding.severity()).isEqualTo(Finding.Severity.HIGH);
                });
    }
}
