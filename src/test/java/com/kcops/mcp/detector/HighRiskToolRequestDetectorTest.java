package com.kcops.mcp.detector;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kcops.mcp.config.KcopsProperties;
import com.kcops.mcp.model.McpRequest;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class HighRiskToolRequestDetectorTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void detectsHighRiskToolByNameIgnoringCase() throws Exception {
        KcopsProperties properties = new KcopsProperties();
        properties.getRequest().getToolCall().setHighRiskTools(List.of("execute_shell"));
        HighRiskToolRequestDetector detector = new HighRiskToolRequestDetector(properties);
        String body = """
                {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"EXECUTE_SHELL","arguments":{"command":"ls"}}}
                """;

        assertThat(detector.inspect(McpRequest.from(objectMapper.readTree(body), body))).singleElement()
                .satisfies(finding -> {
                    assertThat(finding.detector()).isEqualTo("HighRiskToolRequestDetector");
                    assertThat(finding.category()).isEqualTo(PolicyCategory.TOOL_CALL);
                    assertThat(finding.reason()).isEqualTo("HIGH_RISK_TOOL_CALL");
                    assertThat(finding.severity()).isEqualTo(Finding.Severity.HIGH);
                });
    }

    @Test
    void ignoresMissingOrLowRiskTool() throws Exception {
        KcopsProperties properties = new KcopsProperties();
        properties.getRequest().getToolCall().setHighRiskTools(List.of("execute_shell"));
        HighRiskToolRequestDetector detector = new HighRiskToolRequestDetector(properties);
        String body = """
                {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_files","arguments":{}}}
                """;

        assertThat(detector.inspect(McpRequest.from(objectMapper.readTree(body), body))).isEmpty();
    }
}
