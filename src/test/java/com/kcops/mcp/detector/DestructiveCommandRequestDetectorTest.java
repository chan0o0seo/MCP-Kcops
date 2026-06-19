package com.kcops.mcp.detector;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kcops.mcp.config.KcopsProperties;
import com.kcops.mcp.model.McpRequest;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class DestructiveCommandRequestDetectorTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void detectsDestructivePattern() throws Exception {
        KcopsProperties properties = new KcopsProperties();
        properties.getRequest().getDestructive().setPatterns(List.of("rm -rf", "삭제"));
        DestructiveCommandRequestDetector detector = new DestructiveCommandRequestDetector(properties);
        String body = """
                {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_shell","arguments":{"command":"rm -rf /workspace/tmp/*"}}}
                """;

        assertThat(detector.inspect(McpRequest.from(objectMapper.readTree(body), body))).singleElement()
                .satisfies(finding -> {
                    assertThat(finding.detector()).isEqualTo("DestructiveCommandRequestDetector");
                    assertThat(finding.category()).isEqualTo(PolicyCategory.DESTRUCTIVE);
                    assertThat(finding.reason()).isEqualTo("DESTRUCTIVE_OR_CODE_EXECUTION_REQUEST");
                    assertThat(finding.severity()).isEqualTo(Finding.Severity.HIGH);
                });
    }

    @Test
    void ignoresBenignCommand() throws Exception {
        KcopsProperties properties = new KcopsProperties();
        properties.getRequest().getDestructive().setPatterns(List.of("rm -rf", "삭제"));
        DestructiveCommandRequestDetector detector = new DestructiveCommandRequestDetector(properties);
        String body = """
                {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_shell","arguments":{"command":"ls /workspace/tmp"}}}
                """;

        assertThat(detector.inspect(McpRequest.from(objectMapper.readTree(body), body))).isEmpty();
    }

    @Test
    void detectsUnicodeEscapedDestructivePatternFromDecodedJsonValue() throws Exception {
        KcopsProperties properties = new KcopsProperties();
        properties.getRequest().getDestructive().setPatterns(List.of("rm -rf"));
        DestructiveCommandRequestDetector detector = new DestructiveCommandRequestDetector(properties);
        String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"params\":{\"name\":\"execute_shell\","
                + "\"arguments\":{\"command\":\"r" + "\\" + "u006d -rf /tmp\"}}}";

        assertThat(detector.inspect(McpRequest.from(objectMapper.readTree(body), body))).singleElement();
    }
}
