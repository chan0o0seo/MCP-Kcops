package com.kcops.mcp.detector;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kcops.mcp.config.KcopsProperties;
import com.kcops.mcp.model.McpRequest;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ExcessiveScopeRequestDetectorTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void detectsExcessiveScopePatternIgnoringCase() throws Exception {
        KcopsProperties properties = new KcopsProperties();
        properties.getRequest().getScope().setPatterns(List.of("select * from", "모든 파일"));
        ExcessiveScopeRequestDetector detector = new ExcessiveScopeRequestDetector(properties);
        String body = """
                {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"query_database","arguments":{"query":"SELECT * FROM customers"}}}
                """;

        assertThat(detector.inspect(McpRequest.from(objectMapper.readTree(body), body))).singleElement()
                .satisfies(finding -> {
                    assertThat(finding.detector()).isEqualTo("ExcessiveScopeRequestDetector");
                    assertThat(finding.category()).isEqualTo(PolicyCategory.SCOPE);
                    assertThat(finding.reason()).isEqualTo("EXCESSIVE_SCOPE_REQUEST");
                    assertThat(finding.severity()).isEqualTo(Finding.Severity.MEDIUM);
                });
    }

    @Test
    void ignoresScopedQuery() throws Exception {
        KcopsProperties properties = new KcopsProperties();
        properties.getRequest().getScope().setPatterns(List.of("select * from", "모든 파일"));
        ExcessiveScopeRequestDetector detector = new ExcessiveScopeRequestDetector(properties);
        String body = """
                {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"query_database","arguments":{"query":"select id from customers where id = 1"}}}
                """;

        assertThat(detector.inspect(McpRequest.from(objectMapper.readTree(body), body))).isEmpty();
    }
}
