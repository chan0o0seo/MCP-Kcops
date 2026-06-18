package com.kcops.mcp.detector;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kcops.mcp.model.McpRequest;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SensitiveDataRequestDetectorTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void detectsEncodedPiiAsPresenceOnlyFinding() throws Exception {
        String escapedPhone = unicodeEscape("010-1234-5678");
        String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"params\":{\"name\":\"send_email\","
                + "\"arguments\":{\"phone\":\"" + escapedPhone + "\"}}}";

        assertThat(new SensitiveDataRequestDetector()
                .inspect(McpRequest.from(objectMapper.readTree(body), body)))
                .singleElement()
                .satisfies(finding -> {
                    assertThat(finding.detector()).isEqualTo("korean_phone");
                    assertThat(finding.reason()).isEqualTo("PII_IN_REQUEST_ARG");
                    assertThat(finding.spans()).isEmpty();
                });
    }

    private String unicodeEscape(String value) {
        StringBuilder escaped = new StringBuilder();
        value.codePoints().forEach(codePoint -> escaped.append(String.format("\\u%04x", codePoint)));
        return escaped.toString();
    }
}
