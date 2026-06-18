package com.kcops.mcp.detector.dlp;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class JsonTextExtractorTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void extractsDecodedTextFromNestedObjectsAndArrays() throws Exception {
        String body = "{\"outer\":{\"command\":\"r" + "\\" + "u006d -rf\"},"
                + "\"items\":[\"alpha\",{\"pii\":\"" + unicodeEscape("홍길동") + "\"}],"
                + "\"number\":123,\"flag\":true,\"none\":null}";

        assertThat(JsonTextExtractor.extract(objectMapper.readTree(body)))
                .isEqualTo("rm -rf\nalpha\n홍길동");
    }

    @Test
    void isNullSafe() {
        assertThat(JsonTextExtractor.extract(null)).isEmpty();
    }

    private String unicodeEscape(String value) {
        StringBuilder escaped = new StringBuilder();
        value.codePoints().forEach(codePoint -> escaped.append(String.format("\\u%04x", codePoint)));
        return escaped.toString();
    }
}
