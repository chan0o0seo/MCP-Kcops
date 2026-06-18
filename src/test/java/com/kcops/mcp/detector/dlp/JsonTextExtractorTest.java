package com.kcops.mcp.detector.dlp;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

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

    @Test
    void stopsAtMaximumDepthWithoutStackOverflow() {
        ObjectNode root = objectMapper.createObjectNode();
        root.put("visible", "shallow");
        ObjectNode current = root;
        for (int depth = 0; depth < 10_000; depth++) {
            current = current.putObject("nested");
        }
        current.put("hidden", "too-deep");

        String extracted = assertDoesNotThrow(() -> JsonTextExtractor.extract(root));

        assertThat(extracted).contains("shallow").doesNotContain("too-deep");
    }

    private String unicodeEscape(String value) {
        StringBuilder escaped = new StringBuilder();
        value.codePoints().forEach(codePoint -> escaped.append(String.format("\\u%04x", codePoint)));
        return escaped.toString();
    }
}
