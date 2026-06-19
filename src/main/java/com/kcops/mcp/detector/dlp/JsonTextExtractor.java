package com.kcops.mcp.detector.dlp;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.List;

public final class JsonTextExtractor {

    static final int MAX_DEPTH = 200;

    private JsonTextExtractor() {
    }

    public static String extract(JsonNode node) {
        List<String> values = new ArrayList<>();
        collect(node, values, 0);
        return String.join("\n", values);
    }

    private static void collect(JsonNode node, List<String> values, int depth) {
        if (depth > MAX_DEPTH || node == null || node.isNull() || node.isMissingNode()) {
            return;
        }
        if (node.isTextual()) {
            values.add(node.textValue());
            return;
        }
        if (node.isContainerNode()) {
            node.elements().forEachRemaining(child -> collect(child, values, depth + 1));
        }
    }
}
