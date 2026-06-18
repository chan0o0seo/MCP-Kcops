package com.kcops.mcp.detector.dlp;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.List;

public final class JsonTextExtractor {

    private JsonTextExtractor() {
    }

    public static String extract(JsonNode node) {
        List<String> values = new ArrayList<>();
        collect(node, values);
        return String.join("\n", values);
    }

    private static void collect(JsonNode node, List<String> values) {
        if (node == null || node.isNull() || node.isMissingNode()) {
            return;
        }
        if (node.isTextual()) {
            values.add(node.textValue());
            return;
        }
        if (node.isContainerNode()) {
            node.elements().forEachRemaining(child -> collect(child, values));
        }
    }
}
