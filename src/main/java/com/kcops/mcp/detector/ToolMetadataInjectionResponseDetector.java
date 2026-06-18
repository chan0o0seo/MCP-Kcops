package com.kcops.mcp.detector;

import com.fasterxml.jackson.databind.JsonNode;
import com.kcops.mcp.config.KcopsProperties;
import com.kcops.mcp.detector.dlp.JsonTextExtractor;
import com.kcops.mcp.model.McpResponse;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.springframework.stereotype.Component;

@Component
public class ToolMetadataInjectionResponseDetector implements ResponseDetector {

    private static final String DETECTOR = "tool_metadata_injection";
    private static final String REASON = "TOOL_METADATA_INJECTION_SUSPECTED";

    private final KcopsProperties properties;

    public ToolMetadataInjectionResponseDetector(KcopsProperties properties) {
        this.properties = properties;
    }

    @Override
    public String name() {
        return DETECTOR;
    }

    @Override
    public List<Finding> inspect(McpResponse resp) {
        if (resp.result() == null || !resp.result().path("tools").isArray()) {
            return List.of();
        }

        Map<String, List<String>> types = properties.getResponse().getInjection().getTypes();
        if (types == null || types.isEmpty()) {
            return List.of();
        }

        for (JsonNode tool : resp.result().path("tools")) {
            String text = tool.path("name").asText("")
                    + "\n" + tool.path("description").asText("")
                    + "\n" + JsonTextExtractor.extract(tool.path("inputSchema"));
            String lowered = text.toLowerCase(Locale.ROOT);
            if (types.values().stream().anyMatch(patterns -> matchesAny(lowered, patterns))) {
                return List.of(new Finding(
                        DETECTOR,
                        PolicyCategory.TOOL_METADATA,
                        REASON,
                        Finding.Severity.HIGH
                ));
            }
        }
        return List.of();
    }

    private boolean matchesAny(String lowered, List<String> patterns) {
        return patterns != null && patterns.stream()
                .filter(pattern -> pattern != null && !pattern.isEmpty())
                .anyMatch(pattern -> lowered.contains(pattern.toLowerCase(Locale.ROOT)));
    }
}
