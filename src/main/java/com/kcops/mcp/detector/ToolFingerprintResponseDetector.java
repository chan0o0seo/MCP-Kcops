package com.kcops.mcp.detector;

import com.fasterxml.jackson.databind.JsonNode;
import com.kcops.mcp.fingerprint.ToolFingerprintStore;
import com.kcops.mcp.model.McpResponse;
import java.util.ArrayList;
import java.util.List;
import org.springframework.stereotype.Component;

@Component
public class ToolFingerprintResponseDetector implements ResponseDetector {

    private static final String REASON = "TOOL_DESCRIPTION_FINGERPRINT_CHANGED";
    private final ToolFingerprintStore store;

    public ToolFingerprintResponseDetector(ToolFingerprintStore store) {
        this.store = store;
    }

    @Override
    public String name() {
        return "tool_fingerprint";
    }

    @Override
    public List<Finding> inspect(McpResponse resp) {
        if (resp.result() == null || !resp.result().path("tools").isArray()) {
            return List.of();
        }

        List<String> changedTools = new ArrayList<>();
        for (JsonNode tool : resp.result().path("tools")) {
            String toolName = tool.path("name").asText("");
            if (toolName.isEmpty()) {
                continue;
            }
            String descriptionHash = ToolFingerprintStore.sha256Hex(tool.path("description").asText(""));
            JsonNode inputSchema = tool.path("inputSchema");
            String schema = inputSchema.isMissingNode() ? "" : inputSchema.toString();
            String schemaHash = ToolFingerprintStore.sha256Hex(schema);
            if (store.checkAndRegister(toolName, descriptionHash, schemaHash)) {
                changedTools.add(toolName);
            }
        }

        if (changedTools.isEmpty()) {
            return List.of();
        }
        return List.of(new Finding(
                name(),
                PolicyCategory.FINGERPRINT,
                REASON,
                Finding.Severity.HIGH
        ));
    }
}
