package com.kcops.mcp.detector;

import com.kcops.mcp.config.KcopsProperties;
import com.kcops.mcp.model.McpRequest;
import java.util.List;
import org.springframework.stereotype.Component;

@Component
public class HighRiskToolRequestDetector implements RequestDetector {

    private final KcopsProperties properties;

    public HighRiskToolRequestDetector(KcopsProperties properties) {
        this.properties = properties;
    }

    @Override
    public String name() {
        return "HighRiskToolRequestDetector";
    }

    @Override
    public List<Finding> inspect(McpRequest req) {
        String tool = req.tool();
        if (tool == null || tool.isBlank()) {
            return List.of();
        }
        boolean highRisk = properties.getRequest().getToolCall().getHighRiskTools().stream()
                .anyMatch(value -> value.equalsIgnoreCase(tool));
        if (!highRisk) {
            return List.of();
        }
        return List.of(new Finding(name(), PolicyCategory.TOOL_CALL, "HIGH_RISK_TOOL_CALL", Finding.Severity.HIGH));
    }
}
