package com.kcops.mcp.detector;

import com.kcops.mcp.config.KcopsProperties;
import com.kcops.mcp.model.McpResponse;
import java.util.List;
import java.util.Locale;
import org.springframework.stereotype.Component;

@Component
public class PromptInjectionResponseDetector implements ResponseDetector {

    private final KcopsProperties properties;

    public PromptInjectionResponseDetector(KcopsProperties properties) {
        this.properties = properties;
    }

    @Override
    public String name() {
        return "PromptInjectionResponseDetector";
    }

    @Override
    public List<Finding> inspect(McpResponse resp) {
        String text = resp.rawBody() == null ? "" : resp.rawBody();
        String lowered = text.toLowerCase(Locale.ROOT);
        boolean matched = properties.getInjectionPatterns().stream()
                .anyMatch(pattern -> lowered.contains(pattern.toLowerCase(Locale.ROOT)));
        if (!matched) {
            return List.of();
        }
        return List.of(new Finding(name(), "PROMPT_INJECTION", Finding.Severity.HIGH));
    }
}
