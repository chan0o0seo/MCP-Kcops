package com.kcops.mcp.detector;

import com.kcops.mcp.config.KcopsProperties;
import com.kcops.mcp.detector.dlp.JsonTextExtractor;
import com.kcops.mcp.model.McpRequest;
import java.util.List;
import java.util.Locale;
import org.springframework.stereotype.Component;

@Component
public class DestructiveCommandRequestDetector implements RequestDetector {

    private final KcopsProperties properties;

    public DestructiveCommandRequestDetector(KcopsProperties properties) {
        this.properties = properties;
    }

    @Override
    public String name() {
        return "DestructiveCommandRequestDetector";
    }

    @Override
    public List<Finding> inspect(McpRequest req) {
        String text = ((req.tool() == null ? "" : req.tool())
                + " " + (req.rawBody() == null ? "" : req.rawBody())
                + "\n" + JsonTextExtractor.extract(req.raw()))
                .toLowerCase(Locale.ROOT);
        boolean destructive = properties.getRequest().getDestructive().getPatterns().stream()
                .filter(pattern -> pattern != null && !pattern.isBlank())
                .map(pattern -> pattern.toLowerCase(Locale.ROOT))
                .anyMatch(text::contains);
        if (!destructive) {
            return List.of();
        }
        return List.of(new Finding(name(), PolicyCategory.DESTRUCTIVE,
                "DESTRUCTIVE_OR_CODE_EXECUTION_REQUEST", Finding.Severity.HIGH));
    }
}
