package com.kcops.mcp.detector;

import com.kcops.mcp.config.KcopsProperties;
import com.kcops.mcp.detector.dlp.JsonTextExtractor;
import com.kcops.mcp.model.McpRequest;
import java.util.List;
import java.util.Locale;
import org.springframework.stereotype.Component;

@Component
public class ExcessiveScopeRequestDetector implements RequestDetector {

    private final KcopsProperties properties;

    public ExcessiveScopeRequestDetector(KcopsProperties properties) {
        this.properties = properties;
    }

    @Override
    public String name() {
        return "ExcessiveScopeRequestDetector";
    }

    @Override
    public List<Finding> inspect(McpRequest req) {
        String body = req.rawBody() == null ? "" : req.rawBody();
        String lowered = (body + "\n" + JsonTextExtractor.extract(req.raw())).toLowerCase(Locale.ROOT);
        boolean excessive = properties.getRequest().getScope().getPatterns().stream()
                .filter(pattern -> pattern != null && !pattern.isBlank())
                .map(pattern -> pattern.toLowerCase(Locale.ROOT))
                .anyMatch(lowered::contains);
        if (!excessive) {
            return List.of();
        }
        return List.of(new Finding(name(), PolicyCategory.SCOPE, "EXCESSIVE_SCOPE_REQUEST", Finding.Severity.MEDIUM));
    }
}
