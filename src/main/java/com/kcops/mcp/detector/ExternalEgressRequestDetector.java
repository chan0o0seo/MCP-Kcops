package com.kcops.mcp.detector;

import com.kcops.mcp.config.KcopsProperties;
import com.kcops.mcp.model.McpRequest;
import java.net.URI;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;

@Component
public class ExternalEgressRequestDetector implements RequestDetector {

    private static final Pattern URL_PATTERN = Pattern.compile("https?://[^\\s\\\"'<>)}]+", Pattern.CASE_INSENSITIVE);
    private static final Pattern KOREAN_RRN = Pattern.compile("\\b\\d{6}-\\d{7}\\b");
    private final KcopsProperties properties;

    public ExternalEgressRequestDetector(KcopsProperties properties) {
        this.properties = properties;
    }

    @Override
    public String name() {
        return "ExternalEgressRequestDetector";
    }

    @Override
    public List<Finding> inspect(McpRequest req) {
        String body = req.rawBody() == null ? "" : req.rawBody();
        String tool = req.tool() == null ? "" : req.tool();
        boolean riskyIntent = isHighRiskTool(tool) || containsEgressVerb(tool + " " + body);
        if (!riskyIntent || !hasDisallowedUrl(body)) {
            return List.of();
        }
        Finding.Severity severity = containsSensitiveKeyword(body) ? Finding.Severity.HIGH : Finding.Severity.MEDIUM;
        return List.of(new Finding(name(), PolicyCategory.EGRESS, "EXTERNAL_EGRESS", severity));
    }

    private boolean isHighRiskTool(String tool) {
        return properties.getRequest().getToolCall().getHighRiskTools().stream()
                .anyMatch(value -> value.equalsIgnoreCase(tool));
    }

    private boolean containsEgressVerb(String text) {
        String lowered = text.toLowerCase(Locale.ROOT);
        return properties.getRequest().getEgress().getRiskyKeywords().stream()
                .map(value -> value.toLowerCase(Locale.ROOT))
                .anyMatch(lowered::contains);
    }

    private boolean hasDisallowedUrl(String body) {
        Matcher matcher = URL_PATTERN.matcher(body);
        while (matcher.find()) {
            String host = hostOf(matcher.group());
            if (host != null && !isAllowedDomain(host)) {
                return true;
            }
        }
        return false;
    }

    private String hostOf(String url) {
        try {
            return URI.create(url).getHost();
        } catch (IllegalArgumentException ex) {
            return null;
        }
    }

    private boolean isAllowedDomain(String host) {
        String normalized = host.toLowerCase(Locale.ROOT);
        return properties.getRequest().getEgress().getAllowDomains().stream()
                .map(value -> value.toLowerCase(Locale.ROOT))
                .anyMatch(allowed -> normalized.equals(allowed) || normalized.endsWith("." + allowed));
    }

    private boolean containsSensitiveKeyword(String body) {
        return body.contains("sk-") || KOREAN_RRN.matcher(body).find();
    }
}
