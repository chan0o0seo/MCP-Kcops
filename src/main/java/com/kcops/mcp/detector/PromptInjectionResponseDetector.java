package com.kcops.mcp.detector;

import com.kcops.mcp.config.KcopsProperties;
import com.kcops.mcp.detector.dlp.JsonTextExtractor;
import com.kcops.mcp.model.McpResponse;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;

@Component
public class PromptInjectionResponseDetector implements ResponseDetector {

    private static final String REASON = "PROMPT_INJECTION_DETECTED";
    private static final String DEFAULT_TYPE = "prompt_injection";
    private static final Pattern BASE64_TOKEN = Pattern.compile("[A-Za-z0-9+/]{16,}={0,2}");

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
        if (resp.result() != null && resp.result().path("tools").isArray()) {
            return List.of();
        }
        String text = (resp.rawBody() == null ? "" : resp.rawBody())
                + "\n" + JsonTextExtractor.extract(resp.raw());
        KcopsProperties.Injection injection = properties.getResponse().getInjection();
        Set<String> variants = InjectionTextNormalizer.variants(
                inspectionText(text, injection.isDecodeBase64()));
        Map<String, List<String>> types = injection.getTypes();

        if (types == null || types.isEmpty()) {
            return matchesAny(variants, injection.getPatterns())
                    ? List.of(finding(name()))
                    : List.of();
        }

        List<Finding> findings = new ArrayList<>();
        types.forEach((type, patterns) -> {
            if (matchesAny(variants, patterns)) {
                findings.add(finding(type));
            }
        });
        if (matchesAny(variants, injection.getPatterns())
                && findings.stream().noneMatch(finding -> DEFAULT_TYPE.equals(finding.detector()))) {
            findings.add(finding(DEFAULT_TYPE));
        }
        return List.copyOf(findings);
    }

    private String inspectionText(String text, boolean decodeBase64) {
        if (!decodeBase64) {
            return text;
        }

        StringBuilder combined = new StringBuilder(text);
        Matcher matcher = BASE64_TOKEN.matcher(text);
        while (matcher.find()) {
            try {
                byte[] decoded = Base64.getDecoder().decode(matcher.group());
                combined.append('\n').append(new String(decoded, StandardCharsets.UTF_8));
            } catch (IllegalArgumentException ignored) {
                // Base64처럼 보이지만 유효하지 않은 토큰은 검사 대상에서 제외한다.
            }
        }
        return combined.toString();
    }

    private boolean matchesAny(Set<String> variants, List<String> patterns) {
        return patterns != null && patterns.stream()
                .filter(pattern -> pattern != null && !pattern.isEmpty())
                .anyMatch(pattern -> matches(variants, pattern));
    }

    private boolean matches(Set<String> variants, String pattern) {
        String loweredPattern = pattern.toLowerCase(Locale.ROOT);
        String compactPattern = InjectionTextNormalizer.compact(pattern);
        return variants.stream().anyMatch(variant ->
                variant.contains(loweredPattern)
                        || !compactPattern.isEmpty() && variant.contains(compactPattern));
    }

    private Finding finding(String detector) {
        return new Finding(detector, PolicyCategory.INJECTION, REASON, Finding.Severity.HIGH);
    }
}
