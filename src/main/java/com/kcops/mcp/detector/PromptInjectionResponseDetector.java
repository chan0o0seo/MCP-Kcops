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
        int scanCap = Math.max(0, injection.getMaxNormalizeChars());
        Set<String> variants = InjectionTextNormalizer.variants(
                inspectionText(text, injection.isDecodeBase64(), injection.getMaxBase64Depth(), scanCap),
                scanCap);
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

    private String inspectionText(String text, boolean decodeBase64, int maxDepth, int scanCap) {
        if (!decodeBase64) {
            return text;
        }
        StringBuilder combined = new StringBuilder(text);
        int cap = scanCap <= 0 ? Integer.MAX_VALUE : Math.multiplyExact(Math.min(scanCap, 1 << 22), 4);
        decodeBase64Into(text, combined, Math.max(1, maxDepth), cap);
        return combined.toString();
    }

    // 중첩 base64를 maxDepth회까지 재귀 디코딩한다. 디코딩 결과가 다시 base64면 한 단계 더 푼다.
    private void decodeBase64Into(String text, StringBuilder combined, int depth, int cap) {
        if (depth <= 0 || combined.length() >= cap) {
            return;
        }
        Matcher matcher = BASE64_TOKEN.matcher(text);
        while (matcher.find()) {
            if (combined.length() >= cap) {
                return;
            }
            try {
                byte[] decoded = Base64.getDecoder().decode(matcher.group());
                String value = new String(decoded, StandardCharsets.UTF_8);
                combined.append('\n').append(value);
                decodeBase64Into(value, combined, depth - 1, cap);
            } catch (IllegalArgumentException ignored) {
                // Base64처럼 보이지만 유효하지 않은 토큰은 검사 대상에서 제외한다.
            }
        }
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
