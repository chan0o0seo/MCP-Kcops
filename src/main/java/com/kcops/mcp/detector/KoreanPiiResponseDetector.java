package com.kcops.mcp.detector;

import com.kcops.mcp.detector.dlp.SensitiveDataScanner;
import com.kcops.mcp.detector.dlp.SensitiveMatch;
import com.kcops.mcp.detector.dlp.JsonTextExtractor;
import com.kcops.mcp.mask.MaskSpan;
import com.kcops.mcp.model.McpResponse;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.stereotype.Component;

@Component
public class KoreanPiiResponseDetector implements ResponseDetector {

    @Override
    public String name() {
        return "KoreanPiiResponseDetector";
    }

    @Override
    public List<Finding> inspect(McpResponse resp) {
        String rawBody = resp.rawBody() == null ? "" : resp.rawBody();
        return findingsWithDecodedPresence(
                rawBody,
                JsonTextExtractor.extract(resp.raw()),
                "PII_DETECTED",
                "SECRET_DETECTED"
        );
    }

    static List<Finding> findingsWithDecodedPresence(
            String rawBody,
            String decodedText,
            String piiReason,
            String secretReason
    ) {
        List<SensitiveMatch> rawMatches = SensitiveDataScanner.scan(rawBody);
        List<Finding> findings = new ArrayList<>(toFindings(rawMatches, piiReason, secretReason));
        Set<String> rawValues = rawMatches.stream()
                .map(SensitiveMatch::value)
                .collect(Collectors.toSet());
        List<SensitiveMatch> decodedOnlyMatches = SensitiveDataScanner.scan(decodedText).stream()
                .filter(match -> !rawValues.contains(match.value()))
                .toList();

        Map<String, SensitiveMatch> decodedOnlyByDetector = new LinkedHashMap<>();
        for (SensitiveMatch match : decodedOnlyMatches) {
            decodedOnlyByDetector.putIfAbsent(match.detectorName(), match);
        }
        for (SensitiveMatch match : decodedOnlyByDetector.values()) {
            String reason = match.category() == PolicyCategory.SECRET ? secretReason : piiReason;
            findings.add(new Finding(match.detectorName(), match.category(), reason, Finding.Severity.HIGH));
        }
        return List.copyOf(findings);
    }

    static List<Finding> toFindings(List<SensitiveMatch> matches, String piiReason, String secretReason) {
        Map<String, List<SensitiveMatch>> byDetector = new LinkedHashMap<>();
        for (SensitiveMatch match : matches) {
            byDetector.computeIfAbsent(match.detectorName(), ignored -> new ArrayList<>()).add(match);
        }

        List<Finding> findings = new ArrayList<>();
        for (Map.Entry<String, List<SensitiveMatch>> entry : byDetector.entrySet()) {
            SensitiveMatch first = entry.getValue().get(0);
            List<MaskSpan> spans = entry.getValue().stream()
                    .map(match -> new MaskSpan(match.start(), match.end(), match.maskChar(), match.replacement()))
                    .toList();
            String reason = first.category() == PolicyCategory.SECRET ? secretReason : piiReason;
            findings.add(new Finding(first.detectorName(), first.category(), reason, Finding.Severity.HIGH, spans));
        }
        return List.copyOf(findings);
    }
}
