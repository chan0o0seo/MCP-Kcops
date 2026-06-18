package com.kcops.mcp.detector;

import com.kcops.mcp.detector.dlp.SensitiveDataScanner;
import com.kcops.mcp.detector.dlp.SensitiveMatch;
import com.kcops.mcp.mask.MaskSpan;
import com.kcops.mcp.model.McpResponse;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

@Component
public class KoreanPiiResponseDetector implements ResponseDetector {

    @Override
    public String name() {
        return "KoreanPiiResponseDetector";
    }

    @Override
    public List<Finding> inspect(McpResponse resp) {
        String text = resp.rawBody() == null ? "" : resp.rawBody();
        return toFindings(SensitiveDataScanner.scan(text), "PII_DETECTED", "SECRET_DETECTED");
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
