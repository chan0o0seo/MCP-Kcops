package com.kcops.mcp.detector;

import com.kcops.mcp.detector.dlp.SensitiveDataScanner;
import com.kcops.mcp.model.McpRequest;
import java.util.List;
import org.springframework.stereotype.Component;

@Component
public class SensitiveDataRequestDetector implements RequestDetector {

    @Override
    public String name() {
        return "SensitiveDataRequestDetector";
    }

    @Override
    public List<Finding> inspect(McpRequest req) {
        String text = req.rawBody() == null ? "" : req.rawBody();
        return KoreanPiiResponseDetector.toFindings(
                SensitiveDataScanner.scan(text),
                "PII_IN_REQUEST_ARG",
                "SECRET_IN_REQUEST_ARG"
        );
    }
}
