package com.kcops.mcp.mask;

import com.kcops.mcp.detector.Finding;
import com.kcops.mcp.detector.PolicyCategory;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class MaskerTest {

    @Test
    void masksConfiguredSpansAndClampsBounds() {
        Finding finding = new Finding("SyntheticDetector", PolicyCategory.PII, "PII",
                Finding.Severity.HIGH, List.of(
                new MaskSpan(6, 10, '*'),
                new MaskSpan(13, 99, '#')
        ));

        assertThat(Masker.mask("token abcdef secret", List.of(finding)))
                .isEqualTo("token ****ef ######");
    }

    @Test
    void returnsOriginalWhenNoSpansExist() {
        Finding finding = new Finding("SyntheticDetector", PolicyCategory.PII, "PII", Finding.Severity.HIGH);

        assertThat(Masker.mask("plain", List.of(finding))).isEqualTo("plain");
    }
}
