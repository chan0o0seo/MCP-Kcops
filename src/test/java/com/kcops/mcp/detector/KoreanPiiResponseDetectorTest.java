package com.kcops.mcp.detector;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kcops.mcp.mask.Masker;
import com.kcops.mcp.model.McpResponse;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class KoreanPiiResponseDetectorTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void masksDemoContentExactlyWithoutMaskingName() throws Exception {
        String content = "홍길동 / 010-1234-5678 / 900101-1234568 / hong@example.com / 서울특별시 강남구 테헤란로 123";
        McpResponse response = new McpResponse(
                "2.0",
                objectMapper.readTree("1"),
                objectMapper.createObjectNode(),
                null,
                objectMapper.createObjectNode(),
                content
        );

        List<Finding> findings = new KoreanPiiResponseDetector().inspect(response);

        assertThat(findings).extracting(Finding::detector)
                .containsExactly("korean_rrn", "korean_phone", "email", "korean_address");
        assertThat(Masker.mask(content, findings)).isEqualTo(
                "홍길동 / 010-****-5678 / ******-******* / h***@example.com / 서울특별시 강남구 ****"
        );
    }

    @Test
    void ordinaryKoreanTextDoesNotProduceFindings() {
        McpResponse response = new McpResponse(
                "2.0",
                null,
                null,
                null,
                objectMapper.createObjectNode(),
                "홍길동입니다. 오늘 업무 회의 자료를 정리하고 처리로 이어지는 절차를 설명합니다."
        );

        assertThat(new KoreanPiiResponseDetector().inspect(response)).isEmpty();
    }
}
