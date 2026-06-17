package com.kcops.mcp.detector.dlp;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SensitiveDataScannerTest {

    @Test
    void detectsKoreanRrn() {
        assertThat(SensitiveDataScanner.scan("주민번호 900101-1234567"))
                .extracting(SensitiveMatch::detectorName)
                .contains("korean_rrn");
        assertThat(SensitiveDataScanner.scan("날짜 900101-123456")).extracting(SensitiveMatch::detectorName)
                .doesNotContain("korean_rrn");
    }

    @Test
    void detectsKoreanPhone() {
        assertThat(SensitiveDataScanner.scan("연락처 010-1234-5678"))
                .extracting(SensitiveMatch::detectorName)
                .contains("korean_phone");
        assertThat(SensitiveDataScanner.scan("번호 020-1234-5678")).extracting(SensitiveMatch::detectorName)
                .doesNotContain("korean_phone");
    }

    @Test
    void detectsEmail() {
        assertThat(SensitiveDataScanner.scan("user@example.com"))
                .extracting(SensitiveMatch::detectorName)
                .contains("email");
        assertThat(SensitiveDataScanner.scan("user at example dot com")).extracting(SensitiveMatch::detectorName)
                .doesNotContain("email");
    }

    @Test
    void detectsApiKey() {
        assertThat(SensitiveDataScanner.scan("token sk-live-abc"))
                .extracting(SensitiveMatch::detectorName)
                .contains("api_key");
        assertThat(SensitiveDataScanner.scan("token sk-short")).extracting(SensitiveMatch::detectorName)
                .doesNotContain("api_key");
    }
}
