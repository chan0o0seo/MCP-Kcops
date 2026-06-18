package com.kcops.mcp.detector.dlp;

import com.kcops.mcp.detector.PolicyCategory;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SensitiveDataScannerTest {

    @Test
    void detectsOnlyChecksumValidKoreanRrnWithOffsets() {
        String text = "주민번호 900101-1234568";

        List<SensitiveMatch> matches = SensitiveDataScanner.scan(text);

        assertThat(matches).extracting(SensitiveMatch::detectorName).containsOnly("korean_rrn");
        assertThat(matches).extracting(SensitiveMatch::start)
                .containsExactly(text.indexOf("900101"), text.indexOf("1234568"));
        assertThat(SensitiveDataScanner.scan("주민번호 900101-1234567"))
                .extracting(SensitiveMatch::detectorName)
                .doesNotContain("korean_rrn");
    }

    @Test
    void detectsKoreanPhoneMiddleGroup() {
        String text = "연락처 010-1234-5678";

        assertThat(SensitiveDataScanner.scan(text))
                .filteredOn(match -> match.detectorName().equals("korean_phone"))
                .singleElement()
                .satisfies(match -> {
                    assertThat(text.substring(match.start(), match.end())).isEqualTo("1234");
                    assertThat(match.category()).isEqualTo(PolicyCategory.PII);
                });
        assertThat(SensitiveDataScanner.scan("번호 020-1234-5678"))
                .extracting(SensitiveMatch::detectorName)
                .doesNotContain("korean_phone");
    }

    @Test
    void detectsEmailLocalPartMaskSpan() {
        String text = "mail hong@example.com";

        assertThat(SensitiveDataScanner.scan(text))
                .filteredOn(match -> match.detectorName().equals("email"))
                .singleElement()
                .satisfies(match -> assertThat(text.substring(match.start(), match.end())).isEqualTo("ong"));
        assertThat(SensitiveDataScanner.scan("user at example dot com"))
                .extracting(SensitiveMatch::detectorName)
                .doesNotContain("email");
    }

    @Test
    void detectsBankAccountOnlyWithContext() {
        assertThat(SensitiveDataScanner.scan("입금 계좌 123-456-789012"))
                .extracting(SensitiveMatch::detectorName)
                .contains("korean_bank_account");
        assertThat(SensitiveDataScanner.scan("주문번호 123456789012 입니다"))
                .extracting(SensitiveMatch::detectorName)
                .doesNotContain("korean_bank_account");
    }

    @Test
    void detectsAddressDetailReplacementSpan() {
        String text = "주소 서울특별시 강남구 테헤란로 123";

        assertThat(SensitiveDataScanner.scan(text))
                .filteredOn(match -> match.detectorName().equals("korean_address"))
                .singleElement()
                .satisfies(match -> {
                    assertThat(text.substring(match.start(), match.end())).isEqualTo("테헤란로 123");
                    assertThat(match.replacement()).isEqualTo("****");
                });
        assertThat(SensitiveDataScanner.scan("업무 처리로 길게 설명했습니다"))
                .extracting(SensitiveMatch::detectorName)
                .doesNotContain("korean_address");
        assertThat(SensitiveDataScanner.scan("서울특별시 강남구 업무 처리로 이어집니다"))
                .extracting(SensitiveMatch::detectorName)
                .doesNotContain("korean_address");
    }

    @Test
    void detectsSecrets() {
        assertThat(SensitiveDataScanner.scan("token sk-live-abc"))
                .extracting(SensitiveMatch::detectorName)
                .contains("api_key");
        assertThat(SensitiveDataScanner.scan("aws AKIA1234567890ABCDEF"))
                .extracting(SensitiveMatch::detectorName)
                .contains("api_key");
        assertThat(SensitiveDataScanner.scan("jwt eyJabc.eyJdef.signature"))
                .extracting(SensitiveMatch::detectorName)
                .contains("jwt");
        assertThat(SensitiveDataScanner.scan("""
                -----BEGIN PRIVATE KEY-----
                abc
                -----END PRIVATE KEY-----
                """))
                .extracting(SensitiveMatch::detectorName)
                .contains("ssh_private_key");
        assertThat(SensitiveDataScanner.scan("token sk-short"))
                .extracting(SensitiveMatch::detectorName)
                .doesNotContain("api_key");
        assertThat(SensitiveDataScanner.scan("jwt eyJabc.only-two-parts"))
                .extracting(SensitiveMatch::detectorName)
                .doesNotContain("jwt");
        assertThat(SensitiveDataScanner.scan("-----BEGIN PRIVATE KEY----- incomplete"))
                .extracting(SensitiveMatch::detectorName)
                .doesNotContain("ssh_private_key");
    }

    @Test
    void doesNotTreatNameAsStandalonePii() {
        assertThat(SensitiveDataScanner.scan("홍길동입니다")).isEmpty();
        assertThat(SensitiveDataScanner.koreanNameSignalScore("홍길동")).isGreaterThanOrEqualTo(1);
    }
}
