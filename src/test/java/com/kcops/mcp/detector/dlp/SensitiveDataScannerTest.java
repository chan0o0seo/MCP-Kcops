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
    void detectsKoreanRrnAdjacentToKoreanTextWithOffsets() {
        String trailingText = "900101-1000006입니다";
        String leadingText = "주민번호900101-1000006";

        assertThat(SensitiveDataScanner.scan(trailingText))
                .filteredOn(match -> match.detectorName().equals("korean_rrn"))
                .extracting(match -> trailingText.substring(match.start(), match.end()))
                .containsExactly("900101", "1000006");
        assertThat(SensitiveDataScanner.scan(leadingText))
                .filteredOn(match -> match.detectorName().equals("korean_rrn"))
                .extracting(match -> leadingText.substring(match.start(), match.end()))
                .containsExactly("900101", "1000006");
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
    void detectsKoreanPhoneAdjacentToKoreanTextWithMaskSpan() {
        String trailingText = "010-2345-6789입니다";
        String leadingText = "연락처010-2345-6789";

        assertThat(SensitiveDataScanner.scan(trailingText))
                .filteredOn(match -> match.detectorName().equals("korean_phone"))
                .singleElement()
                .satisfies(match -> assertThat(trailingText.substring(match.start(), match.end()))
                        .isEqualTo("2345"));
        assertThat(SensitiveDataScanner.scan(leadingText))
                .filteredOn(match -> match.detectorName().equals("korean_phone"))
                .singleElement()
                .satisfies(match -> assertThat(leadingText.substring(match.start(), match.end()))
                        .isEqualTo("2345"));
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
    void detectsEmailAdjacentToKoreanTextWithMaskSpan() {
        String trailingText = "minji.kim@example.com입니다";
        String leadingText = "메일minji.kim@example.com";

        assertThat(SensitiveDataScanner.scan(trailingText))
                .filteredOn(match -> match.detectorName().equals("email"))
                .singleElement()
                .satisfies(match -> assertThat(trailingText.substring(match.start(), match.end()))
                        .isEqualTo("inji.kim"));
        assertThat(SensitiveDataScanner.scan(leadingText))
                .filteredOn(match -> match.detectorName().equals("email"))
                .singleElement()
                .satisfies(match -> assertThat(leadingText.substring(match.start(), match.end()))
                        .isEqualTo("inji.kim"));
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
    void detectsBankAccountAdjacentToKoreanTextWhenContextIsPresent() {
        String text = "계좌123-456-789012입니다";

        assertThat(SensitiveDataScanner.scan(text))
                .filteredOn(match -> match.detectorName().equals("korean_bank_account"))
                .extracting(match -> text.substring(match.start(), match.end()))
                .containsExactly("123", "456", "789012");
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
    void detectsSecretsAdjacentToKoreanTextWithMaskSpans() {
        String apiKeyText = "키sk-live-abc12345가";
        String jwtText = "토큰eyJheader.eyJpayload.signature를";

        assertThat(SensitiveDataScanner.scan(apiKeyText))
                .filteredOn(match -> match.detectorName().equals("api_key"))
                .singleElement()
                .satisfies(match -> assertThat(apiKeyText.substring(match.start(), match.end()))
                        .isEqualTo("ive-abc12345"));
        assertThat(SensitiveDataScanner.scan(jwtText))
                .filteredOn(match -> match.detectorName().equals("jwt"))
                .singleElement()
                .satisfies(match -> assertThat(jwtText.substring(match.start(), match.end()))
                        .isEqualTo("eyJheader.eyJpayload.signature"));
    }

    @Test
    void doesNotMatchSensitiveTokensInsideLongerAsciiRuns() {
        assertThat(SensitiveDataScanner.scan("12900101-10000061"))
                .extracting(SensitiveMatch::detectorName)
                .doesNotContain("korean_rrn");
        assertThat(SensitiveDataScanner.scan("9010-2345-67890"))
                .extracting(SensitiveMatch::detectorName)
                .doesNotContain("korean_phone");
        assertThat(SensitiveDataScanner.scan("계좌 1123-456-7890123"))
                .extracting(SensitiveMatch::detectorName)
                .doesNotContain("korean_bank_account");
        assertThat(SensitiveDataScanner.scan("prefixsk-live-abc12345suffix"))
                .extracting(SensitiveMatch::detectorName)
                .doesNotContain("api_key");
        assertThat(SensitiveDataScanner.scan("prefixeyJheader.eyJpayload.signaturesuffix"))
                .extracting(SensitiveMatch::detectorName)
                .doesNotContain("jwt");
        assertThat(SensitiveDataScanner.scan("minji.kim@example.com1"))
                .extracting(SensitiveMatch::detectorName)
                .doesNotContain("email");
    }

    @Test
    void doesNotTreatNameAsStandalonePii() {
        assertThat(SensitiveDataScanner.scan("홍길동입니다")).isEmpty();
        assertThat(SensitiveDataScanner.koreanNameSignalScore("홍길동")).isGreaterThanOrEqualTo(1);
    }
}
