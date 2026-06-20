package com.kcops.mcp.detector.dlp;

import com.kcops.mcp.detector.PolicyCategory;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class SensitiveDataScanner {

    // 하이픈은 선택적이다(900101-1234568 / 9001011234568 모두 탐지). 앞 6자리와 뒤 7자리를 각각 캡처해
    // 하이픈은 그대로 두고 숫자만 마스킹한다.
    private static final Pattern KOREAN_RRN = Pattern.compile("(?<![0-9])(\\d{6})-?(\\d{7})(?![0-9])");
    // 구분자는 하이픈/점/공백을 허용하고, 국가코드(+82)와 그에 따른 선행 0 생략도 처리한다.
    // 선행 0 생략(1로 시작)은 리터럴 '+'가 붙은 +82일 때만 허용해 일반 숫자열(예: 82로 시작) 오탐을 막는다.
    private static final Pattern KOREAN_PHONE = Pattern.compile(
            "(?<![0-9+])(?:\\+82[-. ]?0?|0)1[016-9][-. ]?(\\d{3,4})[-. ]?\\d{4}(?![0-9])"
    );
    private static final Pattern EMAIL = Pattern.compile(
            "(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}(?![A-Za-z0-9.-])"
    );
    private static final Pattern BANK_ACCOUNT = Pattern.compile(
            "(?<![0-9])(?:\\d{2,6}-\\d{2,6}-\\d{2,6}|\\d{10,14})(?![0-9])"
    );
    private static final Pattern ADDRESS = Pattern.compile(
            "((?:서울특별시|부산광역시|대구광역시|인천광역시|광주광역시|대전광역시|울산광역시|세종특별자치시|제주특별자치도|[가-힣]+도|[가-힣]+시)\\s+[가-힣]+(?:시|군|구)\\s+)"
                    + "((?:[가-힣]+(?:로|길|동)\\s*\\d+(?:-\\d+)?|\\d+(?:-\\d+)?번지)(?:\\s+[가-힣0-9-]+)*)"
    );
    private static final Pattern API_KEY = Pattern.compile(
            "(?<![A-Za-z0-9-])(?:sk-[A-Za-z0-9-]{8,}|AKIA[0-9A-Z]{16})(?![A-Za-z0-9-])"
    );
    private static final Pattern JWT = Pattern.compile(
            "(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+(?![A-Za-z0-9_-])"
    );
    private static final Pattern SSH_PRIVATE_KEY = Pattern.compile(
            "-----BEGIN [A-Z ]*PRIVATE KEY-----[\\s\\S]*?-----END [A-Z ]*PRIVATE KEY-----"
    );
    private static final Pattern KOREAN_NAME = Pattern.compile("\\b[가-힣]{2,4}\\b");
    private static final List<String> BANK_CONTEXT_KEYWORDS = List.of("은행", "계좌", "입금", "예금주", "송금");
    private static final int[] RRN_WEIGHTS = {2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5};

    private SensitiveDataScanner() {
    }

    public static List<SensitiveMatch> scan(String input) {
        String text = input == null ? "" : input;
        List<SensitiveMatch> matches = new ArrayList<>();
        scanRrn(text, matches);
        scanPhone(text, matches);
        scanEmail(text, matches);
        scanBankAccount(text, matches);
        scanAddress(text, matches);
        scanPrefixSecret("api_key", API_KEY, text, matches);
        scanFullMask("jwt", JWT, PolicyCategory.SECRET, text, matches);
        scanReplacement("ssh_private_key", SSH_PRIVATE_KEY, PolicyCategory.SECRET, text, matches);
        return List.copyOf(matches);
    }

    public static boolean hasSensitiveData(String input) {
        return !scan(input).isEmpty();
    }

    public static int koreanNameSignalScore(String input) {
        String text = input == null ? "" : input;
        Matcher matcher = KOREAN_NAME.matcher(text);
        int score = 0;
        while (matcher.find()) {
            score++;
        }
        return score;
    }

    private static void scanRrn(String text, List<SensitiveMatch> matches) {
        Matcher matcher = KOREAN_RRN.matcher(text);
        while (matcher.find()) {
            if (!validRrn(matcher.group())) {
                continue;
            }
            // 앞 6자리와 뒤 7자리를 각각 마스킹한다(하이픈이 있으면 그 사이는 보존됨).
            matches.add(new SensitiveMatch("korean_rrn", PolicyCategory.PII,
                    matcher.start(1), matcher.end(1), '*', null, matcher.group()));
            matches.add(new SensitiveMatch("korean_rrn", PolicyCategory.PII,
                    matcher.start(2), matcher.end(2), '*', null, matcher.group()));
        }
    }

    private static boolean validRrn(String value) {
        String digits = value.replace("-", "");
        int sum = 0;
        for (int i = 0; i < RRN_WEIGHTS.length; i++) {
            sum += (digits.charAt(i) - '0') * RRN_WEIGHTS[i];
        }
        int check = (11 - (sum % 11)) % 10;
        return check == digits.charAt(12) - '0';
    }

    private static void scanPhone(String text, List<SensitiveMatch> matches) {
        Matcher matcher = KOREAN_PHONE.matcher(text);
        while (matcher.find()) {
            matches.add(new SensitiveMatch("korean_phone", PolicyCategory.PII,
                    matcher.start(1), matcher.end(1), '*', null, matcher.group()));
        }
    }

    private static void scanEmail(String text, List<SensitiveMatch> matches) {
        Matcher matcher = EMAIL.matcher(text);
        while (matcher.find()) {
            int at = text.indexOf('@', matcher.start());
            if (at > matcher.start() && at < matcher.end()) {
                matches.add(new SensitiveMatch("email", PolicyCategory.PII,
                        matcher.start() + 1, at, '*', null, matcher.group()));
            }
        }
    }

    private static void scanBankAccount(String text, List<SensitiveMatch> matches) {
        String lowered = text.toLowerCase(Locale.ROOT);
        boolean hasContext = BANK_CONTEXT_KEYWORDS.stream().anyMatch(lowered::contains);
        if (!hasContext) {
            return;
        }
        Matcher matcher = BANK_ACCOUNT.matcher(text);
        while (matcher.find()) {
            Matcher digitRun = Pattern.compile("\\d+").matcher(matcher.group());
            while (digitRun.find()) {
                matches.add(new SensitiveMatch("korean_bank_account", PolicyCategory.PII,
                        matcher.start() + digitRun.start(), matcher.start() + digitRun.end(), '*', null,
                        matcher.group()));
            }
        }
    }

    private static void scanAddress(String text, List<SensitiveMatch> matches) {
        Matcher matcher = ADDRESS.matcher(text);
        while (matcher.find()) {
            String detail = matcher.group(2);
            if (detail == null || detail.isBlank()) {
                continue;
            }
            matches.add(new SensitiveMatch("korean_address", PolicyCategory.PII,
                    matcher.start(2), matcher.end(2), '*', "****", matcher.group()));
        }
    }

    private static void scanPrefixSecret(String detectorName, Pattern pattern, String text, List<SensitiveMatch> matches) {
        Matcher matcher = pattern.matcher(text);
        while (matcher.find()) {
            int keep = Math.min(4, matcher.end() - matcher.start());
            matches.add(new SensitiveMatch(detectorName, PolicyCategory.SECRET,
                    matcher.start() + keep, matcher.end(), '*', null, matcher.group()));
        }
    }

    private static void scanFullMask(String detectorName, Pattern pattern, PolicyCategory category, String text,
                                     List<SensitiveMatch> matches) {
        Matcher matcher = pattern.matcher(text);
        while (matcher.find()) {
            matches.add(new SensitiveMatch(detectorName, category, matcher.start(), matcher.end(), '*', null,
                    matcher.group()));
        }
    }

    private static void scanReplacement(String detectorName, Pattern pattern, PolicyCategory category, String text,
                                        List<SensitiveMatch> matches) {
        Matcher matcher = pattern.matcher(text);
        while (matcher.find()) {
            matches.add(new SensitiveMatch(detectorName, category, matcher.start(), matcher.end(), '*', "****",
                    matcher.group()));
        }
    }
}
