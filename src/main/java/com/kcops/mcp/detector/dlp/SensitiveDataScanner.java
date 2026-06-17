package com.kcops.mcp.detector.dlp;

import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Stream;

public final class SensitiveDataScanner {

    private static final Pattern KOREAN_RRN = Pattern.compile("\\b\\d{6}-\\d{7}\\b");
    private static final Pattern KOREAN_PHONE = Pattern.compile("\\b01[0-9]-?\\d{3,4}-?\\d{4}\\b");
    private static final Pattern EMAIL = Pattern.compile("\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b");
    private static final Pattern API_KEY = Pattern.compile("\\bsk-[A-Za-z0-9-]{8,}\\b");

    private SensitiveDataScanner() {
    }

    public static List<SensitiveMatch> scan(String input) {
        String text = input == null ? "" : input;
        return Stream.of(
                        match("korean_rrn", KOREAN_RRN, text),
                        match("korean_phone", KOREAN_PHONE, text),
                        match("email", EMAIL, text),
                        match("api_key", API_KEY, text)
                )
                .flatMap(List::stream)
                .toList();
    }

    public static boolean hasSensitiveData(String input) {
        return !scan(input).isEmpty();
    }

    private static List<SensitiveMatch> match(String detectorName, Pattern pattern, String text) {
        if (pattern.matcher(text).find()) {
            return List.of(new SensitiveMatch(detectorName));
        }
        return List.of();
    }
}
