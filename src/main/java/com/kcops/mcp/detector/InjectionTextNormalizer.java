package com.kcops.mcp.detector;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class InjectionTextNormalizer {

    /**
     * variants()가 비용이 큰 디코딩 계층을 적용할 입력 길이 상한(코드포인트 수)의 기본값.
     * 이보다 긴 입력은 기본 정규화(평문·NFKC·compact)만 적용해 CPU·메모리 고갈을 막는다.
     */
    public static final int DEFAULT_MAX_NORMALIZE_CHARS = 200_000;

    private static final Pattern HEX_BYTES = Pattern.compile(
            "(?<![0-9a-fA-F])((?:[0-9a-fA-F]{2}[\\s]*){4,})(?![0-9a-fA-F])");
    private static final Pattern INLINE_BRACKET_INSERTION = Pattern.compile(
            "(?<=[\\p{L}\\p{N}])\\[[^\\]\\r\\n]{1,32}](?=[\\p{L}\\p{N}])");
    private static final Pattern HTML_ENTITY = Pattern.compile(
            "&#(x?)([0-9a-fA-F]{1,6});|&([a-zA-Z][a-zA-Z0-9]{1,9});");
    // base32 후보: 경계로 분리된 A-Z/a-z/2-7 토큰. 평문 단어 오인을 줄이기 위해
    // 숫자(2-7)나 패딩(=)을 하나 이상 포함한 토큰만 디코딩 대상으로 본다.
    private static final Pattern BASE32_TOKEN = Pattern.compile(
            "(?<![A-Za-z2-7])([A-Za-z2-7]{8,}={0,6})(?![A-Za-z2-7])");
    private static final String BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private static final Map<String, Character> NAMED_ENTITIES = Map.of(
            "amp", '&',
            "lt", '<',
            "gt", '>',
            "quot", '"',
            "apos", '\'',
            "nbsp", ' '
    );
    private static final Map<Integer, Character> HOMOGLYPHS = Map.ofEntries(
            Map.entry((int) 'а', 'a'),
            Map.entry((int) 'е', 'e'),
            Map.entry((int) 'о', 'o'),
            Map.entry((int) 'р', 'p'),
            Map.entry((int) 'с', 'c'),
            Map.entry((int) 'х', 'x'),
            Map.entry((int) 'у', 'y'),
            Map.entry((int) 'і', 'i'),
            Map.entry((int) 'ј', 'j'),
            Map.entry((int) 'κ', 'k'),
            Map.entry((int) 'ο', 'o'),
            Map.entry((int) 'ρ', 'p'),
            Map.entry((int) 'τ', 't'),
            Map.entry((int) 'χ', 'x'),
            Map.entry((int) 'ι', 'i'),
            Map.entry((int) 'α', 'a'),
            Map.entry((int) 'ε', 'e')
    );

    private InjectionTextNormalizer() {
    }

    public static String normalizeNfkc(String value) {
        if (value == null || value.isEmpty()) {
            return "";
        }
        return Normalizer.normalize(value, Normalizer.Form.NFKC).toLowerCase(Locale.ROOT);
    }

    public static String mapHomoglyphs(String value) {
        if (value == null || value.isEmpty()) {
            return "";
        }
        StringBuilder mapped = new StringBuilder(value.length());
        value.codePoints().forEach(codePoint -> {
            Character replacement = HOMOGLYPHS.get(codePoint);
            if (replacement == null) {
                mapped.appendCodePoint(codePoint);
            } else {
                mapped.append(replacement);
            }
        });
        return mapped.toString();
    }

    public static String deLeet(String value) {
        return deLeet(value, false);
    }

    private static String deLeet(String value, boolean oneAsLetterI) {
        if (value == null || value.isEmpty()) {
            return "";
        }
        StringBuilder decoded = new StringBuilder(value.length());
        for (int index = 0; index < value.length(); index++) {
            char current = value.charAt(index);
            char replacement = leetReplacement(current, oneAsLetterI);
            if (replacement != 0 && hasAdjacentAsciiLetter(value, index)) {
                decoded.append(replacement);
            } else {
                decoded.append(current);
            }
        }
        return decoded.toString();
    }

    public static String compact(String value) {
        String withoutBracketInsertions = value == null
                ? ""
                : INLINE_BRACKET_INSERTION.matcher(value).replaceAll("");
        String normalized = deLeet(mapHomoglyphs(normalizeNfkc(withoutBracketInsertions)));
        return compactChars(normalized);
    }

    private static String compactChars(String normalized) {
        StringBuilder compacted = new StringBuilder(normalized.length());
        normalized.codePoints()
                .filter(InjectionTextNormalizer::isCompactCharacter)
                .forEach(compacted::appendCodePoint);
        return compacted.toString();
    }

    public static String rot13(String value) {
        if (value == null || value.isEmpty()) {
            return "";
        }
        StringBuilder decoded = new StringBuilder(value.length());
        for (int index = 0; index < value.length(); index++) {
            char current = value.charAt(index);
            if (current >= 'a' && current <= 'z') {
                decoded.append((char) ('a' + (current - 'a' + 13) % 26));
            } else if (current >= 'A' && current <= 'Z') {
                decoded.append((char) ('A' + (current - 'A' + 13) % 26));
            } else {
                decoded.append(current);
            }
        }
        return decoded.toString();
    }

    public static String reverse(String value) {
        if (value == null || value.isEmpty()) {
            return "";
        }
        return new StringBuilder(value).reverse().toString();
    }

    public static String decodeHexBytes(String value) {
        if (value == null || value.isEmpty()) {
            return "";
        }
        StringBuilder decoded = new StringBuilder();
        Matcher matcher = HEX_BYTES.matcher(value);
        while (matcher.find()) {
            String token = matcher.group(1).replaceAll("\\s", "");
            try {
                byte[] bytes = new byte[token.length() / 2];
                for (int index = 0; index < token.length(); index += 2) {
                    bytes[index / 2] = (byte) Integer.parseInt(token.substring(index, index + 2), 16);
                }
                appendStrictUtf8(decoded, bytes);
            } catch (IllegalArgumentException ignored) {
                // Invalid hex tokens are not useful matching variants.
            }
        }
        return decoded.toString();
    }

    /**
     * %XX / %uXXXX URL 퍼센트 인코딩을 디코딩한다. 연속된 %XX 바이트는 UTF-8로 묶어 해석한다.
     * '+'는 공백으로 바꾸지 않는다(정상 텍스트 오탐 방지).
     */
    public static String urlDecode(String value) {
        if (value == null || value.indexOf('%') < 0) {
            return "";
        }
        StringBuilder out = new StringBuilder(value.length());
        ByteArrayOutputStream pending = new ByteArrayOutputStream();
        int index = 0;
        while (index < value.length()) {
            char current = value.charAt(index);
            if (current == '%' && index + 1 < value.length()
                    && (value.charAt(index + 1) == 'u' || value.charAt(index + 1) == 'U')
                    && index + 5 < value.length() && isHex(value, index + 2, 4)) {
                flushUtf8(out, pending);
                out.append((char) Integer.parseInt(value.substring(index + 2, index + 6), 16));
                index += 6;
            } else if (current == '%' && index + 2 < value.length() && isHex(value, index + 1, 2)) {
                pending.write(Integer.parseInt(value.substring(index + 1, index + 3), 16));
                index += 3;
            } else {
                flushUtf8(out, pending);
                out.append(current);
                index++;
            }
        }
        flushUtf8(out, pending);
        return out.toString();
    }

    /**
     * &#NN; / &#xHH; 수치 참조와 흔한 명명 엔티티(&amp; 등)를 디코딩한다.
     */
    public static String htmlEntityDecode(String value) {
        if (value == null || value.indexOf('&') < 0) {
            return "";
        }
        Matcher matcher = HTML_ENTITY.matcher(value);
        StringBuilder out = new StringBuilder(value.length());
        while (matcher.find()) {
            String replacement;
            if (matcher.group(3) != null) {
                Character named = NAMED_ENTITIES.get(matcher.group(3).toLowerCase(Locale.ROOT));
                replacement = named == null ? matcher.group() : String.valueOf(named);
            } else {
                int radix = matcher.group(1).isEmpty() ? 10 : 16;
                try {
                    int codePoint = Integer.parseInt(matcher.group(2), radix);
                    replacement = Character.isValidCodePoint(codePoint)
                            && codePoint != 0
                            ? new String(Character.toChars(codePoint))
                            : matcher.group();
                } catch (NumberFormatException ex) {
                    replacement = matcher.group();
                }
            }
            matcher.appendReplacement(out, Matcher.quoteReplacement(replacement));
        }
        matcher.appendTail(out);
        return out.toString();
    }

    /**
     * RFC 4648 base32 토큰을 디코딩한다. 유효한 UTF-8로 복원되는 토큰만 채택해 평문 오탐을 막는다.
     */
    public static String base32Decode(String value) {
        if (value == null || value.isEmpty()) {
            return "";
        }
        StringBuilder decoded = new StringBuilder();
        Matcher matcher = BASE32_TOKEN.matcher(value);
        while (matcher.find()) {
            String token = matcher.group(1);
            String stripped = token.replace("=", "").toUpperCase(Locale.ROOT);
            // 숫자(2-7)나 패딩(=)이 없는 순수 알파벳 토큰은 평문 단어일 가능성이 높아 건너뛴다.
            if (stripped.equals(token.toUpperCase(Locale.ROOT))
                    && token.chars().noneMatch(c -> c >= '2' && c <= '7')) {
                continue;
            }
            byte[] bytes = decodeBase32(stripped);
            if (bytes == null || bytes.length == 0) {
                continue;
            }
            int before = decoded.length();
            appendStrictUtf8(decoded, bytes);
            if (decoded.length() == before) {
                // strict UTF-8 디코딩 실패: 토큰을 채택하지 않는다.
                continue;
            }
            decoded.append('\n');
        }
        return decoded.toString();
    }

    /**
     * 결정적 변환을 적용한 매칭용 변형 집합을 만든다. 기본 자원 상한을 사용한다.
     */
    public static Set<String> variants(String raw) {
        return variants(raw, DEFAULT_MAX_NORMALIZE_CHARS);
    }

    public static Set<String> variants(String raw, int maxNormalizeChars) {
        Set<String> variants = new LinkedHashSet<>();
        if (raw == null || raw.isEmpty()) {
            return Set.of();
        }
        addVariants(variants, raw);
        if (maxNormalizeChars > 0 && raw.length() > maxNormalizeChars) {
            // 자원 상한 초과: 비용이 큰 디코딩 계층은 생략한다. 평문·compact 변형은 이미 반영되어
            // 탐지가 완전히 비활성화되지는 않는다(fail-open 아님).
            return Set.copyOf(variants);
        }
        addVariants(variants, rot13(raw));
        addVariants(variants, decodeHexBytes(raw));
        addVariants(variants, urlDecode(raw));
        addVariants(variants, htmlEntityDecode(raw));
        addVariants(variants, base32Decode(raw));
        addVariants(variants, reverse(raw));
        return Set.copyOf(variants);
    }

    private static void addVariants(Set<String> variants, String value) {
        if (value == null || value.isEmpty()) {
            return;
        }
        String normalized = normalizeNfkc(value);
        String homoglyphed = mapHomoglyphs(normalized);
        String canonical = deLeet(homoglyphed);
        addIfNotEmpty(variants, value.toLowerCase(Locale.ROOT));
        addIfNotEmpty(variants, normalized);
        addIfNotEmpty(variants, canonical);
        addIfNotEmpty(variants, compact(canonical));
        // '1'을 알파벳 i로 보는 대체 leet 해석(1gn0r3 → ignore). 기본 해석('1'→l)과 다를 때만 추가.
        String canonicalAltOne = deLeet(homoglyphed, true);
        if (!canonicalAltOne.equals(canonical)) {
            addIfNotEmpty(variants, compactChars(canonicalAltOne));
        }
    }

    private static void addIfNotEmpty(Set<String> variants, String value) {
        if (value != null && !value.isEmpty()) {
            variants.add(value);
        }
    }

    private static byte[] decodeBase32(String token) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(token.length() * 5 / 8 + 1);
        int buffer = 0;
        int bitsLeft = 0;
        for (int index = 0; index < token.length(); index++) {
            int symbol = BASE32_ALPHABET.indexOf(token.charAt(index));
            if (symbol < 0) {
                return null;
            }
            buffer = (buffer << 5) | symbol;
            bitsLeft += 5;
            if (bitsLeft >= 8) {
                bitsLeft -= 8;
                out.write((buffer >> bitsLeft) & 0xFF);
            }
        }
        return out.toByteArray();
    }

    private static void appendStrictUtf8(StringBuilder target, byte[] bytes) {
        try {
            String text = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes))
                    .toString();
            if (target.length() > 0) {
                target.append('\n');
            }
            target.append(text);
        } catch (CharacterCodingException ignored) {
            // 유효한 UTF-8이 아닌 바이트열은 매칭에 쓸모가 없으므로 버린다.
        }
    }

    private static void flushUtf8(StringBuilder target, ByteArrayOutputStream pending) {
        if (pending.size() == 0) {
            return;
        }
        target.append(new String(pending.toByteArray(), StandardCharsets.UTF_8));
        pending.reset();
    }

    private static boolean isHex(String value, int start, int length) {
        if (start + length > value.length()) {
            return false;
        }
        for (int index = start; index < start + length; index++) {
            char current = value.charAt(index);
            boolean hex = current >= '0' && current <= '9'
                    || current >= 'a' && current <= 'f'
                    || current >= 'A' && current <= 'F';
            if (!hex) {
                return false;
            }
        }
        return true;
    }

    private static boolean hasAdjacentAsciiLetter(String value, int index) {
        return index > 0 && isAsciiLetter(value.charAt(index - 1))
                || index + 1 < value.length() && isAsciiLetter(value.charAt(index + 1));
    }

    private static boolean isAsciiLetter(char value) {
        return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z';
    }

    private static char leetReplacement(char value, boolean oneAsLetterI) {
        return switch (value) {
            case '0' -> 'o';
            case '1' -> oneAsLetterI ? 'i' : 'l';
            case '3' -> 'e';
            case '4', '@' -> 'a';
            case '5', '$' -> 's';
            case '7' -> 't';
            default -> 0;
        };
    }

    private static boolean isCompactCharacter(int codePoint) {
        return codePoint >= 'a' && codePoint <= 'z'
                || codePoint >= '0' && codePoint <= '9'
                || codePoint >= '가' && codePoint <= '힣';
    }
}
