package com.kcops.mcp.detector;

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

    private static final Pattern HEX_BYTES = Pattern.compile(
            "(?<![0-9a-fA-F])((?:[0-9a-fA-F]{2}[\\s]*){4,})(?![0-9a-fA-F])");
    private static final Pattern INLINE_BRACKET_INSERTION = Pattern.compile(
            "(?<=[\\p{L}\\p{N}])\\[[^\\]\\r\\n]{1,32}](?=[\\p{L}\\p{N}])");
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
        if (value == null || value.isEmpty()) {
            return "";
        }
        StringBuilder decoded = new StringBuilder(value.length());
        for (int index = 0; index < value.length(); index++) {
            char current = value.charAt(index);
            char replacement = leetReplacement(current);
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
                String text = StandardCharsets.UTF_8.newDecoder()
                        .onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT)
                        .decode(ByteBuffer.wrap(bytes))
                        .toString();
                if (!decoded.isEmpty()) {
                    decoded.append('\n');
                }
                decoded.append(text);
            } catch (IllegalArgumentException | CharacterCodingException ignored) {
                // Invalid hex or UTF-8 tokens are not useful matching variants.
            }
        }
        return decoded.toString();
    }

    public static Set<String> variants(String raw) {
        Set<String> variants = new LinkedHashSet<>();
        addVariants(variants, raw);
        addVariants(variants, rot13(raw));
        addVariants(variants, decodeHexBytes(raw));
        return Set.copyOf(variants);
    }

    private static void addVariants(Set<String> variants, String value) {
        if (value == null || value.isEmpty()) {
            return;
        }
        String normalized = normalizeNfkc(value);
        String canonical = deLeet(mapHomoglyphs(normalized));
        addIfNotEmpty(variants, value.toLowerCase(Locale.ROOT));
        addIfNotEmpty(variants, normalized);
        addIfNotEmpty(variants, canonical);
        addIfNotEmpty(variants, compact(canonical));
    }

    private static void addIfNotEmpty(Set<String> variants, String value) {
        if (value != null && !value.isEmpty()) {
            variants.add(value);
        }
    }

    private static boolean hasAdjacentAsciiLetter(String value, int index) {
        return index > 0 && isAsciiLetter(value.charAt(index - 1))
                || index + 1 < value.length() && isAsciiLetter(value.charAt(index + 1));
    }

    private static boolean isAsciiLetter(char value) {
        return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z';
    }

    private static char leetReplacement(char value) {
        return switch (value) {
            case '0' -> 'o';
            case '1' -> 'l';
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
