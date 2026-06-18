package com.kcops.mcp.fingerprint;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.kcops.mcp.config.KcopsProperties;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class ToolFingerprintStore {

    private static final Logger log = LoggerFactory.getLogger(ToolFingerprintStore.class);
    private final ObjectMapper objectMapper;
    private final Path path;
    private final ConcurrentHashMap<String, FingerprintState> fingerprints = new ConcurrentHashMap<>();

    public ToolFingerprintStore(KcopsProperties properties, ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
        this.path = Path.of(properties.getFingerprintStorePath());
        load();
    }

    public synchronized boolean checkAndRegister(
            String toolName,
            String descriptionHash,
        String schemaHash
    ) {
        Fingerprint observed = new Fingerprint(descriptionHash, schemaHash);
        FingerprintState previous = fingerprints.get(toolName);
        if (previous == null) {
            fingerprints.put(toolName, new FingerprintState(observed, observed));
            save();
            return false;
        }
        if (observed.equals(previous.current())) {
            return false;
        }
        fingerprints.put(toolName, new FingerprintState(previous.baseline(), observed));
        save();
        return !observed.equals(previous.baseline());
    }

    public static String sha256Hex(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] bytes = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder builder = new StringBuilder(bytes.length * 2);
            for (byte b : bytes) {
                builder.append(String.format("%02x", b));
            }
            return builder.toString();
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is not available", ex);
        }
    }

    private synchronized void load() {
        if (!Files.exists(path)) {
            return;
        }
        try {
            Map<String, FingerprintState> loaded = objectMapper.readValue(
                    Files.readString(path, StandardCharsets.UTF_8),
                    new TypeReference<>() {
                    }
            );
            fingerprints.putAll(loaded);
        } catch (IOException ex) {
            log.warn("Failed to load tool fingerprints from {}; continuing with in-memory store", path, ex);
        }
    }

    private void save() {
        try {
            Path parent = path.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Files.writeString(path, objectMapper.writeValueAsString(fingerprints), StandardCharsets.UTF_8);
        } catch (IOException ex) {
            log.warn("Failed to persist tool fingerprints to {}; continuing with in-memory store", path, ex);
        }
    }

    public record Fingerprint(String descriptionHash, String schemaHash) {
    }

    public record FingerprintState(Fingerprint baseline, Fingerprint current) {
    }
}
