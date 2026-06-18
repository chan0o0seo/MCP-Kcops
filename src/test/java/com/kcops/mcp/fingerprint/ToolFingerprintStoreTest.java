package com.kcops.mcp.fingerprint;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kcops.mcp.config.KcopsProperties;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.assertj.core.api.Assertions.assertThat;

class ToolFingerprintStoreTest {

    @TempDir
    Path tempDir;

    @Test
    void registersAndUpdatesFingerprints() {
        ToolFingerprintStore store = store();

        assertThat(store.checkAndRegister("search_mail", "description-1", "schema-1")).isFalse();
        assertThat(store.checkAndRegister("search_mail", "description-1", "schema-1")).isFalse();
        assertThat(store.checkAndRegister("search_mail", "description-2", "schema-1")).isTrue();
        assertThat(store.checkAndRegister("search_mail", "description-2", "schema-2")).isTrue();
        assertThat(store.checkAndRegister("search_mail", "description-2", "schema-2")).isFalse();
        assertThat(store.checkAndRegister("search_mail", "description-1", "schema-1")).isFalse();
    }

    @Test
    void loadsPersistedFingerprintsOnStartup() {
        ToolFingerprintStore first = store();
        assertThat(first.checkAndRegister("search_mail", "description-1", "schema-1")).isFalse();
        assertThat(first.checkAndRegister("search_mail", "description-2", "schema-1")).isTrue();

        ToolFingerprintStore reloaded = store();

        assertThat(reloaded.checkAndRegister("search_mail", "description-2", "schema-1")).isFalse();
    }

    private ToolFingerprintStore store() {
        KcopsProperties properties = new KcopsProperties();
        properties.setFingerprintStorePath(tempDir.resolve("fingerprints.json").toString());
        return new ToolFingerprintStore(properties, new ObjectMapper());
    }
}
