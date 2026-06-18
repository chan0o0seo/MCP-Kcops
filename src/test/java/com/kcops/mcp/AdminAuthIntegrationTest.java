package com.kcops.mcp;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import reactor.netty.DisposableServer;
import reactor.netty.http.server.HttpServer;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AdminAuthIntegrationTest {

    private static final DisposableServer upstream = HttpServer.create()
            .host("127.0.0.1")
            .port(0)
            .handle((request, response) -> {
                String json = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":\"ok\"}}";
                return request.receive().then(response
                        .header("Content-Type", "application/json;charset=UTF-8")
                        .sendByteArray(Mono.just(json.getBytes(StandardCharsets.UTF_8)))
                        .then());
            })
            .bindNow();
    private static final Path tempDir = createTempDir();

    @Autowired
    WebTestClient webTestClient;

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("kcops.admin.token", () -> "test-admin-token");
        registry.add("kcops.upstream-url", () -> "http://127.0.0.1:" + upstream.port() + "/mcp");
        registry.add("kcops.audit-log-path", () -> tempDir.resolve("audit.jsonl").toString());
        registry.add("kcops.audit-anchor-path", () -> tempDir.resolve("audit-anchor.jsonl").toString());
        registry.add("kcops.fingerprint-store-path", () -> tempDir.resolve("fingerprints.json").toString());
    }

    @AfterAll
    static void stopUpstream() {
        upstream.disposeNow();
    }

    @Test
    void rejectsMissingAdminToken() {
        webTestClient.get().uri("/admin/approvals")
                .exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().contentType("application/json;charset=UTF-8")
                .expectBody()
                .jsonPath("$.error").isEqualTo("unauthorized");
    }

    @Test
    void rejectsWrongAdminToken() {
        webTestClient.get().uri("/admin/approvals")
                .header("Authorization", "Bearer wrong")
                .exchange()
                .expectStatus().isUnauthorized()
                .expectBody()
                .jsonPath("$.error").isEqualTo("unauthorized");
    }

    @Test
    void acceptsCorrectAdminToken() {
        webTestClient.get().uri("/admin/approvals")
                .header("Authorization", "Bearer test-admin-token")
                .exchange()
                .expectStatus().isOk();
    }

    @Test
    void doesNotProtectMcpRoute() {
        String request = """
                {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"calendar_lookup","arguments":{}}}
                """;

        webTestClient.post().uri("/mcp")
                .bodyValue(request)
                .exchange()
                .expectStatus().isOk();
    }

    private static Path createTempDir() {
        try {
            return Files.createTempDirectory("kcops-admin-auth-");
        } catch (IOException ex) {
            throw new IllegalStateException(ex);
        }
    }
}
