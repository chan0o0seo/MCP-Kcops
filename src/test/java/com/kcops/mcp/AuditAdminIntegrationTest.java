package com.kcops.mcp;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
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
class AuditAdminIntegrationTest {

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
    private static final Path auditPath = tempDir.resolve("audit.jsonl");
    private static final Path anchorPath = tempDir.resolve("audit-anchor.jsonl");

    @Autowired
    WebTestClient webTestClient;

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("kcops.upstream-url", () -> "http://127.0.0.1:" + upstream.port() + "/mcp");
        registry.add("kcops.audit-log-path", auditPath::toString);
        registry.add("kcops.audit-anchor-path", anchorPath::toString);
    }

    @AfterAll
    static void stopUpstream() {
        upstream.disposeNow();
    }

    @Test
    void publishesAnchorVerifiesTrafficAndReportsTamperedLine() throws Exception {
        String request = """
                {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"calendar_lookup","arguments":{}}}
                """;
        webTestClient.post().uri("/mcp")
                .bodyValue(request)
                .exchange()
                .expectStatus().isOk();

        webTestClient.post().uri("/admin/audit/anchor")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.recordCount").isEqualTo(2);

        webTestClient.get().uri("/admin/audit/verify")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.valid").isEqualTo(true)
                .jsonPath("$.brokenAtLine").isEqualTo(-1)
                .jsonPath("$.anchorConsistent").isEqualTo(true);

        List<String> lines = Files.readAllLines(auditPath, StandardCharsets.UTF_8);
        lines.set(0, lines.get(0).replace("NO_FINDINGS", "ALTERED"));
        Files.write(auditPath, lines, StandardCharsets.UTF_8);

        webTestClient.get().uri("/admin/audit/verify")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.valid").isEqualTo(false)
                .jsonPath("$.brokenAtLine").isEqualTo(1);
    }

    private static Path createTempDir() {
        try {
            return Files.createTempDirectory("kcops-audit-admin-");
        } catch (IOException ex) {
            throw new IllegalStateException(ex);
        }
    }
}
