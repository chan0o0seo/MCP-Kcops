package com.kcops.mcp;

import com.kcops.mcp.detector.RequestDetector;
import com.kcops.mcp.detector.ResponseDetector;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import reactor.netty.DisposableServer;
import reactor.netty.http.server.HttpServer;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import(BlockingIoOffloadIntegrationTest.ProbeConfiguration.class)
class BlockingIoOffloadIntegrationTest {

    private static final AtomicReference<String> requestThread = new AtomicReference<>();
    private static final AtomicReference<String> responseThread = new AtomicReference<>();
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
        registry.add("kcops.upstream-url", () -> "http://127.0.0.1:" + upstream.port() + "/mcp");
        registry.add("kcops.audit-log-path", () -> tempDir.resolve("audit.jsonl").toString());
        registry.add("kcops.fingerprint-store-path", () -> tempDir.resolve("fingerprints.json").toString());
    }

    @BeforeEach
    void resetThreads() {
        requestThread.set(null);
        responseThread.set(null);
    }

    @AfterAll
    static void stopUpstream() {
        upstream.disposeNow();
    }

    @Test
    void runsRequestAndResponseDetectionOnBoundedElastic() {
        String request = """
                {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"calendar_lookup","arguments":{}}}
                """;

        webTestClient.post().uri("/mcp")
                .bodyValue(request)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.result.content").isEqualTo("ok");

        assertThat(requestThread.get())
                .startsWith("boundedElastic")
                .doesNotStartWith("reactor-http-nio");
        assertThat(responseThread.get())
                .startsWith("boundedElastic")
                .doesNotStartWith("reactor-http-nio");
    }

    private static Path createTempDir() {
        try {
            return Files.createTempDirectory("kcops-offload-");
        } catch (IOException ex) {
            throw new IllegalStateException(ex);
        }
    }

    @TestConfiguration
    static class ProbeConfiguration {

        @Bean
        RequestDetector threadProbeRequestDetector() {
            return new RequestDetector() {
                @Override
                public String name() {
                    return "thread_probe_request";
                }

                @Override
                public List<com.kcops.mcp.detector.Finding> inspect(com.kcops.mcp.model.McpRequest req) {
                    requestThread.set(Thread.currentThread().getName());
                    return List.of();
                }
            };
        }

        @Bean
        ResponseDetector threadProbeResponseDetector() {
            return new ResponseDetector() {
                @Override
                public String name() {
                    return "thread_probe_response";
                }

                @Override
                public List<com.kcops.mcp.detector.Finding> inspect(com.kcops.mcp.model.McpResponse resp) {
                    responseThread.set(Thread.currentThread().getName());
                    return List.of();
                }
            };
        }
    }
}
