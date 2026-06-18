package com.kcops.mcp;

import com.kcops.mcp.detector.Finding;
import com.kcops.mcp.detector.RequestDetector;
import com.kcops.mcp.detector.ResponseDetector;
import com.kcops.mcp.model.McpRequest;
import com.kcops.mcp.model.McpResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
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
@Import(DetectorFailClosedIntegrationTest.ProbeConfiguration.class)
class DetectorFailClosedIntegrationTest {

    private static final AtomicInteger upstreamCalls = new AtomicInteger();
    private static final Path tempDir = createTempDir();
    private static final DisposableServer upstream = HttpServer.create()
            .host("127.0.0.1")
            .port(0)
            .handle((request, response) -> request.receive().aggregate().asString()
                    .flatMap(body -> {
                        upstreamCalls.incrementAndGet();
                        String content = body.contains("response_detector_error")
                                ? "response_detector_error"
                                : "ok";
                        String json = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":\""
                                + content + "\"}}";
                        return response.header("Content-Type", "application/json;charset=UTF-8")
                                .sendByteArray(Mono.just(json.getBytes(StandardCharsets.UTF_8)))
                                .then();
                    }))
            .bindNow();

    @Autowired
    WebTestClient webTestClient;

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("kcops.upstream-url", () -> "http://127.0.0.1:" + upstream.port() + "/mcp");
        registry.add("kcops.audit-log-path", () -> tempDir.resolve("audit.jsonl").toString());
        registry.add("kcops.fingerprint-store-path", () -> tempDir.resolve("fingerprints.json").toString());
    }

    @BeforeEach
    void resetUpstreamCalls() {
        upstreamCalls.set(0);
    }

    @AfterAll
    static void stopUpstream() {
        upstream.disposeNow();
    }

    @Test
    void requestDetectorExceptionBlocksWithoutCallingUpstreamAndAudits() throws Exception {
        String request = request("request_detector_error");

        webTestClient.post().uri("/mcp")
                .bodyValue(request)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.decision").isEqualTo("BLOCK")
                .jsonPath("$.reason").isEqualTo("DETECTOR_ERROR")
                .jsonPath("$.detectors[0]").isEqualTo("throwing_request_probe");

        assertThat(upstreamCalls).hasValue(0);
        assertThat(auditLog())
                .contains("\"direction\":\"AGENT_TO_MCP_SERVER\"")
                .contains("\"reason\":\"DETECTOR_ERROR\"")
                .contains("throwing_request_probe");
    }

    @Test
    void responseDetectorExceptionBlocksBodyAndAudits() throws Exception {
        String request = request("response_detector_error");

        webTestClient.post().uri("/mcp")
                .bodyValue(request)
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class)
                .value(body -> assertThat(body)
                        .contains("\"decision\":\"BLOCK\"")
                        .contains("\"reason\":\"DETECTOR_ERROR\"")
                        .contains("throwing_response_probe")
                        .doesNotContain("\"content\":\"response_detector_error\""));

        assertThat(upstreamCalls).hasValue(1);
        assertThat(auditLog())
                .contains("\"direction\":\"MCP_SERVER_TO_AGENT\"")
                .contains("\"reason\":\"DETECTOR_ERROR\"")
                .contains("throwing_response_probe");
    }

    private static String request(String trigger) {
        return """
                {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"calendar_lookup","arguments":{"trigger":"%s"}}}
                """.formatted(trigger);
    }

    private String auditLog() throws IOException {
        return Files.readString(tempDir.resolve("audit.jsonl"), StandardCharsets.UTF_8);
    }

    private static Path createTempDir() {
        try {
            return Files.createTempDirectory("kcops-detector-fail-closed-");
        } catch (IOException ex) {
            throw new IllegalStateException(ex);
        }
    }

    @TestConfiguration
    static class ProbeConfiguration {

        @Bean
        RequestDetector throwingRequestProbe() {
            return new RequestDetector() {
                @Override
                public String name() {
                    return "throwing_request_probe";
                }

                @Override
                public List<Finding> inspect(McpRequest req) {
                    if (req.rawBody() != null && req.rawBody().contains("request_detector_error")) {
                        throw new IllegalStateException("request detector probe failure");
                    }
                    return List.of();
                }
            };
        }

        @Bean
        ResponseDetector throwingResponseProbe() {
            return new ResponseDetector() {
                @Override
                public String name() {
                    return "throwing_response_probe";
                }

                @Override
                public List<Finding> inspect(McpResponse resp) {
                    if (resp.rawBody() != null && resp.rawBody().contains("response_detector_error")) {
                        throw new IllegalStateException("response detector probe failure");
                    }
                    return List.of();
                }
            };
        }
    }
}
