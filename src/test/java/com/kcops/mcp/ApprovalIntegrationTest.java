package com.kcops.mcp;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.StreamSupport;
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

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ApprovalIntegrationTest {

    private static final Set<String> APPROVAL_FIELDS = Set.of(
            "traceId",
            "direction",
            "tool",
            "reason",
            "detectors",
            "categories",
            "createdAt",
            "status"
    );
    private static final AtomicInteger upstreamCalls = new AtomicInteger();
    private static final DisposableServer upstream = upstream();
    private static final Path tempDir = createTempDir();

    @Autowired
    WebTestClient webTestClient;

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("kcops.upstream-url", () -> "http://127.0.0.1:" + upstream.port() + "/mcp");
        registry.add("kcops.audit-log-path", () -> tempDir.resolve("audit.jsonl").toString());
        registry.add("kcops.admin.token", () -> "test-admin-token");
        registry.add("kcops.approval.enabled", () -> "true");
    }

    @AfterAll
    static void stopUpstream() {
        upstream.disposeNow();
    }

    @Test
    void queuesApprovalsAndSupportsApproveDenyAndNotFoundWithoutExposingRawContent() throws Exception {
        upstreamCalls.set(0);
        String firstRawSecret = "rm -rf /workspace/private/TOP_SECRET_PII_900101-1234568";
        requireApproval(1, firstRawSecret);

        JsonNode first = pendingApprovals();
        assertThat(first).hasSize(1);
        JsonNode firstApproval = first.get(0);
        assertSafeApproval(firstApproval, firstRawSecret);
        assertThat(firstApproval.path("direction").asText()).isEqualTo("AGENT_TO_MCP_SERVER");
        assertThat(firstApproval.path("tool").asText()).isEqualTo("execute_shell");
        assertThat(firstApproval.path("status").asText()).isEqualTo("PENDING");
        assertThat(firstApproval.path("categories").toString())
                .contains("DESTRUCTIVE")
                .contains("TOOL_CALL");

        String approvedTraceId = firstApproval.path("traceId").asText();
        webTestClient.post().uri("/admin/approvals/{traceId}/approve", approvedTraceId)
                .header("Authorization", "Bearer test-admin-token")
                .exchange()
                .expectStatus().isOk()
                .expectBody(JsonNode.class)
                .value(approval -> {
                    assertSafeApproval(approval, firstRawSecret);
                    assertThat(approval.path("status").asText()).isEqualTo("APPROVED");
                });
        assertThat(pendingApprovals()).isEmpty();

        String secondRawSecret = "rm -rf /workspace/private/DENY_ME_API_KEY_sk-live-secret";
        requireApproval(2, secondRawSecret);
        JsonNode secondApproval = pendingApprovals().get(0);
        assertSafeApproval(secondApproval, secondRawSecret);
        String deniedTraceId = secondApproval.path("traceId").asText();

        webTestClient.post().uri("/admin/approvals/{traceId}/deny", deniedTraceId)
                .header("Authorization", "Bearer test-admin-token")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.status").isEqualTo("DENIED")
                .jsonPath("$.traceId").isEqualTo(deniedTraceId);

        webTestClient.post().uri("/admin/approvals/{traceId}/approve", "missing-trace-id")
                .header("Authorization", "Bearer test-admin-token")
                .exchange()
                .expectStatus().isNotFound();

        assertThat(upstreamCalls).hasValue(0);
        String audit = Files.readString(tempDir.resolve("audit.jsonl"), StandardCharsets.UTF_8);
        assertThat(audit)
                .contains("\"reason\":\"APPROVAL_GRANTED\"")
                .contains("\"decision\":\"ALLOW\"")
                .contains("\"reason\":\"APPROVAL_DENIED\"")
                .contains("\"decision\":\"BLOCK\"");
    }

    private void requireApproval(int id, String command) {
        String request = """
                {"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"execute_shell","arguments":{"command":"%s"}}}
                """.formatted(id, command);

        webTestClient.post().uri("/mcp")
                .bodyValue(request)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.decision").isEqualTo("REQUIRE_APPROVAL")
                .jsonPath("$.reason").isEqualTo("DESTRUCTIVE_OR_CODE_EXECUTION_REQUEST");
    }

    private JsonNode pendingApprovals() {
        return webTestClient.get().uri("/admin/approvals")
                .header("Authorization", "Bearer test-admin-token")
                .exchange()
                .expectStatus().isOk()
                .expectBody(JsonNode.class)
                .returnResult()
                .getResponseBody();
    }

    private void assertSafeApproval(JsonNode approval, String rawSecret) {
        assertThat(StreamSupport.stream(
                ((Iterable<String>) () -> approval.fieldNames()).spliterator(),
                false
        ).collect(java.util.stream.Collectors.toSet())).isEqualTo(APPROVAL_FIELDS);
        assertThat(approval.toString())
                .doesNotContain(rawSecret)
                .doesNotContain("arguments")
                .doesNotContain("rawBody")
                .doesNotContain("responseBody")
                .doesNotContain("900101-1234568")
                .doesNotContain("sk-live-secret");
    }

    private static DisposableServer upstream() {
        return HttpServer.create()
                .host("127.0.0.1")
                .port(0)
                .handle((request, response) -> {
                    upstreamCalls.incrementAndGet();
                    String json = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":\"ok\"}}";
                    return response.header("Content-Type", "application/json;charset=UTF-8")
                            .sendByteArray(Mono.just(json.getBytes(StandardCharsets.UTF_8)))
                            .then();
                })
                .bindNow();
    }

    private static Path createTempDir() {
        try {
            return Files.createTempDirectory("kcops-manual-approval-");
        } catch (IOException ex) {
            throw new IllegalStateException(ex);
        }
    }
}
