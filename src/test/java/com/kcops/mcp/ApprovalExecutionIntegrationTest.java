package com.kcops.mcp;

import com.fasterxml.jackson.databind.JsonNode;
import com.kcops.mcp.approval.ApprovalStatus;
import com.kcops.mcp.approval.PendingApprovalStore;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
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
class ApprovalExecutionIntegrationTest {

    private static final AtomicInteger upstreamCalls = new AtomicInteger();
    private static final AtomicReference<String> upstreamBody = new AtomicReference<>();
    private static final DisposableServer upstream = upstream();
    private static final Path tempDir = createTempDir();

    @Autowired
    WebTestClient webTestClient;

    @Autowired
    PendingApprovalStore pendingApprovalStore;

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
    void approvedIdenticalRequestExecutesOnceWhileOtherResubmissionsRemainBlocked() throws Exception {
        upstreamCalls.set(0);
        upstreamBody.set(null);
        String secret = "rm -rf /workspace/private/APPROVAL_EXECUTION_SECRET";
        String request = request(41, secret);

        JsonNode initial = post(request, null);
        assertThat(initial.path("decision").asText()).isEqualTo("REQUIRE_APPROVAL");
        assertThat(initial.path("reason").asText())
                .isEqualTo("DESTRUCTIVE_OR_CODE_EXECUTION_REQUEST");
        String approvalId = initial.path("approvalId").asText();
        assertThat(approvalId).isNotBlank();

        JsonNode approvals = pendingApprovals();
        assertThat(approvals).hasSize(1);
        JsonNode adminApproval = approvals.get(0);
        assertThat(adminApproval.path("traceId").asText()).isEqualTo(approvalId);
        assertThat(adminApproval.has("requestBody")).isFalse();
        assertThat(adminApproval.toString()).doesNotContain(secret);
        assertThat(adminApproval.path("bodyHash").asText()).hasSize(64);

        JsonNode unapprovedRetry = post(request, approvalId);
        assertThat(unapprovedRetry.path("decision").asText()).isEqualTo("REQUIRE_APPROVAL");
        assertThat(unapprovedRetry.path("approvalId").asText())
                .isNotBlank()
                .isNotEqualTo(approvalId);
        assertThat(upstreamCalls).hasValue(0);

        webTestClient.post().uri("/admin/approvals/{approvalId}/approve", approvalId)
                .header("Authorization", "Bearer test-admin-token")
                .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                .bodyValue("{\"reason\":\"approved integration execution\"}")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.status").isEqualTo("APPROVED")
                .jsonPath("$.requestBody").doesNotExist();

        JsonNode modifiedRetry = post(request(41, secret + "-changed"), approvalId);
        assertThat(modifiedRetry.path("decision").asText()).isEqualTo("REQUIRE_APPROVAL");
        assertThat(upstreamCalls).hasValue(0);
        assertThat(pendingApprovalStore.find(approvalId))
                .get()
                .extracting(approval -> approval.status())
                .isEqualTo(ApprovalStatus.APPROVED);

        JsonNode executed = post(request, approvalId);
        assertThat(executed.path("result").path("content").asText()).isEqualTo("executed");
        assertThat(upstreamCalls).hasValue(1);
        assertThat(upstreamBody).hasValue(request);
        assertThat(pendingApprovalStore.find(approvalId))
                .get()
                .extracting(approval -> approval.status())
                .isEqualTo(ApprovalStatus.CONSUMED);

        JsonNode reused = post(request, approvalId);
        assertThat(reused.path("decision").asText()).isEqualTo("REQUIRE_APPROVAL");
        assertThat(reused.path("approvalId").asText()).isNotEqualTo(approvalId);
        assertThat(upstreamCalls).hasValue(1);

        String audit = Files.readString(tempDir.resolve("audit.jsonl"), StandardCharsets.UTF_8);
        assertThat(audit)
                .contains("\"direction\":\"AGENT_TO_MCP_SERVER\"")
                .contains("\"decision\":\"ALLOW\"")
                .contains("\"reason\":\"APPROVAL_EXECUTED\"");
    }

    private JsonNode post(String body, String approvalId) {
        WebTestClient.RequestBodySpec request = webTestClient.post().uri("/mcp");
        if (approvalId != null) {
            request.header("X-Kcops-Approval-Id", approvalId);
        }
        return request.bodyValue(body)
                .exchange()
                .expectStatus().isOk()
                .expectBody(JsonNode.class)
                .returnResult()
                .getResponseBody();
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

    private String request(int id, String command) {
        return """
                {"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"execute_shell","arguments":{"command":"%s"}}}
                """.formatted(id, command);
    }

    private static DisposableServer upstream() {
        return HttpServer.create()
                .host("127.0.0.1")
                .port(0)
                .handle((request, response) -> request.receive()
                        .aggregate()
                        .asString(StandardCharsets.UTF_8)
                        .flatMap(body -> {
                            upstreamCalls.incrementAndGet();
                            upstreamBody.set(body);
                            String json = "{\"jsonrpc\":\"2.0\",\"id\":41,\"result\":{\"content\":\"executed\"}}";
                            return response.header("Content-Type", "application/json;charset=UTF-8")
                                    .sendByteArray(Mono.just(json.getBytes(StandardCharsets.UTF_8)))
                                    .then();
                        }))
                .bindNow();
    }

    private static Path createTempDir() {
        try {
            return Files.createTempDirectory("kcops-approval-execution-");
        } catch (IOException ex) {
            throw new IllegalStateException(ex);
        }
    }
}
