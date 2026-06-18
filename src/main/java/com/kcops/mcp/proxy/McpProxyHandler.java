package com.kcops.mcp.proxy;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.kcops.mcp.approval.PendingApprovalStore;
import com.kcops.mcp.audit.AuditDirection;
import com.kcops.mcp.audit.AuditLogger;
import com.kcops.mcp.config.KcopsProperties;
import com.kcops.mcp.detector.Finding;
import com.kcops.mcp.detector.PolicyCategory;
import com.kcops.mcp.detector.RequestDetector;
import com.kcops.mcp.detector.ResponseDetector;
import com.kcops.mcp.mask.Masker;
import com.kcops.mcp.model.McpRequest;
import com.kcops.mcp.model.McpResponse;
import com.kcops.mcp.policy.Action;
import com.kcops.mcp.policy.Direction;
import com.kcops.mcp.policy.PolicyDecision;
import com.kcops.mcp.policy.PolicyEngine;
import java.time.Duration;
import java.time.Instant;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.core.io.buffer.DataBufferLimitException;
import org.springframework.http.MediaType;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.ExchangeStrategies;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

@Component
@Profile("!mock")
public class McpProxyHandler {

    private final ObjectMapper objectMapper;
    private final KcopsProperties properties;
    private final List<RequestDetector> requestDetectors;
    private final List<ResponseDetector> responseDetectors;
    private final PolicyEngine policyEngine;
    private final AuditLogger auditLogger;
    private final PendingApprovalStore pendingApprovalStore;
    private final WebClient webClient;
    private static final MediaType APPLICATION_JSON_UTF8 = new MediaType("application", "json", StandardCharsets.UTF_8);

    public McpProxyHandler(
            ObjectMapper objectMapper,
            KcopsProperties properties,
            List<RequestDetector> requestDetectors,
            List<ResponseDetector> responseDetectors,
            PolicyEngine policyEngine,
            AuditLogger auditLogger,
            PendingApprovalStore pendingApprovalStore,
            WebClient.Builder webClientBuilder
    ) {
        this.objectMapper = objectMapper;
        this.properties = properties;
        this.requestDetectors = requestDetectors;
        this.responseDetectors = responseDetectors;
        this.policyEngine = policyEngine;
        this.auditLogger = auditLogger;
        this.pendingApprovalStore = pendingApprovalStore;
        this.webClient = webClientBuilder
                .exchangeStrategies(ExchangeStrategies.builder()
                        .codecs(codecs -> codecs.defaultCodecs()
                                .maxInMemorySize(properties.getLimits().getMaxResponseBytes()))
                        .build())
                .build();
    }

    public Mono<ServerResponse> handle(ServerRequest serverRequest) {
        String traceId = UUID.randomUUID().toString();
        Instant started = Instant.now();
        return serverRequest.bodyToMono(String.class)
                .flatMap(body -> handleBuffered(traceId, started, body))
                .switchIfEmpty(Mono.defer(() -> handleEmptyRequest(traceId, started)))
                .onErrorResume(DataBufferLimitException.class,
                        ex -> handleRequestTooLarge(traceId, started));
    }

    private Mono<ServerResponse> handleBuffered(String traceId, Instant started, String body) {
        McpRequest request = parseRequest(body);
        List<Finding> findings = requestDetectors.stream()
                .flatMap(detector -> detector.inspect(request).stream())
                .toList();
        PolicyDecision requestDecision = policyEngine.decide(Direction.REQUEST, findings);
        long requestLatency = Duration.between(started, Instant.now()).toMillis();
        auditLogger.log(traceId, AuditDirection.AGENT_TO_MCP_SERVER, properties.getUpstreamUrl(),
                request.tool(), requestDecision, requestLatency,
                requestDecision.action() == Action.MASK, false);
        if (requestDecision.action() == Action.REQUIRE_APPROVAL && properties.getApproval().isEnabled()) {
            pendingApprovalStore.add(
                    traceId,
                    AuditDirection.AGENT_TO_MCP_SERVER,
                    request.tool(),
                    requestDecision
            );
        }
        if (requestDecision.action() == Action.BLOCK || requestDecision.action() == Action.REQUIRE_APPROVAL) {
            return decisionResponse(request.id(), requestDecision);
        }
        String upstreamRequestBody = body;
        if (requestDecision.action() == Action.MASK) {
            if (!Masker.hasSpans(findings)) {
                PolicyDecision approvalDecision = new PolicyDecision(Action.REQUIRE_APPROVAL, requestDecision.reason(),
                        requestDecision.detectors(), requestDecision.categories());
                if (properties.getApproval().isEnabled()) {
                    pendingApprovalStore.add(
                            traceId,
                            AuditDirection.AGENT_TO_MCP_SERVER,
                            request.tool(),
                            approvalDecision
                    );
                }
                return decisionResponse(request.id(), approvalDecision);
            }
            upstreamRequestBody = Masker.mask(body, findings);
        }

        Instant upstreamStarted = Instant.now();
        return webClient.post()
                .uri(properties.getUpstreamUrl())
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(upstreamRequestBody)
                .retrieve()
                .bodyToMono(byte[].class)
                .timeout(Duration.ofMillis(properties.getUpstreamTimeoutMs()))
                .map(bytes -> new String(bytes, StandardCharsets.UTF_8))
                .flatMap(upstreamBody -> handleUpstreamResponse(traceId, request, upstreamStarted, upstreamBody))
                .onErrorResume(ex -> handleUpstreamError(traceId, request, upstreamStarted, ex));
    }

    private Mono<ServerResponse> handleEmptyRequest(String traceId, Instant started) {
        PolicyDecision decision = new PolicyDecision(Action.BLOCK, "INVALID_REQUEST", List.of(), List.of());
        auditLogger.log(traceId, AuditDirection.AGENT_TO_MCP_SERVER, properties.getUpstreamUrl(),
                null, decision, Duration.between(started, Instant.now()).toMillis(),
                false, false);
        return errorResponse(null, decision, -32600, "Invalid Request");
    }

    private Mono<ServerResponse> handleRequestTooLarge(String traceId, Instant started) {
        PolicyDecision decision = new PolicyDecision(
                properties.getLimits().getOverLimitAction(),
                "REQUEST_TOO_LARGE",
                List.of("request_size_limit"),
                List.of()
        );
        auditLogger.log(traceId, AuditDirection.AGENT_TO_MCP_SERVER, properties.getUpstreamUrl(),
                null, decision, Duration.between(started, Instant.now()).toMillis(),
                false, false);
        if (decision.action() == Action.REQUIRE_APPROVAL && properties.getApproval().isEnabled()) {
            pendingApprovalStore.add(
                    traceId,
                    AuditDirection.AGENT_TO_MCP_SERVER,
                    null,
                    decision
            );
        }
        return errorResponse(null, decision, -32001, sizeLimitMessage(decision));
    }

    private Mono<ServerResponse> handleUpstreamError(
            String traceId,
            McpRequest request,
            Instant upstreamStarted,
            Throwable ex
    ) {
        boolean responseTooLarge = hasCause(ex, DataBufferLimitException.class);
        PolicyDecision decision = new PolicyDecision(
                Action.BLOCK,
                responseTooLarge ? "RESPONSE_TOO_LARGE" : "UPSTREAM_UNAVAILABLE",
                List.of(responseTooLarge ? "response_size_limit" : "upstream_error"),
                List.of()
        );
        auditLogger.log(traceId, AuditDirection.MCP_SERVER_TO_AGENT, properties.getUpstreamUrl(),
                request.tool(), decision, Duration.between(upstreamStarted, Instant.now()).toMillis(),
                false, false);
        return responseTooLarge
                ? errorResponse(request.id(), decision, -32001, "MCP upstream response too large")
                : errorResponse(request.id(), decision, -32002, "MCP upstream unavailable");
    }

    private boolean hasCause(Throwable ex, Class<? extends Throwable> type) {
        Throwable current = ex;
        while (current != null) {
            if (type.isInstance(current)) {
                return true;
            }
            current = current.getCause();
        }
        return false;
    }

    private String sizeLimitMessage(PolicyDecision decision) {
        return decision.action() == Action.REQUIRE_APPROVAL
                ? "MCP request requires approval by Kcops policy"
                : "MCP request blocked by Kcops policy";
    }

    private Mono<ServerResponse> handleUpstreamResponse(
            String traceId,
            McpRequest request,
            Instant upstreamStarted,
            String upstreamBody
    ) {
        McpResponse response = parseResponse(upstreamBody);
        List<Finding> findings = responseDetectors.stream()
                .flatMap(detector -> detector.inspect(response).stream())
                .toList();
        PolicyDecision responseDecision = policyEngine.decide(Direction.RESPONSE, findings);
        long latency = Duration.between(upstreamStarted, Instant.now()).toMillis();
        auditLogger.log(traceId, AuditDirection.MCP_SERVER_TO_AGENT, properties.getUpstreamUrl(),
                request.tool(), responseDecision, latency,
                responseDecision.action() == Action.MASK,
                findings.stream().anyMatch(finding -> finding.category() == PolicyCategory.FINGERPRINT));
        if (responseDecision.action() == Action.REQUIRE_APPROVAL && properties.getApproval().isEnabled()) {
            pendingApprovalStore.add(
                    traceId,
                    AuditDirection.MCP_SERVER_TO_AGENT,
                    request.tool(),
                    responseDecision
            );
        }
        if (responseDecision.action() == Action.BLOCK || responseDecision.action() == Action.REQUIRE_APPROVAL) {
            JsonNode id = response.id() == null ? request.id() : response.id();
            return decisionResponse(id, responseDecision);
        }
        if (responseDecision.action() == Action.MASK) {
            return ServerResponse.ok().contentType(APPLICATION_JSON_UTF8).bodyValue(Masker.mask(upstreamBody, findings));
        }
        return ServerResponse.ok().contentType(APPLICATION_JSON_UTF8).bodyValue(upstreamBody);
    }

    private McpRequest parseRequest(String body) {
        try {
            return McpRequest.from(objectMapper.readTree(body), body);
        } catch (JsonProcessingException ex) {
            return new McpRequest(null, null, null, null, null, objectMapper.createObjectNode(), body);
        }
    }

    private McpResponse parseResponse(String body) {
        try {
            return McpResponse.from(objectMapper.readTree(body), body);
        } catch (JsonProcessingException ex) {
            return new McpResponse(null, null, null, null, objectMapper.createObjectNode(), body);
        }
    }

    private Mono<ServerResponse> decisionResponse(JsonNode id, PolicyDecision decision) {
        return errorResponse(
                id,
                decision,
                -32001,
                decision.action() == Action.REQUIRE_APPROVAL
                        ? "MCP request requires approval by Kcops policy"
                        : "MCP request blocked by Kcops policy"
        );
    }

    private Mono<ServerResponse> errorResponse(
            JsonNode id,
            PolicyDecision decision,
            int code,
            String message
    ) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("jsonrpc", "2.0");
        body.put("id", id);
        body.put("decision", decision.action());
        body.put("reason", decision.reason());
        body.put("detectors", decision.detectors());
        body.put("error", Map.of(
                "code", code,
                "message", message
        ));
        return ServerResponse.ok().contentType(APPLICATION_JSON_UTF8).bodyValue(body);
    }
}
