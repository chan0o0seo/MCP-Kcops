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
import java.util.ArrayList;
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
import reactor.core.scheduler.Schedulers;

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
        int maxResponseScanBytes = Math.max(
                properties.getLimits().getMaxResponseBytes(),
                properties.getLimits().getMaxResponseScanBytes()
        );
        this.webClient = webClientBuilder
                .exchangeStrategies(ExchangeStrategies.builder()
                        .codecs(codecs -> codecs.defaultCodecs()
                                .maxInMemorySize(maxResponseScanBytes))
                        .build())
                .build();
    }

    public Mono<ServerResponse> handle(ServerRequest serverRequest) {
        String traceId = UUID.randomUUID().toString();
        Instant started = Instant.now();
        String approvalId = serverRequest.headers().firstHeader("X-Kcops-Approval-Id");
        return serverRequest.bodyToMono(String.class)
                .publishOn(Schedulers.boundedElastic())
                .flatMap(body -> handleBuffered(traceId, started, body, approvalId))
                .switchIfEmpty(Mono.defer(() -> handleEmptyRequest(traceId, started)))
                .onErrorResume(DataBufferLimitException.class,
                        ex -> handleRequestTooLarge(traceId, started));
    }

    private Mono<ServerResponse> handleBuffered(
            String traceId,
            Instant started,
            String body,
            String approvalId
    ) {
        if (approvalId != null && !approvalId.isBlank()) {
            String token = approvalId.trim();
            return pendingApprovalStore.consumeApproved(
                            token,
                            PendingApprovalStore.sha256Hex(body)
                    )
                    .map(approvedBody -> {
                        McpRequest approvedRequest = parseRequest(approvedBody);
                        PolicyDecision executed = new PolicyDecision(
                                Action.ALLOW,
                                "APPROVAL_EXECUTED",
                                List.of(),
                                List.of()
                        );
                        auditLogger.log(token, AuditDirection.AGENT_TO_MCP_SERVER, properties.getUpstreamUrl(),
                                approvedRequest.tool(), executed,
                                Duration.between(started, Instant.now()).toMillis(), false, false);
                        return forwardUpstream(token, approvedRequest, approvedBody);
                    })
                    .orElseGet(() -> handleNormally(traceId, started, body));
        }
        return handleNormally(traceId, started, body);
    }

    private Mono<ServerResponse> handleNormally(String traceId, Instant started, String body) {
        McpRequest request = parseRequest(body);
        DetectionResult detection = inspectRequest(request);
        List<Finding> findings = detection.findings();
        if (!detection.failedDetectors().isEmpty()) {
            PolicyDecision failureDecision = detectorErrorDecision(detection.failedDetectors());
            auditLogger.log(traceId, AuditDirection.AGENT_TO_MCP_SERVER, properties.getUpstreamUrl(),
                    request.tool(), failureDecision, Duration.between(started, Instant.now()).toMillis(),
                    false, false);
            return decisionResponse(request.id(), failureDecision);
        }
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
                    requestDecision,
                    body
            );
        }
        if (requestDecision.action() == Action.BLOCK || requestDecision.action() == Action.REQUIRE_APPROVAL) {
            return decisionResponse(
                    request.id(),
                    requestDecision,
                    properties.getApproval().isEnabled() ? traceId : null
            );
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
                            approvalDecision,
                            body
                    );
                }
                return decisionResponse(
                        request.id(),
                        approvalDecision,
                        properties.getApproval().isEnabled() ? traceId : null
                );
            }
            upstreamRequestBody = Masker.mask(body, findings);
        }

        return forwardUpstream(traceId, request, upstreamRequestBody);
    }

    private Mono<ServerResponse> forwardUpstream(
            String traceId,
            McpRequest request,
            String upstreamRequestBody
    ) {
        Instant upstreamStarted = Instant.now();
        return webClient.post()
                .uri(properties.getUpstreamUrl())
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(upstreamRequestBody)
                .retrieve()
                .bodyToMono(byte[].class)
                .timeout(Duration.ofMillis(properties.getUpstreamTimeoutMs()))
                .publishOn(Schedulers.boundedElastic())
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
        return errorResponse(
                null,
                decision,
                -32001,
                sizeLimitMessage(decision),
                decision.action() == Action.REQUIRE_APPROVAL && properties.getApproval().isEnabled()
                        ? traceId
                        : null
        );
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
        DetectionResult detection = inspectResponse(response);
        List<Finding> findings = detection.findings();
        if (!detection.failedDetectors().isEmpty()) {
            PolicyDecision failureDecision = detectorErrorDecision(detection.failedDetectors());
            auditLogger.log(traceId, AuditDirection.MCP_SERVER_TO_AGENT, properties.getUpstreamUrl(),
                    request.tool(), failureDecision, Duration.between(upstreamStarted, Instant.now()).toMillis(),
                    false, false);
            JsonNode id = response.id() == null ? request.id() : response.id();
            return decisionResponse(id, failureDecision);
        }
        PolicyDecision responseDecision = policyEngine.decide(Direction.RESPONSE, findings);
        if (responseDecision.action() == Action.MASK) {
            Finding unmaskable = findings.stream()
                    .filter(finding -> finding.spans().isEmpty())
                    .findFirst()
                    .orElse(null);
            if (unmaskable != null) {
                responseDecision = new PolicyDecision(
                        Action.BLOCK,
                        unmaskable.reason(),
                        responseDecision.detectors(),
                        responseDecision.categories()
                );
            }
        }
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

    private DetectionResult inspectRequest(McpRequest request) {
        List<Finding> findings = new ArrayList<>();
        List<String> failedDetectors = new ArrayList<>();
        for (RequestDetector detector : requestDetectors) {
            try {
                findings.addAll(detector.inspect(request));
            } catch (RuntimeException ex) {
                failedDetectors.add(detectorName(detector));
            }
        }
        return new DetectionResult(findings, failedDetectors);
    }

    private DetectionResult inspectResponse(McpResponse response) {
        List<Finding> findings = new ArrayList<>();
        List<String> failedDetectors = new ArrayList<>();
        for (ResponseDetector detector : responseDetectors) {
            try {
                findings.addAll(detector.inspect(response));
            } catch (RuntimeException ex) {
                failedDetectors.add(detectorName(detector));
            }
        }
        return new DetectionResult(findings, failedDetectors);
    }

    private String detectorName(RequestDetector detector) {
        try {
            return detector.name();
        } catch (RuntimeException ex) {
            return detector.getClass().getSimpleName();
        }
    }

    private String detectorName(ResponseDetector detector) {
        try {
            return detector.name();
        } catch (RuntimeException ex) {
            return detector.getClass().getSimpleName();
        }
    }

    private PolicyDecision detectorErrorDecision(List<String> failedDetectors) {
        return new PolicyDecision(Action.BLOCK, "DETECTOR_ERROR", failedDetectors, List.of());
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
        return decisionResponse(id, decision, null);
    }

    private Mono<ServerResponse> decisionResponse(
            JsonNode id,
            PolicyDecision decision,
            String approvalId
    ) {
        return errorResponse(
                id,
                decision,
                -32001,
                decision.action() == Action.REQUIRE_APPROVAL
                        ? "MCP request requires approval by Kcops policy"
                        : "MCP request blocked by Kcops policy",
                approvalId
        );
    }

    private Mono<ServerResponse> errorResponse(
            JsonNode id,
            PolicyDecision decision,
            int code,
            String message
    ) {
        return errorResponse(id, decision, code, message, null);
    }

    private Mono<ServerResponse> errorResponse(
            JsonNode id,
            PolicyDecision decision,
            int code,
            String message,
            String approvalId
    ) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("jsonrpc", "2.0");
        body.put("id", id);
        body.put("decision", decision.action());
        body.put("reason", properties.isDiscloseDetectors() ? decision.reason() : "POLICY_VIOLATION");
        body.put("detectors", properties.isDiscloseDetectors() ? decision.detectors() : List.of());
        if (decision.action() == Action.REQUIRE_APPROVAL && approvalId != null) {
            body.put("approvalId", approvalId);
        }
        body.put("error", Map.of(
                "code", code,
                "message", message
        ));
        return ServerResponse.ok().contentType(APPLICATION_JSON_UTF8).bodyValue(body);
    }

    private record DetectionResult(List<Finding> findings, List<String> failedDetectors) {
        private DetectionResult {
            findings = List.copyOf(findings);
            failedDetectors = List.copyOf(failedDetectors);
        }
    }
}
