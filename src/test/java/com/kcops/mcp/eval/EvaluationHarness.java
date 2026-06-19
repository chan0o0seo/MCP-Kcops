package com.kcops.mcp.eval;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.kcops.mcp.detector.Finding;
import com.kcops.mcp.detector.PolicyCategory;
import com.kcops.mcp.detector.RequestDetector;
import com.kcops.mcp.detector.ResponseDetector;
import com.kcops.mcp.model.McpRequest;
import com.kcops.mcp.model.McpResponse;
import com.kcops.mcp.policy.Action;
import com.kcops.mcp.policy.Direction;
import com.kcops.mcp.policy.PolicyDecision;
import com.kcops.mcp.policy.PolicyEngine;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import reactor.netty.DisposableServer;
import reactor.netty.http.server.HttpServer;

import static org.assertj.core.api.Assertions.assertThat;

@Tag("eval")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class EvaluationHarness {

    private static final List<String> DATASET_FILES = List.of(
            "requests_malicious.jsonl",
            "requests_benign.jsonl",
            "responses_injection_simple.jsonl",
            "responses_injection_obfuscated.jsonl",
            "responses_benign.jsonl",
            "stress_korean_fp.jsonl"
    );
    private static final int WARMUP_RUNS = 30;
    private static final int MEASURE_RUNS = 200;
    private static final Path TEMP_DIR = createTempDir();
    private static final DisposableServer UPSTREAM = HttpServer.create()
            .host("127.0.0.1")
            .port(0)
            .handle((request, response) -> request.receive().aggregate().asString()
                    .then(sendJson(response,
                            "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":\"ok\"}}")))
            .bindNow();

    @Autowired
    ObjectMapper objectMapper;

    @Autowired
    List<RequestDetector> requestDetectors;

    @Autowired
    List<ResponseDetector> responseDetectors;

    @Autowired
    PolicyEngine policyEngine;

    @Autowired
    WebTestClient proxyClient;

    @DynamicPropertySource
    static void evaluationProperties(DynamicPropertyRegistry registry) {
        registry.add("kcops.upstream-url", () -> "http://127.0.0.1:" + UPSTREAM.port() + "/mcp");
        registry.add("kcops.audit-log-path", () -> TEMP_DIR.resolve("audit.jsonl").toString());
        registry.add("kcops.audit-anchor-path", () -> TEMP_DIR.resolve("audit-anchor.jsonl").toString());
        registry.add("kcops.fingerprint-store-path", () -> TEMP_DIR.resolve("fingerprints.json").toString());
        registry.add("kcops.admin.token", () -> "eval-local-only");
    }

    @AfterAll
    static void stopUpstream() {
        UPSTREAM.disposeNow();
    }

    @Test
    void evaluateDatasetsAndWriteReports() throws Exception {
        Path evalDir = Path.of(System.getProperty("user.dir")).resolve("eval");
        List<EvalCase> cases = loadCases(evalDir);
        assertThat(cases).isNotEmpty();

        List<CaseResult> results = cases.stream().map(this::evaluate).toList();
        LatencyResult latency = measureLatency();
        Report report = buildReport(results, latency);

        Files.createDirectories(evalDir);
        Files.writeString(evalDir.resolve("REPORT.md"), renderMarkdown(report), StandardCharsets.UTF_8);
        Files.writeString(evalDir.resolve("report.csv"), renderCsv(report), StandardCharsets.UTF_8);
    }

    private List<EvalCase> loadCases(Path evalDir) throws IOException {
        List<EvalCase> cases = new ArrayList<>();
        for (String fileName : DATASET_FILES) {
            Path path = evalDir.resolve(fileName);
            assertThat(path).as("dataset %s", fileName).isRegularFile();
            int lineNumber = 0;
            for (String line : Files.readAllLines(path, StandardCharsets.UTF_8)) {
                lineNumber++;
                if (line.isBlank()) {
                    continue;
                }
                JsonNode node = objectMapper.readTree(line);
                cases.add(new EvalCase(
                        node.path("id").asText(),
                        Direction.valueOf(node.path("direction").asText()),
                        node.path("attackType").asText(),
                        node.path("expectStopped").asBoolean(),
                        stringList(node.path("piiExpected")),
                        node.path("payload"),
                        fileName,
                        lineNumber
                ));
            }
        }
        return List.copyOf(cases);
    }

    private CaseResult evaluate(EvalCase evalCase) {
        try {
            String rawBody = objectMapper.writeValueAsString(evalCase.payload());
            List<Finding> findings;
            PolicyDecision decision;
            if (evalCase.direction() == Direction.REQUEST) {
                McpRequest request = McpRequest.from(evalCase.payload(), rawBody);
                findings = requestDetectors.stream()
                        .flatMap(detector -> detector.inspect(request).stream())
                        .toList();
                decision = policyEngine.decide(Direction.REQUEST, findings);
            } else {
                McpResponse response = McpResponse.from(evalCase.payload(), rawBody);
                findings = responseDetectors.stream()
                        .flatMap(detector -> detector.inspect(response).stream())
                        .toList();
                decision = policyEngine.decide(Direction.RESPONSE, findings);
                if (decision.action() == Action.MASK
                        && findings.stream().anyMatch(finding -> finding.spans().isEmpty())) {
                    Finding unmaskable = findings.stream()
                            .filter(finding -> finding.spans().isEmpty())
                            .findFirst()
                            .orElseThrow();
                    decision = new PolicyDecision(
                            Action.BLOCK,
                            unmaskable.reason(),
                            decision.detectors(),
                            decision.categories()
                    );
                }
            }
            return new CaseResult(evalCase, decision, findings);
        } catch (Exception ex) {
            throw new IllegalStateException(
                    "Failed to evaluate " + evalCase.fileName() + ":" + evalCase.lineNumber()
                            + " (" + evalCase.id() + ")",
                    ex
            );
        }
    }

    private LatencyResult measureLatency() {
        WebTestClient directClient = WebTestClient.bindToServer()
                .baseUrl("http://127.0.0.1:" + UPSTREAM.port())
                .responseTimeout(java.time.Duration.ofSeconds(5))
                .build();
        String request = """
                {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"calendar_lookup","arguments":{"date":"2026-06-19","team":"platform"}}}
                """.trim();

        for (int i = 0; i < WARMUP_RUNS; i++) {
            exchange(directClient, request);
            exchange(proxyClient, request);
        }

        List<Double> overheadMillis = new ArrayList<>(MEASURE_RUNS);
        for (int i = 0; i < MEASURE_RUNS; i++) {
            long direct = timedExchange(directClient, request);
            long proxy = timedExchange(proxyClient, request);
            overheadMillis.add(Math.max(0.0, (proxy - direct) / 1_000_000.0));
        }
        List<Double> sorted = overheadMillis.stream().sorted().toList();
        double average = overheadMillis.stream().mapToDouble(Double::doubleValue).average().orElse(0.0);
        int p95Index = Math.max(0, (int) Math.ceil(sorted.size() * 0.95) - 1);
        return new LatencyResult(average, sorted.get(p95Index), WARMUP_RUNS, MEASURE_RUNS);
    }

    private long timedExchange(WebTestClient client, String body) {
        long started = System.nanoTime();
        exchange(client, body);
        return System.nanoTime() - started;
    }

    private void exchange(WebTestClient client, String body) {
        client.post()
                .uri("/mcp")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .consumeWith(result -> assertThat(result.getResponseBody()).isNotNull());
    }

    private Report buildReport(List<CaseResult> results, LatencyResult latency) {
        List<Metric> metrics = new ArrayList<>();
        metrics.add(rateMetric(
                "위험 요청 차단율",
                results,
                result -> result.evalCase().direction() == Direction.REQUEST
                        && result.evalCase().expectStopped(),
                CaseResult::stopped,
                "≥ 90%"
        ));
        metrics.add(rateMetric(
                "정상 요청 오탐률",
                results,
                result -> result.evalCase().direction() == Direction.REQUEST
                        && !result.evalCase().expectStopped(),
                CaseResult::reacted,
                "≤ 10%"
        ));
        metrics.add(rateMetric(
                "요청 인자 DLP 탐지율",
                results,
                result -> result.evalCase().direction() == Direction.REQUEST
                        && Set.of("pii", "secret").contains(result.evalCase().attackType()),
                result -> result.hasCategory(PolicyCategory.PII) || result.hasCategory(PolicyCategory.SECRET),
                "≥ 90%"
        ));
        metrics.add(rateMetric(
                "외부 전송 위험 탐지율",
                results,
                result -> result.evalCase().direction() == Direction.REQUEST
                        && result.evalCase().attackType().equals("egress"),
                result -> result.hasCategory(PolicyCategory.EGRESS),
                "≥ 90%"
        ));
        metrics.add(rateMetric(
                "단순·직접 인젝션 응답 차단율",
                results,
                result -> result.evalCase().attackType().equals("injection_simple"),
                CaseResult::stopped,
                "≥ 90%"
        ));
        metrics.add(rateMetric(
                "난독화 인젝션 차단율",
                results,
                result -> result.evalCase().attackType().equals("injection_obfuscated"),
                CaseResult::stopped,
                "목표 없음"
        ));
        metrics.add(rateMetric(
                "정상 응답 오탐률(한국어 스트레스 포함)",
                results,
                result -> result.evalCase().direction() == Direction.RESPONSE
                        && !result.evalCase().expectStopped()
                        && result.evalCase().piiExpected().isEmpty(),
                CaseResult::reacted,
                "≤ 10%"
        ));
        metrics.add(rateMetric(
                "PII 마스킹 성공률",
                results,
                result -> !result.evalCase().piiExpected().isEmpty(),
                CaseResult::allExpectedPiiHaveSpans,
                "≥ 90%"
        ));
        metrics.add(rateMetric(
                "비밀정보 탐지율",
                results,
                result -> result.evalCase().attackType().equals("secret"),
                result -> result.hasCategory(PolicyCategory.SECRET),
                "≥ 90%"
        ));
        metrics.add(numberMetric("평균 추가 지연(ms)", latency.averageMillis(), "≤ 50 ms"));
        metrics.add(numberMetric("p95 추가 지연(ms)", latency.p95Millis(), "측정값"));

        Map<String, Long> counts = results.stream()
                .collect(Collectors.groupingBy(
                        result -> result.evalCase().fileName(),
                        LinkedHashMap::new,
                        Collectors.counting()
                ));
        return new Report(Instant.now(), counts, List.copyOf(metrics), latency);
    }

    private Metric rateMetric(
            String name,
            List<CaseResult> results,
            Predicate<CaseResult> denominatorFilter,
            Predicate<CaseResult> numeratorFilter,
            String target
    ) {
        List<CaseResult> denominator = results.stream().filter(denominatorFilter).toList();
        long numerator = denominator.stream().filter(numeratorFilter).count();
        double value = denominator.isEmpty() ? 0.0 : numerator * 100.0 / denominator.size();
        return new Metric(name, value, "%", numerator, (long) denominator.size(), target, targetStatus(value, target));
    }

    private Metric numberMetric(String name, double value, String target) {
        return new Metric(name, value, "ms", null, null, target, targetStatus(value, target));
    }

    private String targetStatus(double value, String target) {
        if (target.startsWith("≥")) {
            double threshold = Double.parseDouble(target.replaceAll("[^0-9.]", ""));
            return value >= threshold ? "달성" : "미달";
        }
        if (target.startsWith("≤")) {
            double threshold = Double.parseDouble(target.replaceAll("[^0-9.]", ""));
            return value <= threshold ? "달성" : "미달";
        }
        return "참고";
    }

    private String renderMarkdown(Report report) {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("uuuu-MM-dd HH:mm:ss z")
                .withLocale(Locale.KOREAN)
                .withZone(ZoneId.systemDefault());
        StringBuilder markdown = new StringBuilder();
        markdown.append("# MCP-Kcops 평가 리포트\n\n");
        markdown.append("- 측정 시각: ").append(formatter.format(report.measuredAt())).append('\n');
        markdown.append("- 실행 방식: 실제 탐지기 빈 + `PolicyEngine`, 외부 호출 없음\n");
        markdown.append("- 지연 측정: 로컬 Netty 즉답 업스트림, 워밍업 ")
                .append(report.latency().warmups()).append("회 / 측정 ")
                .append(report.latency().runs()).append("회\n\n");
        markdown.append("## 데이터셋\n\n");
        markdown.append("| 파일 | 항목 수 |\n|---|---:|\n");
        report.datasetCounts().forEach((file, count) ->
                markdown.append("| `").append(file).append("` | ").append(count).append(" |\n"));
        markdown.append("| **합계** | **")
                .append(report.datasetCounts().values().stream().mapToLong(Long::longValue).sum())
                .append("** |\n\n");
        markdown.append("## 핵심 지표\n\n");
        markdown.append("| 지표 | 측정값 | 분자/분모 | 기획서 목표 | 결과 |\n");
        markdown.append("|---|---:|---:|---:|---|\n");
        for (Metric metric : report.metrics()) {
            String value = metric.unit().equals("%")
                    ? format(metric.value()) + "%"
                    : format(metric.value()) + " ms";
            String fraction = metric.numerator() == null
                    ? "-"
                    : metric.numerator() + "/" + metric.denominator();
            markdown.append("| ").append(metric.name()).append(" | ")
                    .append(value).append(" | ").append(fraction).append(" | ")
                    .append(metric.target()).append(" | ").append(metric.status()).append(" |\n");
        }
        markdown.append("\n## 해석상 주의\n\n");
        markdown.append("난독화 인젝션 구간은 베이스라인의 일반화 한계를 드러내기 위해 별도 구성했으며 목표치를 두지 않았다. ");
        markdown.append("이 구간의 미탐은 숨기거나 단순 구간과 합산하지 않고 측정값 그대로 보고한다(기획서 6.3·13장).\n");
        return markdown.toString();
    }

    private String renderCsv(Report report) {
        StringBuilder csv = new StringBuilder();
        csv.append("metric,value,unit,numerator,denominator,target,status\n");
        for (Metric metric : report.metrics()) {
            csv.append(csv(metric.name())).append(',')
                    .append(format(metric.value())).append(',')
                    .append(metric.unit()).append(',')
                    .append(metric.numerator() == null ? "" : metric.numerator()).append(',')
                    .append(metric.denominator() == null ? "" : metric.denominator()).append(',')
                    .append(csv(metric.target())).append(',')
                    .append(csv(metric.status())).append('\n');
        }
        return csv.toString();
    }

    private String csv(String value) {
        return "\"" + value.replace("\"", "\"\"") + "\"";
    }

    private String format(double value) {
        return String.format(Locale.ROOT, "%.2f", value);
    }

    private List<String> stringList(JsonNode node) {
        if (!node.isArray()) {
            return List.of();
        }
        List<String> values = new ArrayList<>();
        node.forEach(value -> values.add(value.asText()));
        return List.copyOf(values);
    }

    private static Mono<Void> sendJson(reactor.netty.http.server.HttpServerResponse response, String json) {
        return response.header("Content-Type", "application/json;charset=UTF-8")
                .sendByteArray(Mono.just(json.getBytes(StandardCharsets.UTF_8)))
                .then();
    }

    private static Path createTempDir() {
        try {
            return Files.createTempDirectory("kcops-eval-");
        } catch (IOException ex) {
            throw new IllegalStateException(ex);
        }
    }

    private record EvalCase(
            String id,
            Direction direction,
            String attackType,
            boolean expectStopped,
            List<String> piiExpected,
            JsonNode payload,
            String fileName,
            int lineNumber
    ) {
    }

    private record CaseResult(EvalCase evalCase, PolicyDecision decision, List<Finding> findings) {
        boolean stopped() {
            return decision.action() == Action.BLOCK || decision.action() == Action.REQUIRE_APPROVAL;
        }

        boolean reacted() {
            return decision.action() != Action.ALLOW;
        }

        boolean hasCategory(PolicyCategory category) {
            return findings.stream().anyMatch(finding -> finding.category() == category);
        }

        boolean allExpectedPiiHaveSpans() {
            Set<String> detectorsWithSpans = findings.stream()
                    .filter(finding -> !finding.spans().isEmpty())
                    .map(Finding::detector)
                    .collect(Collectors.toSet());
            return detectorsWithSpans.containsAll(evalCase.piiExpected());
        }
    }

    private record LatencyResult(double averageMillis, double p95Millis, int warmups, int runs) {
    }

    private record Metric(
            String name,
            double value,
            String unit,
            Long numerator,
            Long denominator,
            String target,
            String status
    ) {
    }

    private record Report(
            Instant measuredAt,
            Map<String, Long> datasetCounts,
            List<Metric> metrics,
            LatencyResult latency
    ) {
    }
}
