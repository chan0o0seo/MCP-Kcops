package com.kcops.mcp.config;

import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThat;

class AdminAuthWebFilterTest {

    @Test
    void failsClosedWhenAdminTokenIsBlank() {
        KcopsProperties properties = new KcopsProperties();
        properties.getAdmin().setToken("");
        AdminAuthWebFilter filter = new AdminAuthWebFilter(properties);
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/admin/approvals").build()
        );
        AtomicBoolean chainCalled = new AtomicBoolean();

        StepVerifier.create(filter.filter(exchange, ignored -> {
                    chainCalled.set(true);
                    return Mono.empty();
                }))
                .verifyComplete();

        assertThat(chainCalled).isFalse();
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
        assertThat(exchange.getResponse().getHeaders().getContentType())
                .hasToString("application/json;charset=UTF-8");
        assertThat(exchange.getResponse().getBodyAsString().block())
                .isEqualTo("{\"error\":\"admin_api_disabled\"}");
    }
}
