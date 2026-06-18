package com.kcops.mcp.config;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.context.annotation.Profile;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@Component
@Profile("!mock")
@Order(Ordered.HIGHEST_PRECEDENCE)
public class AdminAuthWebFilter implements WebFilter {

    private static final String ADMIN_PATH_PREFIX = "/admin/";
    private static final String ADMIN_TOKEN_HEADER = "X-Kcops-Admin-Token";
    private static final String BEARER_PREFIX = "Bearer ";

    private final KcopsProperties properties;

    public AdminAuthWebFilter(KcopsProperties properties) {
        this.properties = properties;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getPath().value();
        if (!path.startsWith(ADMIN_PATH_PREFIX)) {
            return chain.filter(exchange);
        }

        String expectedToken = properties.getAdmin().getToken();
        if (expectedToken == null || expectedToken.isBlank()) {
            return writeJson(
                    exchange,
                    HttpStatus.SERVICE_UNAVAILABLE,
                    "{\"error\":\"admin_api_disabled\"}"
            );
        }

        String presentedToken = extractPresentedToken(exchange.getRequest().getHeaders());
        if (presentedToken == null || !constantTimeEquals(expectedToken, presentedToken)) {
            return writeJson(exchange, HttpStatus.UNAUTHORIZED, "{\"error\":\"unauthorized\"}");
        }

        return chain.filter(exchange);
    }

    private String extractPresentedToken(HttpHeaders headers) {
        String authorization = headers.getFirst(HttpHeaders.AUTHORIZATION);
        if (authorization != null && authorization.startsWith(BEARER_PREFIX)) {
            return authorization.substring(BEARER_PREFIX.length());
        }
        return headers.getFirst(ADMIN_TOKEN_HEADER);
    }

    private boolean constantTimeEquals(String expected, String presented) {
        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8),
                presented.getBytes(StandardCharsets.UTF_8)
        );
    }

    private Mono<Void> writeJson(ServerWebExchange exchange, HttpStatus status, String body) {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponse().setStatusCode(status);
        exchange.getResponse().getHeaders().setContentType(
                new MediaType(MediaType.APPLICATION_JSON, StandardCharsets.UTF_8)
        );
        DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);
        return exchange.getResponse().writeWith(Mono.just(buffer));
    }
}
