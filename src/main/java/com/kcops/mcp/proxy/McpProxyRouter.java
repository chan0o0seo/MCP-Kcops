package com.kcops.mcp.proxy;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.ServerResponse;

import static org.springframework.web.reactive.function.server.RequestPredicates.POST;
import static org.springframework.web.reactive.function.server.RouterFunctions.route;

@Configuration
@Profile("!mock")
public class McpProxyRouter {

    @Bean
    RouterFunction<ServerResponse> mcpRoutes(McpProxyHandler handler) {
        return route(POST("/mcp"), handler::handle);
    }
}
