package com.kcops.mcp.model;

import com.fasterxml.jackson.databind.JsonNode;

public record McpRequest(
        String jsonrpc,
        JsonNode id,
        String method,
        String tool,
        JsonNode arguments,
        JsonNode raw,
        String rawBody
) {
    public static McpRequest from(JsonNode raw, String rawBody) {
        JsonNode params = raw.path("params");
        String name = params.path("name").isMissingNode() ? null : params.path("name").asText(null);
        JsonNode arguments = params.path("arguments").isMissingNode() ? null : params.path("arguments");
        return new McpRequest(
                raw.path("jsonrpc").asText(null),
                raw.get("id"),
                raw.path("method").asText(null),
                name,
                arguments,
                raw,
                rawBody
        );
    }
}
