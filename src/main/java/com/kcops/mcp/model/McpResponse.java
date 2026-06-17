package com.kcops.mcp.model;

import com.fasterxml.jackson.databind.JsonNode;

public record McpResponse(
        String jsonrpc,
        JsonNode id,
        JsonNode result,
        JsonNode error,
        JsonNode raw,
        String rawBody
) {
    public static McpResponse from(JsonNode raw, String rawBody) {
        return new McpResponse(
                raw.path("jsonrpc").asText(null),
                raw.get("id"),
                raw.get("result"),
                raw.get("error"),
                raw,
                rawBody
        );
    }
}
