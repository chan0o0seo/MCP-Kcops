package com.kcops.mcp.detector;

import com.kcops.mcp.model.McpResponse;
import java.util.List;

public interface ResponseDetector extends TrafficDetector {
    List<Finding> inspect(McpResponse resp);
}
