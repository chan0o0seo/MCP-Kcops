package com.kcops.mcp.detector;

import com.kcops.mcp.model.McpRequest;
import java.util.List;

public interface RequestDetector extends TrafficDetector {
    List<Finding> inspect(McpRequest req);
}
