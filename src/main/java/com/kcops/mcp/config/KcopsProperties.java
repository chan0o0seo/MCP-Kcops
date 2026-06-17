package com.kcops.mcp.config;

import java.util.ArrayList;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "kcops")
public class KcopsProperties {

    private String upstreamUrl = "http://localhost:8090/mcp";
    private List<String> highRiskTools = new ArrayList<>();
    private List<String> allowDomains = new ArrayList<>();
    private List<String> egressVerbs = new ArrayList<>();
    private List<String> injectionPatterns = new ArrayList<>();
    private String auditLogPath = "logs/audit.jsonl";

    public String getUpstreamUrl() {
        return upstreamUrl;
    }

    public void setUpstreamUrl(String upstreamUrl) {
        this.upstreamUrl = upstreamUrl;
    }

    public List<String> getHighRiskTools() {
        return highRiskTools;
    }

    public void setHighRiskTools(List<String> highRiskTools) {
        this.highRiskTools = highRiskTools;
    }

    public List<String> getAllowDomains() {
        return allowDomains;
    }

    public void setAllowDomains(List<String> allowDomains) {
        this.allowDomains = allowDomains;
    }

    public List<String> getEgressVerbs() {
        return egressVerbs;
    }

    public void setEgressVerbs(List<String> egressVerbs) {
        this.egressVerbs = egressVerbs;
    }

    public List<String> getInjectionPatterns() {
        return injectionPatterns;
    }

    public void setInjectionPatterns(List<String> injectionPatterns) {
        this.injectionPatterns = injectionPatterns;
    }

    public String getAuditLogPath() {
        return auditLogPath;
    }

    public void setAuditLogPath(String auditLogPath) {
        this.auditLogPath = auditLogPath;
    }
}
