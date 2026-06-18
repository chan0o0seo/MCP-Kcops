package com.kcops.mcp.config;

import com.kcops.mcp.policy.Action;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "kcops")
public class KcopsProperties {

    private Mode mode = Mode.ENFORCE;
    private String upstreamUrl = "http://localhost:8090/mcp";
    private String auditLogPath = "logs/audit.jsonl";
    private String auditAnchorPath = "logs/audit-anchor.jsonl";
    private String fingerprintStorePath = "logs/fingerprints.json";
    private long upstreamTimeoutMs = 10000;
    private Limits limits = new Limits();
    private Admin admin = new Admin();
    private Approval approval = new Approval();
    private Request request = new Request();
    private Response response = new Response();

    public enum Mode {
        ENFORCE,
        LOG_ONLY
    }

    public Mode getMode() {
        return mode;
    }

    public void setMode(Mode mode) {
        this.mode = mode;
    }

    public String getUpstreamUrl() {
        return upstreamUrl;
    }

    public void setUpstreamUrl(String upstreamUrl) {
        this.upstreamUrl = upstreamUrl;
    }

    public String getAuditLogPath() {
        return auditLogPath;
    }

    public void setAuditLogPath(String auditLogPath) {
        this.auditLogPath = auditLogPath;
    }

    public String getAuditAnchorPath() {
        return auditAnchorPath;
    }

    public void setAuditAnchorPath(String auditAnchorPath) {
        this.auditAnchorPath = auditAnchorPath;
    }

    public String getFingerprintStorePath() {
        return fingerprintStorePath;
    }

    public void setFingerprintStorePath(String fingerprintStorePath) {
        this.fingerprintStorePath = fingerprintStorePath;
    }

    public long getUpstreamTimeoutMs() {
        return upstreamTimeoutMs;
    }

    public void setUpstreamTimeoutMs(long upstreamTimeoutMs) {
        this.upstreamTimeoutMs = upstreamTimeoutMs;
    }

    public Limits getLimits() {
        return limits;
    }

    public void setLimits(Limits limits) {
        this.limits = limits;
    }

    public Admin getAdmin() {
        return admin;
    }

    public void setAdmin(Admin admin) {
        this.admin = admin;
    }

    public Approval getApproval() {
        return approval;
    }

    public void setApproval(Approval approval) {
        this.approval = approval;
    }

    public Request getRequest() {
        return request;
    }

    public void setRequest(Request request) {
        this.request = request;
    }

    public Response getResponse() {
        return response;
    }

    public void setResponse(Response response) {
        this.response = response;
    }

    public static class Limits {
        private int maxRequestBytes = 262144;
        private int maxResponseBytes = 262144;
        private Action overLimitAction = Action.REQUIRE_APPROVAL;

        public int getMaxRequestBytes() {
            return maxRequestBytes;
        }

        public void setMaxRequestBytes(int maxRequestBytes) {
            this.maxRequestBytes = maxRequestBytes;
        }

        public int getMaxResponseBytes() {
            return maxResponseBytes;
        }

        public void setMaxResponseBytes(int maxResponseBytes) {
            this.maxResponseBytes = maxResponseBytes;
        }

        public Action getOverLimitAction() {
            return overLimitAction;
        }

        public void setOverLimitAction(Action overLimitAction) {
            this.overLimitAction = overLimitAction;
        }
    }

    public static class Admin {
        private String token = "";

        public String getToken() {
            return token;
        }

        public void setToken(String token) {
            this.token = token;
        }
    }

    public static class Approval {
        private boolean enabled = true;
        private int maxPending = 1000;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public int getMaxPending() {
            return maxPending;
        }

        public void setMaxPending(int maxPending) {
            this.maxPending = maxPending;
        }
    }

    public static class Request {
        private ToolCall toolCall = new ToolCall();
        private Egress egress = new Egress();
        private Destructive destructive = new Destructive();
        private Scope scope = new Scope();
        private Pii pii = new Pii(Action.REQUIRE_APPROVAL);

        public ToolCall getToolCall() {
            return toolCall;
        }

        public void setToolCall(ToolCall toolCall) {
            this.toolCall = toolCall;
        }

        public Egress getEgress() {
            return egress;
        }

        public void setEgress(Egress egress) {
            this.egress = egress;
        }

        public Destructive getDestructive() {
            return destructive;
        }

        public void setDestructive(Destructive destructive) {
            this.destructive = destructive;
        }

        public Scope getScope() {
            return scope;
        }

        public void setScope(Scope scope) {
            this.scope = scope;
        }

        public Pii getPii() {
            return pii;
        }

        public void setPii(Pii pii) {
            this.pii = pii;
        }
    }

    public static class Response {
        private Injection injection = new Injection();
        private Pii pii = new Pii(Action.MASK);
        private Fingerprint fingerprint = new Fingerprint();

        public Injection getInjection() {
            return injection;
        }

        public void setInjection(Injection injection) {
            this.injection = injection;
        }

        public Pii getPii() {
            return pii;
        }

        public void setPii(Pii pii) {
            this.pii = pii;
        }

        public Fingerprint getFingerprint() {
            return fingerprint;
        }

        public void setFingerprint(Fingerprint fingerprint) {
            this.fingerprint = fingerprint;
        }
    }

    public static class ToolCall {
        private Action action = Action.REQUIRE_APPROVAL;
        private List<String> highRiskTools = new ArrayList<>();

        public Action getAction() {
            return action;
        }

        public void setAction(Action action) {
            this.action = action;
        }

        public List<String> getHighRiskTools() {
            return highRiskTools;
        }

        public void setHighRiskTools(List<String> highRiskTools) {
            this.highRiskTools = highRiskTools;
        }
    }

    public static class Egress {
        private Action action = Action.BLOCK;
        private List<String> allowDomains = new ArrayList<>();
        private List<String> riskyKeywords = new ArrayList<>();

        public Action getAction() {
            return action;
        }

        public void setAction(Action action) {
            this.action = action;
        }

        public List<String> getAllowDomains() {
            return allowDomains;
        }

        public void setAllowDomains(List<String> allowDomains) {
            this.allowDomains = allowDomains;
        }

        public List<String> getRiskyKeywords() {
            return riskyKeywords;
        }

        public void setRiskyKeywords(List<String> riskyKeywords) {
            this.riskyKeywords = riskyKeywords;
        }
    }

    public static class Destructive {
        private Action action = Action.REQUIRE_APPROVAL;
        private List<String> patterns = new ArrayList<>();

        public Action getAction() {
            return action;
        }

        public void setAction(Action action) {
            this.action = action;
        }

        public List<String> getPatterns() {
            return patterns;
        }

        public void setPatterns(List<String> patterns) {
            this.patterns = patterns;
        }
    }

    public static class Scope {
        private Action action = Action.REQUIRE_APPROVAL;
        private List<String> patterns = new ArrayList<>();

        public Action getAction() {
            return action;
        }

        public void setAction(Action action) {
            this.action = action;
        }

        public List<String> getPatterns() {
            return patterns;
        }

        public void setPatterns(List<String> patterns) {
            this.patterns = patterns;
        }
    }

    public static class Pii {
        private Action action;
        private List<String> detectors = new ArrayList<>();

        public Pii() {
            this(Action.REQUIRE_APPROVAL);
        }

        public Pii(Action action) {
            this.action = action;
        }

        public Action getAction() {
            return action;
        }

        public void setAction(Action action) {
            this.action = action;
        }

        public List<String> getDetectors() {
            return detectors;
        }

        public void setDetectors(List<String> detectors) {
            this.detectors = detectors;
        }
    }

    public static class Injection {
        private Action action = Action.BLOCK;
        private List<String> patterns = new ArrayList<>();
        private boolean decodeBase64 = false;
        private Map<String, List<String>> types = new LinkedHashMap<>();

        public Action getAction() {
            return action;
        }

        public void setAction(Action action) {
            this.action = action;
        }

        public List<String> getPatterns() {
            return patterns;
        }

        public void setPatterns(List<String> patterns) {
            this.patterns = patterns;
        }

        public boolean isDecodeBase64() {
            return decodeBase64;
        }

        public void setDecodeBase64(boolean decodeBase64) {
            this.decodeBase64 = decodeBase64;
        }

        public Map<String, List<String>> getTypes() {
            return types;
        }

        public void setTypes(Map<String, List<String>> types) {
            this.types = types;
        }
    }

    public static class Fingerprint {
        private Action action = Action.REQUIRE_APPROVAL;

        public Action getAction() {
            return action;
        }

        public void setAction(Action action) {
            this.action = action;
        }
    }
}
