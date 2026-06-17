package com.kcops.mcp.config;

import com.kcops.mcp.policy.Action;
import java.util.ArrayList;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "kcops")
public class KcopsProperties {

    private Mode mode = Mode.ENFORCE;
    private String upstreamUrl = "http://localhost:8090/mcp";
    private String auditLogPath = "logs/audit.jsonl";
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

    public static class Request {
        private ToolCall toolCall = new ToolCall();
        private Egress egress = new Egress();
        private Destructive destructive = new Destructive();
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
}
