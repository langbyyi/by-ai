package ai.burp.model;

import java.util.*;
import ai.burp.util.SimpleJson;

/**
 * 漏洞报告模型。
 * 表示一个安全风险发现。
 */
public class VulnReport
{
    public enum Severity
    {
        CRITICAL("严重", 5),
        HIGH("高", 4),
        MEDIUM("中", 3),
        LOW("低", 2),
        INFO("信息", 1);

        private final String label;
        private final int level;

        Severity(String label, int level)
        {
            this.label = label;
            this.level = level;
        }

        public String label() { return label; }
        public int level() { return level; }

        public static Severity fromString(String s)
        {
            if (s == null) return INFO;
            s = s.trim().toLowerCase();
            if (s.contains("严重") || s.contains("critical")) return CRITICAL;
            if (s.contains("高") || s.contains("high")) return HIGH;
            if (s.contains("中") || s.contains("medium")) return MEDIUM;
            if (s.contains("低") || s.contains("low")) return LOW;
            return INFO;
        }
    }

    public enum VerifyStatus
    {
        PENDING("待验证"),
        CONFIRMED("已确认"),
        FALSE_POSITIVE("误报"),
        UNVERIFIED("无法验证");

        private final String label;
        VerifyStatus(String label) { this.label = label; }
        public String label() { return label; }
    }

    private String url;
    private String method;
    private String vulnType;
    private Severity severity;
    private String parameter;
    private String description;
    private String suggestion;
    private String evidence;
    private double confidence;
    private VerifyStatus verifyStatus;
    private String verificationDetail;
    private String originalRequest;
    private String reproduceRequest;   // 可复现的完整HTTP请求（注入payload后的测试请求）
    private String originalResponse;   // 原始响应（触发分析时的响应）
    private String testPayload;
    private String testResponse;
    private String host;
    private String category;
    private java.util.List<String> tags;
    private String responseCode;
    private String timestamp;
    private boolean secure;   // 由 proxy 捕获时确定，来自 httpService().secure()
    private long ttfbMs = -1;   // TTFB 首字节时间（毫秒），-1 表示无数据
    private long ttlbMs = -1;  // TTLB 末字节时间（毫秒），-1 表示无数据

    public VulnReport()
    {
        this.severity = Severity.INFO;
        this.verifyStatus = VerifyStatus.PENDING;
        this.confidence = 0.0;
        this.tags = new java.util.ArrayList<>();
        this.timestamp = java.time.LocalDateTime.now()
            .format(java.time.format.DateTimeFormatter.ofPattern("HH:mm:ss"));
    }

    // 工厂方法
    public static VulnReport confirmed(String vulnType, String detail,
        String originalReq, String reproduceReq, String payload, String testResp)
    {
        VulnReport r = new VulnReport();
        r.vulnType = vulnType;
        r.verifyStatus = VerifyStatus.CONFIRMED;
        r.verificationDetail = detail;
        r.originalRequest = originalReq;
        r.reproduceRequest = reproduceReq;
        r.testPayload = payload;
        r.testResponse = testResp;
        return r;
    }

    public static VulnReport notConfirmed(String vulnType)
    {
        VulnReport r = new VulnReport();
        r.vulnType = vulnType;
        r.verifyStatus = VerifyStatus.FALSE_POSITIVE;
        return r;
    }

    // Getters and Setters
    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; }

    public String getMethod() { return method; }
    public void setMethod(String method) { this.method = method; }

    public String getVulnType() { return vulnType; }
    public void setVulnType(String vulnType) { this.vulnType = vulnType; }

    public Severity getSeverity() { return severity != null ? severity : Severity.INFO; }
    public void setSeverity(Severity severity) { this.severity = severity; }

    public String getParameter() { return parameter; }
    public void setParameter(String parameter) { this.parameter = parameter; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public String getSuggestion() { return suggestion; }
    public void setSuggestion(String suggestion) { this.suggestion = suggestion; }

    public String getEvidence() { return evidence; }
    public void setEvidence(String evidence) { this.evidence = evidence; }

    public double getConfidence() { return confidence; }
    public void setConfidence(double confidence) { this.confidence = confidence; }

    public VerifyStatus getVerifyStatus() { return verifyStatus; }
    public void setVerifyStatus(VerifyStatus verifyStatus) { this.verifyStatus = verifyStatus; }

    public String getVerificationDetail() { return verificationDetail; }
    public void setVerificationDetail(String verificationDetail) { this.verificationDetail = verificationDetail; }

    public String getOriginalRequest() { return originalRequest; }
    public void setOriginalRequest(String originalRequest) { this.originalRequest = originalRequest; }

    public String getReproduceRequest() { return reproduceRequest; }
    public void setReproduceRequest(String reproduceRequest) { this.reproduceRequest = reproduceRequest; }

    public String getOriginalResponse() { return originalResponse; }
    public void setOriginalResponse(String originalResponse) { this.originalResponse = originalResponse; }

    public String getTestPayload() { return testPayload; }
    public void setTestPayload(String testPayload) { this.testPayload = testPayload; }

    public String getTestResponse() { return testResponse; }
    public void setTestResponse(String testResponse) { this.testResponse = testResponse; }

    public String getHost() { return host; }
    public void setHost(String host) { this.host = host; }

    public boolean isSecure() { return secure; }
    public void setSecure(boolean secure) { this.secure = secure; }

    public String getCategory() { return category; }
    public void setCategory(String category) { this.category = category; }

    public java.util.List<String> getTags() { return tags; }
    public void addTag(String tag) { if (tag != null && !tag.isEmpty()) tags.add(tag); }

    public String getResponseCode() { return responseCode; }
    public void setResponseCode(String code) { this.responseCode = code; }

    public String getTimestamp() { return timestamp; }
    public void setTimestamp(String timestamp) { this.timestamp = timestamp; }

    public long getTtfbMs() { return ttfbMs; }
    public void setTtfbMs(long ttfbMs) { this.ttfbMs = ttfbMs; }

    public long getTtlbMs() { return ttlbMs; }
    public void setTtlbMs(long ttlbMs) { this.ttlbMs = ttlbMs; }

    public boolean hasTimingData() { return ttfbMs >= 0 || ttlbMs >= 0; }

    /** 格式化时序摘要文本 */
    public String timingSummary()
    {
        if (!hasTimingData()) return "";
        StringBuilder sb = new StringBuilder(" | 响应时间: ");
        if (ttfbMs >= 0) sb.append("TTFB=").append(ttfbMs).append("ms");
        if (ttlbMs >= 0)
        {
            if (ttfbMs >= 0) sb.append(", ");
            sb.append("TTLB=").append(ttlbMs).append("ms");
        }
        return sb.toString();
    }

    /**
     * 生成结构化摘要文本，用于注入聊天会话上下文。
     */
    public String toChatContext()
    {
        StringBuilder sb = new StringBuilder();
        sb.append("- [").append(severity.label()).append("] ").append(vulnType);
        if (url != null && !url.isEmpty()) sb.append(" | URL: ").append(url);
        if (method != null && !method.isEmpty()) sb.append(" | 方法: ").append(method);
        if (parameter != null && !parameter.isEmpty()) sb.append(" | 参数: ").append(parameter);
        sb.append(" | 置信度: ").append(String.format("%.0f%%", confidence * 100));
        sb.append(" | 状态: ").append(verifyStatus.label());
        sb.append(timingSummary());
        if (description != null && !description.isEmpty()) sb.append("\n  描述: ").append(description);
        if (evidence != null && !evidence.isEmpty()) sb.append("\n  证据: ").append(evidence);
        if (suggestion != null && !suggestion.isEmpty()) sb.append("\n  建议: ").append(suggestion);
        if (verificationDetail != null && !verificationDetail.isEmpty())
            sb.append("\n  验证详情: ").append(verificationDetail);
        return sb.toString();
    }

    @Override
    public String toString()
    {
        return "[" + severity.label() + "] " + vulnType + " - " + url
            + " (" + parameter + ") " + verifyStatus.label();
    }

    // ==================== JSON Serialization ====================

    public String toJson()
    {
        Map<String, Object> m = new LinkedHashMap<>();
        put(m, "url", url);
        put(m, "method", method);
        put(m, "vulnType", vulnType);
        if (severity != null) m.put("severity", severity.name());
        put(m, "parameter", parameter);
        put(m, "description", description);
        put(m, "suggestion", suggestion);
        put(m, "evidence", evidence);
        m.put("confidence", confidence);
        if (verifyStatus != null) m.put("verifyStatus", verifyStatus.name());
        put(m, "verificationDetail", verificationDetail);
        put(m, "originalRequest", originalRequest);
        put(m, "reproduceRequest", reproduceRequest);
        put(m, "originalResponse", originalResponse);
        put(m, "testPayload", testPayload);
        put(m, "testResponse", testResponse);
        put(m, "host", host);
        put(m, "category", category);
        if (tags != null && !tags.isEmpty()) m.put("tags", tags);
        put(m, "responseCode", responseCode);
        put(m, "timestamp", timestamp);
        m.put("secure", secure);
        m.put("ttfbMs", ttfbMs);
        m.put("ttlbMs", ttlbMs);
        return SimpleJson.toJson(m);
    }

    private static void put(Map<String, Object> m, String key, String val)
    {
        if (val != null) m.put(key, val);
    }

    public static VulnReport fromJson(String json)
    {
        Map<String, Object> m = SimpleJson.parseObject(json);
        if (m == null || m.isEmpty()) return null;
        VulnReport r = new VulnReport();
        r.url = str(m, "url");
        r.method = str(m, "method");
        r.vulnType = str(m, "vulnType");
        String sev = str(m, "severity");
        if (sev != null) { try { r.severity = Severity.valueOf(sev); } catch (Exception ignored) {} }
        r.parameter = str(m, "parameter");
        r.description = str(m, "description");
        r.suggestion = str(m, "suggestion");
        r.evidence = str(m, "evidence");
        Double conf = SimpleJson.getDouble(m, "confidence");
        if (conf != null) r.confidence = conf;
        String vs = str(m, "verifyStatus");
        if (vs != null) { try { r.verifyStatus = VerifyStatus.valueOf(vs); } catch (Exception ignored) {} }
        r.verificationDetail = str(m, "verificationDetail");
        r.originalRequest = str(m, "originalRequest");
        r.reproduceRequest = str(m, "reproduceRequest");
        r.originalResponse = str(m, "originalResponse");
        r.testPayload = str(m, "testPayload");
        r.testResponse = str(m, "testResponse");
        r.host = str(m, "host");
        r.category = str(m, "category");
        List<Object> tagList = SimpleJson.getList(m, "tags");
        if (tagList != null) { r.tags = new ArrayList<>(); for (Object t : tagList) r.tags.add(String.valueOf(t)); }
        r.responseCode = str(m, "responseCode");
        r.timestamp = str(m, "timestamp");
        r.secure = Boolean.TRUE.equals(m.get("secure"));
        Number ttfb = (Number) m.get("ttfbMs");
        if (ttfb != null) r.ttfbMs = ttfb.longValue();
        Number ttlb = (Number) m.get("ttlbMs");
        if (ttlb != null) r.ttlbMs = ttlb.longValue();
        return r;
    }

    private static String str(Map<String, Object> m, String key)
    {
        Object val = m.get(key);
        return val instanceof String ? (String) val : null;
    }
}
