package ai.burp.scanner;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import ai.burp.model.VulnReport;
import ai.burp.util.SimpleJson;

/**
 * 全操作审计日志 - 完整记录所有AI交互、漏洞检测行为、Payload发送、测试流程。
 */
public class AuditLogger
{
    private final MontoyaApi api;
    private final List<LogEntry> entries = new CopyOnWriteArrayList<>();
    private final List<VulnReport> vulnReports = new CopyOnWriteArrayList<>();
    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("HH:mm:ss");
    private final Path vulnFile;

    /** HTTP 请求回调，用于通知 AIRequestPanel */
    public interface HttpRequestCallback
    {
        void onRequestSent(String requestText, String responseText, String host, String method, int statusCode, long durationMs);
    }

    /** 漏洞报告清空回调，用于通知扫描器重置缓存 */
    public interface ReportsClearedCallback
    {
        void onReportsCleared();
    }

    private volatile HttpRequestCallback httpRequestCallback;
    private volatile ReportsClearedCallback reportsClearedCallback;

    public AuditLogger(MontoyaApi api)
    {
        this.api = api;
        this.vulnFile = Paths.get(System.getProperty("user.home"), ".byai", "vuln_reports.json");
    }

    /**
     * 从持久化文件加载漏洞报告。应在扩展初始化时调用。
     */
    public void loadVulnReports()
    {
        if (!Files.exists(vulnFile)) return;
        try
        {
            String json = new String(Files.readAllBytes(vulnFile), StandardCharsets.UTF_8);
            Object parsed = SimpleJson.parse(json);
            if (!(parsed instanceof List)) return;
            @SuppressWarnings("unchecked")
            List<Object> list = (List<Object>) parsed;
            for (Object item : list)
            {
                if (item instanceof Map)
                {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> m = (Map<String, Object>) item;
                    VulnReport r = VulnReport.fromJson(SimpleJson.toJson(m));
                    if (r != null) vulnReports.add(r);
                }
            }
            if (!vulnReports.isEmpty())
            {
                api.logging().logToOutput("[AuditLogger] Loaded " + vulnReports.size() + " persisted vuln reports");
            }
        }
        catch (Exception e)
        {
            api.logging().logToError("[AuditLogger] Failed to load vuln reports: " + e.getMessage());
        }
    }

    /**
     * 保存漏洞报告到持久化文件。
     */
    public void saveVulnReports()
    {
        try
        {
            List<String> jsonItems = new ArrayList<>();
            for (VulnReport r : vulnReports)
            {
                jsonItems.add(r.toJson());
            }
            StringBuilder sb = new StringBuilder("[\n");
            for (int i = 0; i < jsonItems.size(); i++)
            {
                sb.append(jsonItems.get(i));
                if (i < jsonItems.size() - 1) sb.append(",");
                sb.append("\n");
            }
            sb.append("]");
            Files.createDirectories(vulnFile.getParent());
            Files.write(vulnFile, sb.toString().getBytes(StandardCharsets.UTF_8));
        }
        catch (Exception e)
        {
            api.logging().logToError("[AuditLogger] Failed to save vuln reports: " + e.getMessage());
        }
    }

    public void setHttpRequestCallback(HttpRequestCallback callback)
    {
        this.httpRequestCallback = callback;
    }

    /**
     * 记录一条审计日志。
     */
    public void log(String category, String target, String message)
    {
        LogEntry entry = new LogEntry(category, target, message);
        entries.add(entry);

        // 同步输出到Burp日志
        String line = "[" + entry.timestamp + "] [" + category + "] " + target + " → " + message;
        api.logging().logToOutput(line);
    }

    /**
     * 记录AI交互。
     */
    public void logAIInteraction(String action, String prompt, String response)
    {
        String msg = action + " | Prompt: " + truncate(prompt, 200)
            + " | Response: " + truncate(response, 200);
        log("AI", "", msg);
    }

    /**
     * 记录Payload发送。
     */
    public void logPayloadSent(String url, String method, String payload)
    {
        log("Payload", url, method + " | " + truncate(payload, 300));
    }

    /**
     * 记录完整的 HTTP 请求/响应交换，并通知 AIRequestPanel。
     */
    public void logHttpExchange(String requestText, String responseText,
        String host, String method, int statusCode, long durationMs)
    {
        log("Payload", host, method + " → " + statusCode + " (" + durationMs + "ms)");
        if (httpRequestCallback != null)
        {
            try
            {
                httpRequestCallback.onRequestSent(requestText, responseText, host, method, statusCode, durationMs);
            }
            catch (Exception ignored) {}
        }
    }

    /**
     * 记录漏洞检测结果。
     */
    public void logVulnResult(String vulnName, String url, String severity, boolean confirmed)
    {
        String status = confirmed ? "confirmed" : "unverified";
        log("Vuln", url, vulnName + " (" + severity + ") -> " + status);
    }

    /**
     * 记录结构化的漏洞报告对象。
     * 跨模块去重：相同漏洞类型 + 相同路径 + 相同参数的报告只保留最高严重性的。
     */
    public void logVulnReport(VulnReport report)
    {
        // 统一规范化 URL：仅去掉默认端口(:80/:443)，保留完整参数值
        report.setUrl(stripDefaultPort(report.getUrl()));

        String dedupKey = buildVulnDedupKey(report);
        synchronized (vulnReports)
        {
            for (int i = 0; i < vulnReports.size(); i++)
            {
                VulnReport existing = vulnReports.get(i);
                if (dedupKey.equals(buildVulnDedupKey(existing)))
                {
                    if (report.getSeverity().level() > existing.getSeverity().level())
                    {
                        vulnReports.set(i, report);
                        log("Vuln", report.getUrl() != null ? report.getUrl() : "",
                            "更新报告: " + report.getVulnType() + " (" + report.getSeverity().label() + ")");
                    }
                    else
                    {
                        api.logging().logToOutput("[AuditLogger] 跳过重复报告: " + report.getVulnType()
                            + " " + (report.getUrl() != null ? report.getUrl() : ""));
                    }
                    saveVulnReports();
                    return;
                }
            }
            // 未命中去重，添加新报告（在 synchronized 内防止并发重复）
            vulnReports.add(report);
        }
        saveVulnReports();
        String status = report.getVerifyStatus().label();
        String msg = report.getVulnType() + " (" + report.getSeverity().label()
            + ") -> " + status;
        if (report.getParameter() != null && !report.getParameter().isEmpty())
        {
            msg += " | 参数: " + report.getParameter();
        }
        log("Vuln", report.getUrl() != null ? report.getUrl() : "", msg);
    }

    /**
     * 将 VulnReport 桥接到 Burp 原生 Dashboard Issue Activity 面板。
     * 仅用于流量分析（TrafficAnalyzer/RealtimeTrafficHandler）的结果，
     * 被动/主动扫描器已通过 AuditResult 自行报告。
     */
    public void bridgeToSiteMap(VulnReport report)
    {
        if (report.getVerifyStatus() == VulnReport.VerifyStatus.FALSE_POSITIVE) return;
        if (report.getSeverity().level() <= VulnReport.Severity.INFO.level()) return;
        if (report.getConfidence() < 0.3) return;

        try
        {
            String name = "AI流量分析: " + report.getVulnType();
            String baseUrl = report.getUrl() != null ? report.getUrl() : "";
            AuditIssueSeverity severity = mapToAuditSeverity(report.getSeverity());
            AuditIssueConfidence confidence = mapToAuditConfidence(
                report.getVerifyStatus(), report.getConfidence());
            String detail = buildDashboardDetail(report);
            String remediation = report.getSuggestion() != null ? report.getSuggestion()
                : "对用户输入进行严格验证和过滤，遵循安全编码最佳实践。";
            String background = report.getVulnType() + " — 由 AI 流量分析检测";

            AuditIssue issue = AuditIssue.auditIssue(
                name, detail, remediation, baseUrl,
                severity, confidence,
                background, remediation, severity);
            api.siteMap().add(issue);
        }
        catch (Exception e)
        {
            api.logging().logToError("[AuditLogger] bridgeToSiteMap failed: " + e.getMessage());
        }
    }

    private AuditIssueSeverity mapToAuditSeverity(VulnReport.Severity sev)
    {
        switch (sev)
        {
            case CRITICAL:
            case HIGH: return AuditIssueSeverity.HIGH;
            case MEDIUM: return AuditIssueSeverity.MEDIUM;
            case LOW: return AuditIssueSeverity.LOW;
            default: return AuditIssueSeverity.INFORMATION;
        }
    }

    private AuditIssueConfidence mapToAuditConfidence(
        VulnReport.VerifyStatus status, double confidence)
    {
        if (status == VulnReport.VerifyStatus.CONFIRMED || confidence >= 0.9)
            return AuditIssueConfidence.CERTAIN;
        if (status == VulnReport.VerifyStatus.PENDING || confidence >= 0.6)
            return AuditIssueConfidence.FIRM;
        return AuditIssueConfidence.TENTATIVE;
    }

    private String buildDashboardDetail(VulnReport r)
    {
        StringBuilder sb = new StringBuilder();
        sb.append("<b>漏洞类型:</b> ").append(r.getVulnType()).append("<br>");
        if (r.getParameter() != null && !r.getParameter().isEmpty())
            sb.append("<b>参数:</b> ").append(r.getParameter()).append("<br>");
        sb.append("<b>风险等级:</b> ").append(r.getSeverity().label()).append("<br>");
        sb.append("<b>置信度:</b> ").append(String.format("%.0f%%", r.getConfidence() * 100)).append("<br>");
        sb.append("<b>验证状态:</b> ").append(r.getVerifyStatus().label()).append("<br>");
        if (r.getDescription() != null && !r.getDescription().isEmpty())
            sb.append("<b>描述:</b> ").append(r.getDescription()).append("<br>");
        if (r.getEvidence() != null && !r.getEvidence().isEmpty())
            sb.append("<b>证据:</b> ").append(r.getEvidence()).append("<br>");
        if (r.getVerificationDetail() != null && !r.getVerificationDetail().isEmpty())
            sb.append("<b>验证详情:</b> ").append(r.getVerificationDetail()).append("<br>");
        sb.append(r.timingSummary()).append("<br>");
        if (r.getOriginalRequest() != null && !r.getOriginalRequest().isEmpty())
            sb.append("<b>原始请求:</b><br><pre>").append(escapeHtml(r.getOriginalRequest())).append("</pre><br>");
        if (r.getTestPayload() != null && !r.getTestPayload().isEmpty())
            sb.append("<b>测试Payload:</b> ").append(escapeHtml(r.getTestPayload())).append("<br>");
        if (r.getReproduceRequest() != null && !r.getReproduceRequest().isEmpty())
            sb.append("<b>复现请求:</b><br><pre>").append(escapeHtml(r.getReproduceRequest())).append("</pre><br>");
        sb.append("<b>来源:</b> AI流量分析");
        return sb.toString();
    }

    private String escapeHtml(String text)
    {
        if (text == null) return "";
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    /**
     * 构建漏洞去重 key：标准化URL(去掉端口和查询参数值) + 漏洞类型 + 参数名。
     */
    private String buildVulnDedupKey(VulnReport r)
    {
        String url = r.getUrl() != null ? r.getUrl() : "";
        String normalized = normalizeUrlForDedup(url);
        String param = r.getParameter() != null ? r.getParameter() : "";
        return r.getVulnType() + "|" + normalized + "|" + param;
    }

    /**
     * 仅去掉 URL 中的默认端口(:80/:443)，保留完整的路径和查询参数。
     */
    private String stripDefaultPort(String url)
    {
        if (url == null || url.isEmpty()) return url;
        try
        {
            int schemeEnd = url.indexOf("://");
            if (schemeEnd < 0) return url;
            String scheme = url.substring(0, schemeEnd).toLowerCase();
            String rest = url.substring(schemeEnd + 3);
            int pathStart = rest.indexOf('/');
            String authority = pathStart > 0 ? rest.substring(0, pathStart) : rest;
            String pathAndQuery = pathStart >= 0 ? rest.substring(pathStart) : "";
            if (("http".equals(scheme) && authority.endsWith(":80"))
                || ("https".equals(scheme) && authority.endsWith(":443")))
            {
                authority = authority.substring(0, authority.lastIndexOf(':'));
            }
            return scheme + "://" + authority + pathAndQuery;
        }
        catch (Exception e)
        {
            return url;
        }
    }

    /**
     * 标准化 URL 用于去重：去掉默认端口(:80/:443)，去掉查询参数值只保留参数名。
     */
    private String normalizeUrlForDedup(String url)
    {
        if (url == null || url.isEmpty()) return "";
        try
        {
            int schemeEnd = url.indexOf("://");
            String scheme = schemeEnd > 0 ? url.substring(0, schemeEnd).toLowerCase() : "http";
            String rest = schemeEnd > 0 ? url.substring(schemeEnd + 3) : url;
            int pathStart = rest.indexOf('/');
            String authority = pathStart > 0 ? rest.substring(0, pathStart) : rest;
            String path = pathStart >= 0 ? rest.substring(pathStart) : "/";
            if (("http".equals(scheme) && authority.endsWith(":80"))
                || ("https".equals(scheme) && authority.endsWith(":443")))
            {
                authority = authority.substring(0, authority.lastIndexOf(':'));
            }
            int queryStart = path.indexOf('?');
            if (queryStart >= 0)
            {
                String query = path.substring(queryStart + 1);
                StringBuilder nq = new StringBuilder();
                for (String param : query.split("&"))
                {
                    int eq = param.indexOf('=');
                    if (nq.length() > 0) nq.append('&');
                    nq.append(eq >= 0 ? param.substring(0, eq) : param);
                }
                path = path.substring(0, queryStart + 1) + nq;
            }
            return scheme + "://" + authority + path;
        }
        catch (Exception e)
        {
            return url;
        }
    }

    /**
     * 获取所有日志条目。
     */
    public List<LogEntry> getEntries()
    {
        return new ArrayList<>(entries);
    }

    /**
     * 获取所有漏洞报告。
     */
    public List<VulnReport> getVulnReports()
    {
        return new ArrayList<>(vulnReports);
    }

    /**
     * 用新的漏洞报告列表替换当前内存中的报告快照。
     * 供 ReportPanel 的删除/清空/状态修改回写使用。
     */
    public void replaceVulnReports(List<VulnReport> reports)
    {
        vulnReports.clear();
        if (reports != null)
        {
            vulnReports.addAll(reports);
        }
        saveVulnReports();
        // 报告被清空时通知扫描器重置缓存，允许重新分析
        if ((reports == null || reports.isEmpty()) && reportsClearedCallback != null)
        {
            reportsClearedCallback.onReportsCleared();
        }
    }

    public void setReportsClearedCallback(ReportsClearedCallback callback)
    {
        this.reportsClearedCallback = callback;
    }

    /**
     * 按类别过滤日志。
     */
    public List<LogEntry> getByCategory(String category)
    {
        List<LogEntry> filtered = new ArrayList<>();
        for (LogEntry e : entries)
        {
            if (category.equals(e.category)) filtered.add(e);
        }
        return filtered;
    }

    /**
     * 获取日志总数。
     */
    public int size()
    {
        return entries.size();
    }

    /**
     * 清空日志。
     */
    public void clear()
    {
        entries.clear();
        vulnReports.clear();
        saveVulnReports();
        if (reportsClearedCallback != null) reportsClearedCallback.onReportsCleared();
    }

    private String truncate(String s, int max)
    {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max) + "...";
    }

    /**
     * 日志条目。
     */
    public static class LogEntry
    {
        public final String timestamp;
        public final String category;
        public final String target;
        public final String message;

        public LogEntry(String category, String target, String message)
        {
            this.timestamp = LocalDateTime.now().format(FMT);
            this.category = category;
            this.target = target;
            this.message = message;
        }

        @Override
        public String toString()
        {
            return "[" + timestamp + "] [" + category + "] " + target + " → " + message;
        }
    }
}
