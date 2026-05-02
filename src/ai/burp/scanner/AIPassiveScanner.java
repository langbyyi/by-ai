package ai.burp.scanner;

import java.util.*;

import ai.burp.util.TextUtils;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.scancheck.PassiveScanCheck;

import ai.burp.model.ChatMessage;
import ai.burp.model.VulnReport;
import ai.burp.provider.StreamingAIProvider;
import ai.burp.util.AiResponseParser;
import ai.burp.util.VulnFindingPolicy;

/**
 * AI被动扫描器 - 注册为Burp原生PassiveScanCheck。
 * 自动分析所有经过Proxy/Repeater/Scanner的HTTP流量。
 * 结果以AuditIssue形式出现在Burp Dashboard > Issue Activity面板。
 *
 * 执行链: 技术指纹识别 → 关键信息提取 → POC库匹配 → AI全量漏洞分析 → Repeater验证 → 仪表盘同步
 */
public class AIPassiveScanner implements PassiveScanCheck
{
    private final StreamingAIProvider provider;
    private final TechFingerprint fingerprint;
    private final InfoExtractor infoExtractor;
    private final AuditLogger logger;

    /** 可选：用于发送到Repeater和仪表盘同步 */
    private MontoyaApi api;
    private ScanCallback callback;

    /** 已扫描过的请求URL缓存，避免重复AI调用 */
    private final Set<String> scannedUrls = Collections.synchronizedSet(
        Collections.newSetFromMap(new LinkedHashMap<String, Boolean>()
        {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, Boolean> eldest)
            {
                return size() > 500;
            }
        }));

    public AIPassiveScanner(StreamingAIProvider provider, TechFingerprint fingerprint,
        InfoExtractor infoExtractor, AuditLogger logger)
    {
        this.provider = provider;
        this.fingerprint = fingerprint;
        this.infoExtractor = infoExtractor;
        this.logger = logger;
    }

    /**
     * 注入 MontoyaApi（用于 Repeater）。
     */
    public void setApi(MontoyaApi api)
    {
        this.api = api;
    }

    /**
     * 清空已扫描 URL 缓存，允许对相同请求重新分析。
     */
    public void clearScannedCache()
    {
        scannedUrls.clear();
    }

    /**
     * 设置扫描回调（用于仪表盘同步）。
     */
    public void setCallback(ScanCallback callback)
    {
        this.callback = callback;
    }

    @Override
    public String checkName()
    {
        return "AI 全量被动扫描";
    }

    @Override
    public AuditResult doCheck(HttpRequestResponse baseRequestResponse)
    {
        // 未配置API则跳过
        if (!provider.isConfigured()) return AuditResult.auditResult();

        String url = baseRequestResponse.request().url();
        String method = baseRequestResponse.request().method();

        // 跳过静态资源
        if (isStaticResource(url)) return AuditResult.auditResult();

        // 去重：同URL同Method不重复扫描
        String dedupeKey = method + " " + simplifyUrl(url);
        synchronized (scannedUrls)
        {
            if (scannedUrls.contains(dedupeKey)) return AuditResult.auditResult();
            scannedUrls.add(dedupeKey);
        }

        String request = TextUtils.toStringUtf8(baseRequestResponse.request());
        String response = baseRequestResponse.hasResponse()
            ? TextUtils.toStringUtf8(baseRequestResponse.response()) : "";
        String host = baseRequestResponse.httpService().host();

        // 步骤1: 技术指纹识别（轻量，规则为主，同步执行）
        TechFingerprint.TechStack tech = fingerprint.identify(baseRequestResponse);

        // 步骤2: POC库匹配（基于识别到的技术栈，纯本地匹配）
        List<FullVulnDatabase.POCEntry> matchedPOCs = FullVulnDatabase.matchPOCs(tech);

        // 步骤3: 关键信息提取（规则为主，同步执行）
        InfoExtractor.ExtractedInfo info = infoExtractor.extract(baseRequestResponse);

        // 通知仪表盘更新
        notifyTechStack(tech);

        // 如果匹配到POC，记录到审计日志
        if (!matchedPOCs.isEmpty())
        {
            for (FullVulnDatabase.POCEntry poc : matchedPOCs)
            {
                logger.log("POC匹配", host, poc.cveId + " " + poc.description + " [" + poc.severity + "]");
            }
        }

        // 步骤4: AI全量漏洞被动分析。直接返回 AuditResult，确保 Burp 原生 Issue 绑定到当前请求。
        List<AuditIssue> issues = runPassiveScan(request, response, url, method, host,
            matchedPOCs, baseRequestResponse);
        return AuditResult.auditResult(issues);
    }

    /**
     * 执行被动扫描逻辑，并返回可由 Burp 原生 Scanner 直接接收的 AuditIssue。
     */
    private List<AuditIssue> runPassiveScan(String request, String response, String url,
        String method, String host, List<FullVulnDatabase.POCEntry> matchedPOCs,
        HttpRequestResponse baseRequestResponse)
    {
        List<AuditIssue> issues = new ArrayList<>();
        try
        {
            // AI全量漏洞分析（耗时操作）
            logger.log("被动扫描", url, method + " 正在执行AI分析...");
            String prompt = FullVulnDatabase.buildPassiveScanPrompt(request, response);
            String aiResult = provider.chat(Collections.singletonList(ChatMessage.user(prompt)));
            logger.logAIInteraction("被动扫描", prompt, aiResult);

            issues.addAll(parseIssues(aiResult, baseRequestResponse));

            // 将匹配的POC也转为AuditIssue
            for (FullVulnDatabase.POCEntry poc : matchedPOCs)
            {
                AuditIssue pocIssue = buildPOCIssue(poc, host, baseRequestResponse);
                if (pocIssue != null) issues.add(pocIssue);
            }

            int persistedCount = 0;
            if (!issues.isEmpty())
            {
                for (AuditIssue issue : issues)
                {
                    String issueDetail = stripHtml(issue.detail());
                    String severityLabel = issue.severity() != null ? issue.severity().name() : "";
                    double reportConfidence = issue.confidence() == AuditIssueConfidence.CERTAIN ? 0.95
                        : issue.confidence() == AuditIssueConfidence.FIRM ? 0.8 : 0.5;
                    // POC库匹配有技术栈证据支撑，提升置信度避免被策略过滤
                    if (issue.name().startsWith("潜在组件风险:") && reportConfidence < 0.75)
                    {
                        reportConfidence = 0.75;
                    }
                    if (!VulnFindingPolicy.shouldKeep(issue.name(), severityLabel, reportConfidence,
                        issueDetail, issueDetail, "被动扫描"))
                    {
                        continue;
                    }

                    // 构建结构化 VulnReport 供 ReportPanel 使用
                    VulnReport vr = new VulnReport();
                    vr.setUrl(url);
                    vr.setMethod(method);
                    vr.setHost(host);
                    vr.setVulnType(issue.name());
                    vr.setSeverity(mapToVulnSeverity(issue.severity()));
                    vr.setVerifyStatus(VulnReport.VerifyStatus.PENDING);
                    vr.setDescription(issueDetail);
                    vr.setSuggestion(issue.remediation());
                    vr.setOriginalRequest(request);
                    vr.setOriginalResponse(response);
                    vr.setSecure(baseRequestResponse.httpService().secure());
                    vr.setConfidence(reportConfidence);
                    vr.setCategory("被动扫描");
                    logger.logVulnReport(vr);
                    persistedCount++;

                    // 发送到Repeater供手动验证
                    sendToRepeater("AI检测: " + issue.name(), baseRequestResponse);
                }
                logger.log("被动扫描", url, "发现 " + issues.size() + " 个风险，写入报告 " + persistedCount + " 个");
                if (persistedCount > 0)
                {
                    notifyVulnFound();
                }
            }
            else
            {
                logger.log("被动扫描", url, "未发现风险");
            }
        }
        catch (Exception e)
        {
            logger.log("被动扫描", url, "AI分析失败: " + e.getMessage());
        }
        return issues;
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue existingIssue, AuditIssue newIssue)
    {
        // 同名同URL的漏洞合并
        if (existingIssue.name().equals(newIssue.name())
            && existingIssue.baseUrl().equals(newIssue.baseUrl()))
        {
            return ConsolidationAction.KEEP_EXISTING;
        }
        return ConsolidationAction.KEEP_BOTH;
    }

    /**
     * 解析AI返回的漏洞列表为Burp原生AuditIssue。
     * 包含完整标准化字段：名称/等级/原理/影响范围/复现步骤/验证Payload/修复建议。
     */
    private List<AuditIssue> parseIssues(String aiResult, HttpRequestResponse baseRequestResponse)
    {
        List<AuditIssue> issues = new ArrayList<>();
        try
        {
            String url = baseRequestResponse.request().url();
            IssueCandidate bestCandidate = null;

            for (Map<String, Object> m : AiResponseParser.parseFirstObjectArray(aiResult))
            {
                try
                {
                    String vulnName = AiResponseParser.getString(m, "name");
                    if (vulnName.isEmpty()) continue;

                    String name = "AI检测: " + vulnName;
                    String severity = AiResponseParser.getString(m, "severity");
                    String parameter = AiResponseParser.getString(m, "parameter");
                    String evidence = AiResponseParser.getString(m, "evidence");
                    String detail = AiResponseParser.getString(m, "detail");
                    String scope = AiResponseParser.getString(m, "scope");
                    String reproduceSteps = AiResponseParser.getString(m, "reproduceSteps");
                    String remediation = AiResponseParser.getString(m, "remediation");
                    String background = AiResponseParser.getString(m, "background");
                    double confidence = AiResponseParser.getDouble(m, "confidence", 0.5);
                    if (!VulnFindingPolicy.shouldKeep(vulnName, severity, confidence, evidence, detail, "被动扫描"))
                    {
                        continue;
                    }

                    IssueCandidate candidate = new IssueCandidate();
                    candidate.name = name;
                    candidate.vulnName = vulnName;
                    candidate.severity = severity;
                    candidate.parameter = parameter;
                    candidate.evidence = evidence;
                    candidate.detail = detail;
                    candidate.scope = scope;
                    candidate.reproduceSteps = reproduceSteps;
                    candidate.remediation = remediation;
                    candidate.background = background;
                    candidate.confidence = confidence;

                    if (bestCandidate == null || candidate.score() > bestCandidate.score())
                    {
                        bestCandidate = candidate;
                    }
                }
                catch (Exception ignored) {}
            }

            if (bestCandidate != null)
            {
                String fullDetail = "<b>漏洞名称:</b> " + bestCandidate.name + "<br>"
                    + "<b>漏洞原理:</b> " + bestCandidate.detail + "<br>"
                    + "<b>参数:</b> " + bestCandidate.parameter + "<br>"
                    + "<b>影响范围:</b> "
                    + (bestCandidate.scope.isEmpty() ? "影响使用该参数的所有功能" : bestCandidate.scope) + "<br>"
                    + "<b>复现步骤:</b><br>" + formatSteps(bestCandidate.reproduceSteps) + "<br>"
                    + "<b>证据:</b> " + bestCandidate.evidence + "<br>"
                    + "<b>置信度:</b> " + String.format("%.0f%%", bestCandidate.confidence * 100);

                AuditIssue issue = AuditIssue.auditIssue(
                    bestCandidate.name,
                    fullDetail,
                    bestCandidate.remediation,
                    url,
                    mapSeverity(bestCandidate.severity),
                    mapConfidence(bestCandidate.confidence),
                    bestCandidate.background.isEmpty()
                        ? (bestCandidate.name + "是一种Web安全漏洞")
                        : bestCandidate.background,
                    bestCandidate.remediation.isEmpty()
                        ? "对用户输入进行验证和过滤"
                        : bestCandidate.remediation,
                    mapSeverity(bestCandidate.severity),
                    baseRequestResponse
                );

                issues.add(issue);
            }
        }
        catch (Exception ignored) {}
        return issues;
    }

    /**
     * 将POC库匹配结果转为AuditIssue。
     */
    private AuditIssue buildPOCIssue(FullVulnDatabase.POCEntry poc, String url,
        HttpRequestResponse baseRequestResponse)
    {
        String name = "潜在组件风险: " + poc.cveId + " " + poc.description;
        String fullDetail = "<b>CVE编号:</b> " + poc.cveId + "<br>"
            + "<b>组件:</b> " + poc.component + "<br>"
            + "<b>漏洞原理:</b> " + poc.description + "<br>"
            + "<b>影响范围:</b> " + poc.impact + "<br>"
            + "<b>复现步骤:</b><br>" + formatSteps(poc.reproduceSteps) + "<br>"
            + "<b>验证POC:</b> " + poc.poc + "<br>"
            + "<b>原始风险等级:</b> " + poc.severity + "<br>"
            + "<b>说明:</b> 当前结果来自技术栈关键词匹配，未确认具体受影响版本，请人工复核。";

        AuditIssueSeverity severity = AuditIssueSeverity.INFORMATION;

        return AuditIssue.auditIssue(
            name,
            fullDetail,
            "升级 " + poc.component + " 到安全版本，关注官方安全公告。",
            url,
            severity,
            AuditIssueConfidence.TENTATIVE,
            poc.description,
            "关注组件安全公告，及时升级到安全版本。",
            severity,
            baseRequestResponse
        );
    }

    private AuditIssueSeverity mapSeverity(String severity)
    {
        if (severity == null) return AuditIssueSeverity.MEDIUM;
        String lower = severity.toLowerCase();
        if (lower.contains("严重") || lower.contains("critical")) return AuditIssueSeverity.HIGH;
        if (lower.contains("高") || lower.contains("high")) return AuditIssueSeverity.HIGH;
        if (lower.contains("中") || lower.contains("medium")) return AuditIssueSeverity.MEDIUM;
        if (lower.contains("低") || lower.contains("low")) return AuditIssueSeverity.LOW;
        if (lower.contains("信息") || lower.contains("info")) return AuditIssueSeverity.INFORMATION;
        return AuditIssueSeverity.MEDIUM;
    }

    private AuditIssueConfidence mapConfidence(double confidence)
    {
        if (confidence >= 0.9) return AuditIssueConfidence.CERTAIN;
        if (confidence >= 0.7) return AuditIssueConfidence.FIRM;
        return AuditIssueConfidence.TENTATIVE;
    }

    private VulnReport.Severity mapToVulnSeverity(AuditIssueSeverity severity)
    {
        if (severity == AuditIssueSeverity.HIGH) return VulnReport.Severity.HIGH;
        if (severity == AuditIssueSeverity.MEDIUM) return VulnReport.Severity.MEDIUM;
        if (severity == AuditIssueSeverity.LOW) return VulnReport.Severity.LOW;
        if (severity == AuditIssueSeverity.INFORMATION) return VulnReport.Severity.INFO;
        return VulnReport.Severity.MEDIUM;
    }

    /**
     * 格式化复现步骤为HTML。
     */
    private String formatSteps(String steps)
    {
        if (steps == null || steps.isEmpty()) return "1. 访问目标接口<br>2. 注入测试Payload<br>3. 观察响应";
        return steps.replace("\n", "<br>");
    }

    /**
     * 发送到Repeater。
     */
    private void sendToRepeater(String caption, HttpRequestResponse requestResponse)
    {
        if (api == null) return;
        try
        {
            api.repeater().sendToRepeater(requestResponse.request(), caption);
        }
        catch (Exception ignored) {}
    }

    /**
     * 通知仪表盘技术栈更新。
     */
    private void notifyTechStack(TechFingerprint.TechStack tech)
    {
        if (callback != null)
        {
            try { callback.onTechStackIdentified(tech); } catch (Exception ignored) {}
        }
    }

    /**
     * 通知漏洞发现。
     */
    private void notifyVulnFound()
    {
        if (callback != null)
        {
            try { callback.onVulnerabilityFound(); } catch (Exception ignored) {}
        }
    }

    /**
     * 判断是否为静态资源（跳过AI分析以节省API调用）。
     */
    private boolean isStaticResource(String url)
    {
        String lower = url.toLowerCase();
        return lower.endsWith(".css") || lower.endsWith(".js")
            || lower.endsWith(".png") || lower.endsWith(".jpg")
            || lower.endsWith(".jpeg") || lower.endsWith(".gif")
            || lower.endsWith(".ico") || lower.endsWith(".svg")
            || lower.endsWith(".woff") || lower.endsWith(".woff2")
            || lower.endsWith(".ttf") || lower.endsWith(".eot")
            || lower.endsWith(".map");
    }

    /**
     * 简化URL用于去重（去掉查询参数）。
     */
    private String simplifyUrl(String url)
    {
        int q = url.indexOf('?');
        return q >= 0 ? url.substring(0, q) : url;
    }

    private String stripHtml(String text)
    {
        if (text == null || text.isEmpty()) return "";
        return text.replace("<br>", "\n")
            .replace("<br/>", "\n")
            .replace("<br />", "\n")
            .replaceAll("<[^>]+>", "")
            .replace("&nbsp;", " ")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&amp;", "&")
            .trim();
    }

    private static final class IssueCandidate
    {
        String name = "";
        String vulnName = "";
        String severity = "";
        String parameter = "";
        String evidence = "";
        String detail = "";
        String scope = "";
        String reproduceSteps = "";
        String remediation = "";
        String background = "";
        double confidence = 0.0;

        int score()
        {
            return VulnFindingPolicy.score(vulnName, severity, confidence, evidence, detail, "被动扫描");
        }
    }
    // ==================== 扫描回调接口 ====================

    /**
     * 扫描结果回调 - 用于通知UI层更新。
     */
    public interface ScanCallback
    {
        /** 技术栈识别完成 */
        void onTechStackIdentified(TechFingerprint.TechStack tech);
        /** 发现漏洞 */
        void onVulnerabilityFound();
    }
}
