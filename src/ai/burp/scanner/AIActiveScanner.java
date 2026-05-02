package ai.burp.scanner;

import java.util.*;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.handler.TimingData;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.scancheck.ActiveScanCheck;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;

import ai.burp.model.ChatMessage;
import ai.burp.model.VulnReport;
import ai.burp.provider.StreamingAIProvider;
import ai.burp.util.AiResponseParser;
import ai.burp.util.TextUtils;
import ai.burp.util.VulnFindingPolicy;

/**
 * AI主动扫描器 - 注册为Burp原生ActiveScanCheck。
 * 在Burp Scanner的每个插入点上，AI生成针对性payload并发送验证。
 * 结果以AuditIssue形式出现在Burp Dashboard中。
 * 验证成功自动发送到Repeater供手动复现。
 */
public class AIActiveScanner implements ActiveScanCheck
{
    private final StreamingAIProvider provider;
    private final MontoyaApi api;
    private final AuditLogger logger;
    private ScanCallback callback;

    public AIActiveScanner(StreamingAIProvider provider, MontoyaApi api, AuditLogger logger)
    {
        this.provider = provider;
        this.api = api;
        this.logger = logger;
    }

    @Override
    public String checkName()
    {
        return "AI 智能主动扫描";
    }

    @Override
    public AuditResult doCheck(HttpRequestResponse baseRequestResponse,
        AuditInsertionPoint insertionPoint, Http http)
    {
        if (!provider.isConfigured()) return AuditResult.auditResult();

        // 捕获所有需要的上下文数据，供异步线程使用
        final String request = TextUtils.toStringUtf8(baseRequestResponse.request());
        final String response = baseRequestResponse.hasResponse()
            ? TextUtils.toStringUtf8(baseRequestResponse.response()) : "";
        final String paramName = insertionPoint.name();
        final String baseValue = insertionPoint.baseValue();
        final String url = baseRequestResponse.request().url();
        final String host = baseRequestResponse.httpService().host();

        logger.log("主动扫描", url, "测试参数: " + paramName + " (值: " + baseValue + ")");

        List<AuditIssue> issues = runActiveScan(request, response, paramName, baseValue, url,
            host, baseRequestResponse, insertionPoint, http);
        return AuditResult.auditResult(issues);
    }

    /**
     * 执行主动扫描逻辑，并返回可由 Burp 原生 Scanner 直接接收的 AuditIssue。
     */
    private List<AuditIssue> runActiveScan(String request, String response, String paramName,
        String baseValue, String url, String host, HttpRequestResponse baseRequestResponse,
        AuditInsertionPoint insertionPoint, Http http)
    {
        List<AuditIssue> issues = new ArrayList<>();
        try
        {
            // AI生成测试payload（耗时操作）
            String prompt = FullVulnDatabase.buildActiveScanPrompt(request, paramName, baseValue, response);
            String aiResult = provider.chat(Collections.singletonList(ChatMessage.user(prompt)));
            logger.logAIInteraction("主动扫描Payload生成", prompt, aiResult);

            List<PayloadEntry> payloads = parsePayloads(aiResult);

            for (PayloadEntry pe : payloads)
            {
                try
                {
                    // 通过Burp的插入点机制发送payload
                    burp.api.montoya.core.ByteArray payloadBytes =
                        burp.api.montoya.core.ByteArray.byteArray(pe.payload);
                    burp.api.montoya.http.message.requests.HttpRequest testReq =
                        insertionPoint.buildHttpRequestWithPayload(payloadBytes);

                    long start = System.currentTimeMillis();
                    HttpRequestResponse testResult = http.sendRequest(testReq);
                    long durationMs = System.currentTimeMillis() - start;

                    // 记录到审计日志和 AIRequestPanel
                    String reqText = testReq.toString();
                    String respText = testResult.hasResponse() ? TextUtils.toStringUtf8(testResult.response()) : null;
                    int statusCode = testResult.hasResponse() ? testResult.response().statusCode() : 0;
                    logger.logHttpExchange(reqText, respText, url, "SCAN-" + pe.vulnType, statusCode, durationMs);

                    if (testResult.hasResponse())
                    {
                        String testResp = TextUtils.toStringUtf8(testResult.response());

                        // AI分析验证结果（耗时操作）
                        VerifyResult vr = verifyResponse(response, testResp, pe.vulnType, durationMs);
                        if (vr.vulnerable)
                        {
                            if (!VulnFindingPolicy.shouldKeep(pe.vulnType,
                                determineSeverity(pe.vulnType).name(), vr.confidence,
                                vr.evidence, vr.reasoning, "主动扫描"))
                            {
                                continue;
                            }

                            AuditIssue issue = buildAuditIssue(
                                pe.vulnType, url, paramName, pe.payload,
                                vr.evidence, vr.reasoning, vr.scope, vr.reproduceSteps,
                                baseRequestResponse, testResult);

                            // 构建结构化 VulnReport 供 ReportPanel 使用
                            VulnReport report = new VulnReport();
                            report.setUrl(url);
                            report.setMethod(baseRequestResponse.request().method());
                            report.setHost(host);
                            report.setVulnType(pe.vulnType);
                            report.setParameter(paramName);
                            report.setSeverity(mapActiveSeverityToVuln(determineSeverity(pe.vulnType)));
                            report.setVerifyStatus(VulnReport.VerifyStatus.CONFIRMED);
                            report.setConfidence(vr.confidence);
                            report.setDescription(vr.reasoning);
                            report.setEvidence(vr.evidence);
                            report.setSuggestion(generateRemediation(pe.vulnType));
                            report.setOriginalRequest(request);
                            report.setSecure(baseRequestResponse.httpService().secure());
                            report.setReproduceRequest(reqText);   // 完整的可复现测试请求
                            report.setTestPayload(pe.payload);
                            report.setTestResponse(testResp);
                            report.setOriginalResponse(response);  // 原始响应作为基线
                            report.setCategory("主动扫描");
                            report.addTag("active-scan");
                            if (!pe.scope.isEmpty()) report.setVerificationDetail("影响范围: " + pe.scope);
                            // 从 Burp 原生 TimingData 填充响应时间
                            try
                            {
                                Optional<TimingData> timingData = testResult.timingData();
                                if (timingData.isPresent())
                                {
                                    TimingData td = timingData.get();
                                    if (td.timeBetweenRequestSentAndStartOfResponse() != null)
                                    {
                                        long ttfb = td.timeBetweenRequestSentAndStartOfResponse().toMillis();
                                        if (ttfb > 0) report.setTtfbMs(ttfb);
                                    }
                                    if (td.timeBetweenRequestSentAndEndOfResponse() != null)
                                    {
                                        long ttlb = td.timeBetweenRequestSentAndEndOfResponse().toMillis();
                                        if (ttlb > 0) report.setTtlbMs(ttlb);
                                    }
                                }
                            }
                            catch (Exception ignored) {}
                            logger.logVulnReport(report);

                            // 发送到Repeater供手动验证
                            sendToRepeater("AI验证: " + pe.vulnType + " (" + paramName + ")", testResult);

                            issues.add(issue);

                            // 通知UI层更新
                            notifyVulnFound();

                            break; // 找到一个漏洞就够了
                        }
                    }
                }
                catch (Exception ignored) {}
            }
        }
        catch (Exception e)
        {
            logger.log("主动扫描", url, "AI分析失败: " + e.getMessage());
        }
        return issues;
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue existingIssue, AuditIssue newIssue)
    {
        if (existingIssue.name().equals(newIssue.name())
            && existingIssue.baseUrl().equals(newIssue.baseUrl()))
        {
            return ConsolidationAction.KEEP_EXISTING;
        }
        return ConsolidationAction.KEEP_BOTH;
    }

    /**
     * AI分析响应验证漏洞。
     */
    private VerifyResult verifyResponse(String originalResp, String testResp, String vulnType, long durationMs)
        throws Exception
    {
        String prompt = FullVulnDatabase.buildVerifyPrompt(originalResp, testResp, vulnType, durationMs);
        String aiResult = provider.chat(Collections.singletonList(ChatMessage.user(prompt)));

        try
        {
            Map<String, Object> parsed = AiResponseParser.parseFirstObject(aiResult);
            if (!parsed.isEmpty())
            {
                boolean vulnerable = AiResponseParser.getBoolean(parsed, "vulnerable", false);
                double confidence = AiResponseParser.getDouble(parsed, "confidence", 0.0);
                String reasoning = AiResponseParser.getString(parsed, "reasoning");
                String evidence = AiResponseParser.getString(parsed, "evidence");
                String scope = AiResponseParser.getString(parsed, "scope");
                String reproduceSteps = AiResponseParser.getString(parsed, "reproduceSteps");

                if (vulnerable && confidence >= 0.7)
                {
                    return new VerifyResult(true, confidence, reasoning, evidence, scope, reproduceSteps);
                }
            }
        }
        catch (Exception ignored) {}
        return new VerifyResult(false, 0, "", "", "", "");
    }

    /**
     * 构建Burp原生AuditIssue - 完整标准化信息。
     */
    private AuditIssue buildAuditIssue(String vulnType, String url, String param,
        String payload, String evidence, String reasoning, String scope, String reproduceSteps,
        HttpRequestResponse base, HttpRequestResponse test)
    {
        AuditIssueSeverity severity = determineSeverity(vulnType);
        AuditIssueConfidence confidence = AuditIssueConfidence.FIRM;

        String name = "AI检测: " + vulnType + " (" + param + ")";

        // 完整标准化detail
        String detail = "<b>漏洞名称:</b> " + name + "<br>"
            + "<b>风险等级:</b> " + severity.name() + "<br>"
            + "<b>漏洞原理:</b> " + vulnType + "是因参数 " + param + " 未正确处理导致的Web安全漏洞<br>"
            + "<b>影响范围:</b> " + (scope.isEmpty() ? "影响所有使用参数" + param + "的功能" : scope) + "<br>"
            + "<b>复现步骤:</b><br>" + formatSteps(reproduceSteps) + "<br>"
            + "<b>验证Payload:</b> " + payload + "<br>"
            + "<b>AI推理:</b> " + reasoning + "<br>"
            + "<b>证据:</b> " + evidence;

        String remediation = generateRemediation(vulnType);
        String background = vulnType + "是一种常见Web安全漏洞，攻击者可以利用该漏洞进行未授权操作。";

        return AuditIssue.auditIssue(
            name, detail, remediation, url,
            severity, confidence,
            background,
            remediation,
            severity, base, test);
    }

    /**
     * 格式化复现步骤。
     */
    private String formatSteps(String steps)
    {
        if (steps == null || steps.isEmpty())
            return "1. 访问目标URL<br>2. 在参数中注入Payload<br>3. 观察响应变化";
        return steps.replace("\n", "<br>");
    }

    /**
     * 发送到Repeater供手动验证。
     */
    private void sendToRepeater(String caption, HttpRequestResponse requestResponse)
    {
        try
        {
            api.repeater().sendToRepeater(requestResponse.request(), caption);
            logger.log("Repeater", requestResponse.request().url(), "已发送到Repeater: " + caption);
        }
        catch (Exception ignored) {}
    }

    private AuditIssueSeverity determineSeverity(String vulnType)
    {
        String lower = vulnType.toLowerCase();
        if (lower.contains("rce") || lower.contains("命令注入") || lower.contains("代码注入")
            || lower.contains("反序列化") || lower.contains("ssrf"))
        {
            return AuditIssueSeverity.HIGH;
        }
        if (lower.contains("sql") || lower.contains("sqli") || lower.contains("xss")
            || lower.contains("上传") || lower.contains("xxe"))
        {
            return AuditIssueSeverity.HIGH;
        }
        if (lower.contains("越权") || lower.contains("idor") || lower.contains("路径遍历")
            || lower.contains("文件包含") || lower.contains("ssti"))
        {
            return AuditIssueSeverity.MEDIUM;
        }
        if (lower.contains("信息泄露") || lower.contains("cors") || lower.contains("开放重定向")
            || lower.contains("csp") || lower.contains("hsts"))
        {
            return AuditIssueSeverity.LOW;
        }
        return AuditIssueSeverity.MEDIUM;
    }

    private String generateRemediation(String vulnType)
    {
        String lower = vulnType.toLowerCase();
        if (lower.contains("sql")) return "使用参数化查询/预编译语句，对用户输入进行严格过滤。";
        if (lower.contains("xss")) return "对所有用户输入进行HTML实体编码输出，使用CSP策略。";
        if (lower.contains("ssrf")) return "限制服务器对外请求的目标地址，使用白名单策略。";
        if (lower.contains("命令注入")) return "避免直接拼接用户输入到系统命令，使用安全的API替代。";
        if (lower.contains("xxe")) return "禁用XML外部实体解析，使用安全的XML解析配置。";
        if (lower.contains("ssti")) return "避免直接将用户输入传入模板引擎，使用沙箱环境。";
        if (lower.contains("越权") || lower.contains("idor")) return "在服务端校验用户权限，不依赖客户端传递的用户标识。";
        if (lower.contains("上传")) return "限制上传文件类型和大小，重命名文件，存储到非Web目录。";
        if (lower.contains("路径遍历")) return "校验文件路径，限制在允许的目录范围内。";
        if (lower.contains("反序列化")) return "避免反序列化不可信数据，使用白名单限制反序列化类。";
        if (lower.contains("cors")) return "严格配置CORS策略，限制允许的源和方法。";
        if (lower.contains("信息泄露")) return "关闭生产环境的调试信息和错误详情输出。";
        return "对用户输入进行严格验证和过滤，遵循安全编码最佳实践。";
    }

    private List<PayloadEntry> parsePayloads(String aiResult)
    {
        List<PayloadEntry> payloads = new ArrayList<>();
        try
        {
            int count = 0;
            for (Map<String, Object> m : AiResponseParser.parseFirstObjectArray(aiResult))
            {
                if (count >= 5) break; // 最多5个payload
                PayloadEntry pe = new PayloadEntry();
                pe.vulnType = AiResponseParser.getString(m, "vulnType");
                pe.payload = AiResponseParser.getString(m, "payload");
                pe.description = AiResponseParser.getString(m, "description");
                pe.expectedBehavior = AiResponseParser.getString(m, "expectedBehavior");
                pe.scope = AiResponseParser.getString(m, "scope");
                pe.reproduceSteps = AiResponseParser.getString(m, "reproduceSteps");
                if (!pe.payload.isEmpty())
                {
                    payloads.add(pe);
                    count++;
                }
            }
        }
        catch (Exception ignored) {}
        return payloads;
    }

    private VulnReport.Severity mapActiveSeverityToVuln(AuditIssueSeverity severity)
    {
        if (severity == AuditIssueSeverity.HIGH) return VulnReport.Severity.HIGH;
        if (severity == AuditIssueSeverity.MEDIUM) return VulnReport.Severity.MEDIUM;
        if (severity == AuditIssueSeverity.LOW) return VulnReport.Severity.LOW;
        return VulnReport.Severity.MEDIUM;
    }

    private void notifyVulnFound()
    {
        if (callback != null)
        {
            try { callback.onVulnerabilityFound(); } catch (Exception ignored) {}
        }
    }

    // ==================== 扫描回调接口 ====================

    /**
     * 扫描结果回调 - 用于通知UI层更新。
     */
    public interface ScanCallback
    {
        void onVulnerabilityFound();
    }

    /**
     * 设置扫描回调（用于报告面板同步）。
     */
    public void setCallback(ScanCallback callback)
    {
        this.callback = callback;
    }

    // ==================== 内部类 ====================

    private static class PayloadEntry
    {
        String vulnType = "";
        String payload = "";
        String description = "";
        String expectedBehavior = "";
        String scope = "";
        String reproduceSteps = "";
    }

    private static class VerifyResult
    {
        final boolean vulnerable;
        final double confidence;
        final String reasoning;
        final String evidence;
        final String scope;
        final String reproduceSteps;

        VerifyResult(boolean vulnerable, double confidence, String reasoning,
            String evidence, String scope, String reproduceSteps)
        {
            this.vulnerable = vulnerable;
            this.confidence = confidence;
            this.reasoning = reasoning;
            this.evidence = evidence;
            this.scope = scope;
            this.reproduceSteps = reproduceSteps;
        }
    }
}
