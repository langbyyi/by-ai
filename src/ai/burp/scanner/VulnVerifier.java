package ai.burp.scanner;

import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import ai.burp.model.ChatMessage;
import ai.burp.model.VulnReport;
import ai.burp.provider.StreamingAIProvider;
import ai.burp.util.AiResponseParser;
import ai.burp.util.TextUtils;
import ai.burp.util.VulnFindingPolicy;

/**
 * 漏洞验证器：AI生成测试payload → 自动发送请求 → AI分析响应 → Collaborator回调检查 → 判定结果。
 */
public class VulnVerifier
{
    private final MontoyaApi api;
    private final StreamingAIProvider provider;
    private final AtomicBoolean cancelled = new AtomicBoolean(false);

    /** 每个漏洞最多测试的payload数量 */
    private static final int MAX_PAYLOADS_PER_VULN = 3;

    public VulnVerifier(MontoyaApi api, StreamingAIProvider provider)
    {
        this.api = api;
        this.provider = provider;
    }

    /**
     * 自动验证指定请求中可能存在的漏洞。
     *
     * @param originalReq 原始HTTP请求文本
     * @param originalResp 原始HTTP响应文本（可为空）
     * @param callback 验证进度回调
     * @param contextSecure 由 proxy 捕获时确定的 HTTPS 标志（来自 httpService().secure()）
     */
    public void verify(String originalReq, String originalResp, VerifyCallback callback, boolean contextSecure)
    {
        cancelled.set(false);
        final boolean finalContextSecure = contextSecure;

        try
        {
            // 阶段1：AI分析请求，识别可能的漏洞
            callback.onProgress("AI 正在分析请求，识别可能的漏洞类型...");
            List<VulnReport> potentialVulns = identifyVulnerabilities(originalReq, originalResp);
            if (potentialVulns.isEmpty())
            {
                callback.onComplete(potentialVulns, "未发现明显漏洞");
                return;
            }

            callback.onProgress("发现 " + potentialVulns.size() + " 个潜在漏洞，开始验证...");

            // 从原始请求提取 url/method/host，补全到所有潜在漏洞
            String[] firstLine = originalReq.split("\r?\n", 2);
            String[] reqParts = firstLine[0].split(" ");
            String method = reqParts.length > 0 ? reqParts[0] : "GET";
            String path = reqParts.length > 1 ? reqParts[1] : "/";
            String host = null;
            for (String line : originalReq.split("\r?\n"))
            {
                if (line.toLowerCase().startsWith("host:"))
                {
                    host = line.substring(5).trim();
                    break;
                }
                if (line.isEmpty()) break;
            }
            boolean secure = contextSecure || path.toLowerCase().startsWith("https://") || originalReq.contains("https://");
            String url;
            if (path.startsWith("http://") || path.startsWith("https://"))
            {
                url = path;
            }
            else
            {
                url = (secure ? "https://" : "http://") + (host != null ? host : "unknown") + path;
            }

            for (VulnReport vuln : potentialVulns)
            {
                if (vuln.getUrl() == null || vuln.getUrl().isEmpty()) vuln.setUrl(url);
                if (vuln.getMethod() == null || vuln.getMethod().isEmpty()) vuln.setMethod(method);
                if (vuln.getHost() == null || vuln.getHost().isEmpty()) vuln.setHost(host);
                vuln.setOriginalRequest(originalReq);
                vuln.setOriginalResponse(originalResp);
            }
            potentialVulns = VulnFindingPolicy.keepTopOnePerRequest(potentialVulns);

            // 阶段2：对每个漏洞进行验证
            for (int i = 0; i < potentialVulns.size(); i++)
            {
                if (cancelled.get()) break;

                VulnReport vuln = potentialVulns.get(i);
                callback.onProgress("正在验证 #" + (i + 1) + ": " + vuln.getVulnType() + " (" + vuln.getParameter() + ")");

                verifySingleVuln(vuln, originalReq, originalResp, finalContextSecure);
            }

            int confirmed = 0;
            for (VulnReport v : potentialVulns)
            {
                if (v.getVerifyStatus() == VulnReport.VerifyStatus.CONFIRMED) confirmed++;
            }

            String summary = "验证完成: " + confirmed + " 个已确认, "
                + (potentialVulns.size() - confirmed) + " 个未确认或误报";
            callback.onComplete(potentialVulns, summary);
        }
        catch (Exception e)
        {
            callback.onError("验证过程出错: " + e.getMessage());
        }
    }

    /**
     * AI识别请求中可能存在的漏洞。
     */
    private List<VulnReport> identifyVulnerabilities(String request, String response) throws Exception
    {
        String prompt = "你是专业的Web安全测试专家。请按照以下结构化流程分析HTTP交换中的安全漏洞。\n\n"
            + "## 分析步骤\n"
            + "1. 识别所有用户可控参数（URL参数、POST body、Cookie、HTTP头）\n"
            + "2. 对每个参数评估：参数值是否被后端处理（数据库/文件/命令/模板）？\n"
            + "3. 在响应中寻找漏洞直接证据：错误信息、异常堆栈、敏感数据泄露、异常行为\n"
            + "4. 仅报告有直接证据支持且 confidence >= 0.6 的发现\n"
            + "5. 仅报告同时满足三条件的漏洞：可复现（能稳定重放得到一致结果）、"
            + "可利用（存在明确利用路径而非理论可能）、有实际危害（能造成数据泄露/权限提升/业务破坏等真实影响）。缺一不报。\n\n"
            + "## 反幻觉规则\n"
            + "- 参数名为id不等于存在IDOR，需有权限差异的直接证据\n"
            + "- 参数值为字符串不等于存在SQL注入，需有SQL错误等直接证据\n"
            + "- 响应正常(200+无异常)的参数不要强行报告漏洞\n"
            + "- 优先报告高风险类型(SQL注入/RCE/SSRF)而非低风险类型(信息泄露)\n"
            + "- 单个请求最多只返回1个最有价值、证据最强、最接近根因的漏洞\n"
            + "- 不要同时返回「信息泄露」「配置不当」「安全头缺失」「版本暴露」等泛化低价值项\n"
            + "- 仅当响应中直接出现凭证/token/密钥/敏感文件/堆栈等高价值内容时，才允许报告信息泄露类问题\n\n"
            + "严格按以下JSON数组格式返回，不要包含其他文字：\n"
            + "[{\"vulnType\":\"SQL注入\",\"parameter\":\"username\",\"severity\":\"高\","
            + "\"description\":\"参数未过滤\",\"suggestion\":\"使用参数化查询\","
            + "\"evidence\":\"响应包含SQL错误\",\"confidence\":0.8}]\n\n"
            + "如果没有发现漏洞，返回空数组 []。\n\n"
            + getOobContext()
            + "---请求---\n" + TextUtils.truncateWithSuffix(request, 6000, "\n... [已截断]") + "\n\n"
            + (response != null && !response.isEmpty()
                ? "---响应---\n" + TextUtils.truncateWithSuffix(response, 4000, "\n... [已截断]") + "\n"
                : "");

        String aiResponse = provider.chat(Collections.singletonList(ChatMessage.user(prompt)));
        return parseVulnReports(aiResponse);
    }

    /**
     * 验证单个漏洞：生成payload → 发送 → 分析响应。
     */
    private void verifySingleVuln(VulnReport vuln, String originalReq, String originalResp, boolean contextSecure) throws Exception
    {
        // 1. AI生成测试payload
        String payloadPrompt = "针对在以下请求的 " + vuln.getParameter() + " 参数上可能存在的 "
            + vuln.getVulnType() + " 漏洞，生成 " + MAX_PAYLOADS_PER_VULN + " 个用于验证的HTTP请求。\n\n"
            + "## Payload生成策略\n"
            + "1. 第一个payload：最直接的验证方式（如SQL注入用' OR '1'='1，XSS用<script>alert(1)</script>）\n"
            + "2. 第二个payload：变体测试（不同的注入语法或绕过技术）\n"
            + "3. 第三个payload：如果前两种可能被过滤，使用编码/混淆绕过变体\n\n"
            + "## 约束\n"
            + "- payload要求有回显验证，不要只测引号报错：SQL注入用UNION SELECT回显version()/database()，或报错注入extractvalue/updatexml\n"
            + "- XSS测试确认payload在响应体中原样回显\n"
            + "- 保留原始请求的Host、Cookie、Authorization等认证信息\n"
            + "- 只修改目标参数的值，其他参数保持不变\n\n"
            + "严格按以下JSON数组格式返回：\n"
            + "[{\"method\":\"POST\",\"path\":\"/api/login\","
            + "\"headers\":{\"Content-Type\":\"application/x-www-form-urlencoded\"},"
            + "\"body\":\"username=test&password=test\"}]\n\n"
            + getOobContext()
            + "---原始请求---\n" + TextUtils.truncateWithSuffix(originalReq, 4000, "\n... [已截断]");

        String payloadResponse = provider.chat(Collections.singletonList(ChatMessage.user(payloadPrompt)));
        List<Map<String, Object>> payloads = parsePayloads(payloadResponse);

        // 2. 逐个发送测试请求
        for (Map<String, Object> payload : payloads)
        {
            if (cancelled.get()) return;

            try
            {
                HttpRequest testReq = buildTestRequest(originalReq, payload, contextSecure);
                if (testReq == null) continue;

                HttpRequestResponse testResult = api.http().sendRequest(testReq);

                if (testResult.hasResponse())
                {
                    String testResp = TextUtils.toStringUtf8(testResult.response());

                    // 3. AI分析响应
                    VulnReport.VerifyStatus status = analyzeVerification(
                        originalResp, testResp, vuln.getVulnType());

                    if (status == VulnReport.VerifyStatus.CONFIRMED)
                    {
                        vuln.setVerifyStatus(VulnReport.VerifyStatus.CONFIRMED);
                        String payloadBody = payload.containsKey("body") ? String.valueOf(payload.get("body")) : testReq.toString();
                        vuln.setVerificationDetail("AI判定: 漏洞存在。测试payload: " + payloadBody);
                        vuln.setOriginalRequest(originalReq);
                        vuln.setReproduceRequest(testReq.toString());   // 完整的可复现测试请求
                        vuln.setTestPayload(payloadBody);
                        vuln.setTestResponse(testResp);

                        // 发送到Repeater供手动复现
                        try
                        {
                            api.repeater().sendToRepeater(testReq, "AI验证: " + vuln.getVulnType());
                        }
                        catch (Exception ignored) {}

                        return;
                    }
                }
            }
            catch (Exception ignored)
            {
                // 单个请求失败不影响其他测试
            }
        }

        vuln.setVerifyStatus(VulnReport.VerifyStatus.UNVERIFIED);

        // 阶段3：对 OOB 类型漏洞（盲注/SSRF/XXE），检查 Collaborator 回调
        if (vuln.getVerifyStatus() != VulnReport.VerifyStatus.CONFIRMED
            && isOobVulnType(vuln.getVulnType()))
        {
            checkCollaboratorCallback(vuln);
        }
    }

    /**
     * 判断漏洞类型是否属于 OOB 带外验证类型。
     */
    private boolean isOobVulnType(String vulnType)
    {
        if (vulnType == null) return false;
        String lower = vulnType.toLowerCase();
        return lower.contains("ssrf")
            || lower.contains("xxe")
            || lower.contains("盲注")
            || lower.contains("blind")
            || lower.contains("命令注入")
            || lower.contains("command")
            || lower.contains("log4")
            || lower.contains("jndi");
    }

    /**
     * 检查 Collaborator 是否收到了带外交互回调。
     * 等待目标触发回调后查询，如果发现交互则确认漏洞存在。
     */
    private void checkCollaboratorCallback(VulnReport vuln)
    {
        try
        {
            // 记录当前已有的交互数量作为基线，避免将历史回调误判为本次测试触发的回调
            int baselineCount = CollaboratorHelper.checkOobInteractions().size();

            // 等待目标触发 OOB 回调（网络延迟）
            Thread.sleep(3000);

            int afterCount = CollaboratorHelper.checkOobInteractions().size();
            if (afterCount > baselineCount)
            {
                String summary = CollaboratorHelper.getOobInteractionSummary();
                vuln.setVerifyStatus(VulnReport.VerifyStatus.CONFIRMED);
                vuln.setVerificationDetail("OOB带外验证成功: " + summary);
            }
        }
        catch (InterruptedException e)
        {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * AI分析原始响应与测试响应的差异，判定漏洞是否存在。
     */
    private VulnReport.VerifyStatus analyzeVerification(
        String originalResp, String testResp, String vulnType) throws Exception
    {
        String prompt = "判断以下漏洞验证是否成功。请严格对比原始响应和测试响应的差异。\n\n"
            + "漏洞类型: " + vulnType + "\n\n"
            + "## 判断依据（按优先级）\n"
            + "1. 测试响应中出现漏洞特征的直接证据（如SQL错误、命令输出、文件内容）→ vulnerable=true, confidence>=0.9\n"
            + "2. 测试响应与原始响应有显著差异（状态码变化/长度变化>20%/内容关键字差异）→ vulnerable=true, confidence>=0.7\n"
            + "3. 测试响应被WAF拦截(403/block/denied) → 无法确认，vulnerable=false但标注WAF\n"
            + "4. 测试响应与原始响应几乎相同 → vulnerable=false\n\n"
            + "---原始响应---\n" + TextUtils.truncateWithSuffix(originalResp != null ? originalResp : "", 2000, "\n... [已截断]") + "\n\n"
            + "---测试响应---\n" + TextUtils.truncateWithSuffix(testResp, 2000, "\n... [已截断]") + "\n\n"
            + "严格按以下JSON格式返回：\n"
            + "{\"vulnerable\":true,\"confidence\":0.9,\"reasoning\":\"响应中出现了...\"}\n"
            + "confidence >= 0.7 才判定为漏洞存在。\n"
            + "判定前提：漏洞必须可复现、可利用、有实际危害，缺一则 vulnerable 设为 false。";

        String aiResponse = provider.chat(Collections.singletonList(ChatMessage.user(prompt)));

        try
        {
            Map<String, Object> result = AiResponseParser.parseFirstObject(aiResponse);
            if (AiResponseParser.getBoolean(result, "vulnerable", false)
                && AiResponseParser.getDouble(result, "confidence", 0.0) >= 0.7)
            {
                return VulnReport.VerifyStatus.CONFIRMED;
            }
        }
        catch (Exception ignored) {}

        return VulnReport.VerifyStatus.FALSE_POSITIVE;
    }

    /**
     * 根据AI返回的payload构建HttpRequest。
     */
    private HttpRequest buildTestRequest(String originalReq, Map<String, Object> payload, boolean contextSecure)
    {
        try
        {
            // 从原始请求提取目标信息
            String[] lines = originalReq.split("\r?\n", 2);
            String requestLine = lines[0];
            String[] parts = requestLine.split(" ");
            if (parts.length < 3) return null;

            String originalMethod = parts[0];
            String originalPath = parts[1];

            String method = payload.containsKey("method")
                ? String.valueOf(payload.get("method")) : originalMethod;
            String path = payload.containsKey("path")
                ? String.valueOf(payload.get("path")) : originalPath;
            String body = payload.containsKey("body")
                ? String.valueOf(payload.get("body")) : "";

            // 构建原始HTTP请求文本
            StringBuilder rawReq = new StringBuilder();
            rawReq.append(method).append(" ").append(path).append(" HTTP/1.1\r\n");

            // 从原始请求中提取Host
            for (String line : originalReq.split("\r?\n"))
            {
                if (line.toLowerCase().startsWith("host:"))
                {
                    rawReq.append(line).append("\r\n");
                    break;
                }
            }

            // 添加AI生成的headers
            Object headersObj = payload.get("headers");
            if (headersObj instanceof Map)
            {
                @SuppressWarnings("unchecked")
                Map<String, Object> headers = (Map<String, Object>) headersObj;
                for (Map.Entry<String, Object> e : headers.entrySet())
                {
                    rawReq.append(e.getKey()).append(": ").append(e.getValue()).append("\r\n");
                }
            }

            if (!body.isEmpty())
            {
                rawReq.append("Content-Length: ").append(body.getBytes("UTF-8").length).append("\r\n");
            }

            rawReq.append("\r\n");
            if (!body.isEmpty())
            {
                rawReq.append(body);
            }

            // 从原始请求推断服务
            String host = null;
            boolean secure = contextSecure;
            for (String line : originalReq.split("\r?\n"))
            {
                if (line.toLowerCase().startsWith("host:"))
                {
                    host = line.substring(5).trim();
                    break;
                }
            }

            if (!secure && (originalReq.startsWith("CONNECT") || originalReq.contains("https://")))
            {
                secure = true;
            }

            if (host != null)
            {
                int port = secure ? 443 : 80;
                if (host.contains(":"))
                {
                    String[] hp = host.split(":");
                    host = hp[0];
                    port = Integer.parseInt(hp[1]);
                }
                if (!secure && (port == 443 || port == 8443))
                {
                    secure = true;
                }
                HttpService service = HttpService.httpService(host, port, secure);
                return HttpRequest.httpRequest(service, rawReq.toString());
            }

            // host == null 时，尝试从 URL 路径中解析 host
            try
            {
                String urlStr = originalPath;
                if (urlStr.startsWith("http://") || urlStr.startsWith("https://"))
                {
                    java.net.URI uri = new java.net.URI(urlStr);
                    if (uri.getHost() != null)
                    {
                        boolean s = "https".equalsIgnoreCase(uri.getScheme());
                        int p = uri.getPort() > 0 ? uri.getPort() : (s ? 443 : 80);
                        HttpService service = HttpService.httpService(uri.getHost(), p, s);
                        return HttpRequest.httpRequest(service, rawReq.toString());
                    }
                }
            }
            catch (Exception ignored) {}

            return HttpRequest.httpRequest(rawReq.toString());
        }
        catch (Exception e)
        {
            return null;
        }
    }

    // ==================== 辅助方法 ====================

    private List<VulnReport> parseVulnReports(String aiResponse)
    {
        List<VulnReport> reports = new ArrayList<>();
        try
        {
            for (Map<String, Object> m : AiResponseParser.parseFirstObjectArray(aiResponse))
            {
                VulnReport r = new VulnReport();
                r.setVulnType(AiResponseParser.getString(m, "vulnType"));
                r.setParameter(AiResponseParser.getString(m, "parameter"));
                r.setDescription(AiResponseParser.getString(m, "description"));
                r.setSuggestion(AiResponseParser.getString(m, "suggestion"));
                r.setEvidence(AiResponseParser.getString(m, "evidence"));
                r.setSeverity(VulnReport.Severity.fromString(AiResponseParser.getString(m, "severity")));
                r.setConfidence(AiResponseParser.getDouble(m, "confidence", 0.0));
                reports.add(r);
            }
        }
        catch (Exception ignored) {}
        return reports;
    }

    private List<Map<String, Object>> parsePayloads(String aiResponse)
    {
        List<Map<String, Object>> payloads = new ArrayList<>();
        try
        {
            int count = 0;
            for (Map<String, Object> item : AiResponseParser.parseFirstObjectArray(aiResponse))
            {
                if (count >= MAX_PAYLOADS_PER_VULN) break;
                payloads.add(item);
                count++;
            }
        }
        catch (Exception ignored) {}
        return payloads;
    }

    public void cancel()
    {
        cancelled.set(true);
    }

    /**
     * 验证回调接口。
     */
    public interface VerifyCallback
    {
        void onProgress(String message);
        void onComplete(List<VulnReport> results, String summary);
        void onError(String message);
    }

    /**
     * 构建 OOB 带外测试域名的上下文片段。
     */
    private static String getOobContext()
    {
        String oob = FullVulnDatabase.getOobDomain();
        if (oob == null || oob.isEmpty())
        {
            return "";
        }
        return "重要：当前可用的带外测试(OOB)域名为 " + oob
            + "。生成SSRF、XXE等带外验证payload时必须使用此域名。\n\n";
    }
}
