package ai.burp.scanner;

import java.net.URI;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.TimingData;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import ai.burp.model.ChatMessage;
import ai.burp.model.VulnReport;
import ai.burp.provider.StreamingAIProvider;
import ai.burp.util.AiResponseParser;
import ai.burp.util.TargetScopeMatcher;
import ai.burp.util.SimpleJson;
import ai.burp.util.TextUtils;
import ai.burp.util.VulnFindingPolicy;

/**
 * 流量分析引擎 - 批量分析代理历史中的HTTP请求/响应。
 * v2: 高级过滤、上下文累积、会话流追踪、智能优先级排序。
 */
public class TrafficAnalyzer
{
    private final MontoyaApi api;
    private final StreamingAIProvider provider;
    private final AtomicBoolean cancelled = new AtomicBoolean(false);

    /** 流量分析每批请求数。 */
    private static final int FIXED_BATCH_SIZE = 20;
    private static final int MAX_AUTO_VERIFY_PER_RUN = 5;

    /** 上下文累积最大字符数，防止超出模型 token 限制 */
    private static final int MAX_ACCUMULATED_CONTEXT_CHARS = 8000;

    private boolean autoVerifyEnabled = false;

    // ===== API调用频率限制 =====
    private int rateLimitMs = 2000;
    private final AtomicLong lastApiCallTime = new AtomicLong(0);

    // ===== 过滤条件 =====
    private String hostFilter = "";
    private String methodFilter = "";
    private String statusCodeFilter = "";
    private String keywordFilter = "";
    private TargetScopeMatcher targetScopeMatcher = TargetScopeMatcher.disabled();

    // ===== 上下文累积 =====
    private final StringBuilder accumulatedContext = new StringBuilder();
    private final Set<String> seenVulnSignatures = Collections.synchronizedSet(new LinkedHashSet<>());

    // ===== 会话流追踪 =====
    private final Map<String, List<String>> hostSessions = Collections.synchronizedMap(new LinkedHashMap<>());
    private final Map<String, Set<String>> hostCookies = Collections.synchronizedMap(new LinkedHashMap<>());

    // ===== 请求发送回调（同步到 AI 请求页面） =====
    private RequestSentCallback requestSentCallback;

    @FunctionalInterface
    public interface RequestSentCallback
    {
        void onRequestSent(String requestText, String responseText,
            String host, String method, int statusCode, long durationMs);
    }

    public void setRequestSentCallback(RequestSentCallback callback)
    {
        this.requestSentCallback = callback;
    }

    public TrafficAnalyzer(MontoyaApi api, StreamingAIProvider provider)
    {
        this.api = api;
        this.provider = provider;
    }

    // ===== 过滤器设置 =====

    public void setHostFilter(String hostFilter) { this.hostFilter = hostFilter != null ? hostFilter.trim() : ""; }
    public void setMethodFilter(String methodFilter) { this.methodFilter = methodFilter != null ? methodFilter.trim() : ""; }
    public void setStatusCodeFilter(String statusCodeFilter) { this.statusCodeFilter = statusCodeFilter != null ? statusCodeFilter.trim() : ""; }
    public void setKeywordFilter(String keywordFilter) { this.keywordFilter = keywordFilter != null ? keywordFilter.trim() : ""; }
    public void setTargetScope(TargetScopeMatcher matcher)
    {
        this.targetScopeMatcher = matcher != null ? matcher : TargetScopeMatcher.disabled();
    }

    public void setAutoVerifyEnabled(boolean enabled)
    {
        this.autoVerifyEnabled = enabled;
    }

    /**
     * 设置API调用频率限制（两次调用之间的最小间隔毫秒数）。
     */
    public void setRateLimitMs(int ms)
    {
        this.rateLimitMs = Math.max(0, ms);
    }

    /**
     * 频率限制：确保两次API调用之间至少间隔 rateLimitMs 毫秒。
     */
    private void enforceRateLimit()
    {
        if (rateLimitMs <= 0) return;
        long now = System.currentTimeMillis();
        long last = lastApiCallTime.get();
        long elapsed = now - last;
        if (elapsed < rateLimitMs)
        {
            try
            {
                Thread.sleep(rateLimitMs - elapsed);
            }
            catch (InterruptedException e)
            {
                Thread.currentThread().interrupt();
            }
        }
        lastApiCallTime.set(System.currentTimeMillis());
    }

    /**
     * 分析代理历史记录。
     */
    public void analyzeHistory(int maxCount, String focusType, AnalysisCallback callback)
    {
        cancelled.set(false);
        accumulatedContext.setLength(0);
        seenVulnSignatures.clear();
        hostSessions.clear();
        hostCookies.clear();

        try
        {
            // 获取代理历史
            List<ProxyHttpRequestResponse> history = api.proxy().history();
            if (history.isEmpty())
            {
                callback.onNoData();
                return;
            }

            // 去重
            List<ProxyHttpRequestResponse> targets = deduplicate(history, maxCount);

            // 应用高级过滤
            targets = applyFilters(targets);

            if (targets.isEmpty())
            {
                callback.onNoData();
                return;
            }

            // 智能排序：可疑请求优先
            targets = smartSort(targets);

            callback.onStarted(targets.size());

            List<VulnReport> allResults = Collections.synchronizedList(new ArrayList<>());
            List<List<ProxyHttpRequestResponse>> batches = buildFixedBatches(targets);
            int totalBatches = batches.size();
            AtomicInteger verifyCount = new AtomicInteger(0);

            for (int batch = 0; batch < totalBatches; batch++)
            {
                if (cancelled.get()) break;

                final int batchIndex = batch;
                final List<ProxyHttpRequestResponse> batchTargets = new ArrayList<>(batches.get(batch));
                int from = countItemsBeforeBatch(batches, batchIndex) + 1;
                int to = from + batchTargets.size() - 1;

                String batchInfo = "正在分析第 " + (from) + "-" + to + " 条 (共 "
                    + targets.size() + " 条, 当前批 " + batchTargets.size() + " 条)";
                callback.onProgress(batchInfo);
                callback.onBatchSubmitted(batchIndex + 1, totalBatches, from, to, batchTargets);

                // 更新会话流追踪（在提交线程任务前同步更新）
                updateSessionFlow(batchTargets);

                // 频率限制
                enforceRateLimit();

                // 构造分析prompt（带上下文累积）
                String prompt = buildBatchPromptWithContext(batchTargets, focusType, batchIndex, totalBatches);

                try
                {
                    callback.onProgress("批次 " + (batchIndex + 1) + "/" + totalBatches
                        + " 已提交到 AI，等待响应...");
                    StringBuilder fullResponse = new StringBuilder();
                    AtomicBoolean firstTokenReceived = new AtomicBoolean(false);
                    provider.chatStream(
                        Collections.singletonList(ChatMessage.user(prompt)),
                        new StreamingAIProvider.StreamCallback()
                        {
                            @Override
                            public void onToken(String token)
                            {
                                if (firstTokenReceived.compareAndSet(false, true))
                                {
                                    callback.onProgress("批次 " + (batchIndex + 1) + "/" + totalBatches
                                        + " 已收到 AI 响应，正在解析...");
                                }
                                fullResponse.append(token);
                                callback.onStreamToken(token);
                            }

                            @Override
                            public void onComplete(String fullResp)
                            {
                                if (cancelled.get())
                                {
                                    return;
                                }
                                List<VulnReport> batchResults = parseAnalysisResults(fullResp, batchTargets);
                                if (autoVerifyEnabled)
                                {
                                    autoVerifyReports(batchResults, verifyCount, callback);
                                }
                                allResults.addAll(batchResults);
                                accumulateContext(batchResults, batchTargets);
                                for (VulnReport r : batchResults)
                                {
                                    callback.onVulnFound(r);
                                }
                                callback.onBatchComplete(batchIndex + 1, totalBatches, batchResults, batchTargets);
                                callback.onProgress("批次 " + (batchIndex + 1) + "/" + totalBatches
                                    + " 分析完成，发现 " + batchResults.size() + " 个风险点。");
                            }

                            @Override
                            public void onError(Exception e)
                            {
                                if (!cancelled.get())
                                {
                                    callback.onBatchFailed(batchIndex + 1, totalBatches, batchTargets,
                                        e.getMessage());
                                }
                                callback.onProgress("分析出错: " + e.getMessage());
                            }
                        }
                    );
                }
                catch (Exception e)
                {
                    if (!cancelled.get())
                    {
                        callback.onBatchFailed(batchIndex + 1, totalBatches, batchTargets, e.getMessage());
                    }
                    callback.onProgress("批次 " + (batchIndex + 1) + " 分析失败: " + e.getMessage());
                }
            }

            // 按严重性排序
            synchronized (allResults)
            {
                allResults.sort((a, b) -> b.getSeverity().level() - a.getSeverity().level());
            }
            callback.onComplete(allResults);
        }
        catch (Exception e)
        {
            callback.onError("分析过程出错: " + e.getMessage());
        }
    }

    /**
     * 生成分析摘要文本，用于注入聊天会话。
     */
    public String generateAnalysisSummary(List<VulnReport> results)
    {
        StringBuilder sb = new StringBuilder();
        sb.append("# 流量分析报告\n\n");
        sb.append("## 总览\n");
        sb.append("- 共发现风险点: ").append(results.size()).append(" 个\n");

        // 按严重性统计
        Map<VulnReport.Severity, Integer> severityCount = new EnumMap<>(VulnReport.Severity.class);
        Map<String, Integer> typeCount = new LinkedHashMap<>();
        Map<String, Integer> hostCount = new LinkedHashMap<>();

        for (VulnReport r : results)
        {
            severityCount.merge(r.getSeverity(), 1, Integer::sum);
            typeCount.merge(r.getVulnType(), 1, Integer::sum);
            String host = extractHost(r.getUrl());
            if (host != null) hostCount.merge(host, 1, Integer::sum);
        }

        sb.append("- 严重性分布: ");
        for (VulnReport.Severity sev : VulnReport.Severity.values())
        {
            int c = severityCount.getOrDefault(sev, 0);
            if (c > 0) sb.append(sev.label()).append("=").append(c).append(" ");
        }
        sb.append("\n");

        if (!typeCount.isEmpty())
        {
            sb.append("- 漏洞类型: ");
            typeCount.entrySet().stream()
                .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                .limit(5)
                .forEach(e -> sb.append(e.getKey()).append("(").append(e.getValue()).append(") "));
            sb.append("\n");
        }

        sb.append("\n## 详细发现\n\n");
        for (int i = 0; i < results.size(); i++)
        {
            VulnReport r = results.get(i);
            sb.append("### 发现 #").append(i + 1).append("\n");
            sb.append(r.toChatContext()).append("\n\n");
        }

        // 附加会话流摘要
        if (!hostSessions.isEmpty())
        {
            sb.append("## 会话流追踪\n\n");
            for (Map.Entry<String, List<String>> entry : hostSessions.entrySet())
            {
                if (entry.getValue().size() > 1)
                {
                    sb.append("- ").append(entry.getKey()).append(": ").append(entry.getValue().size())
                        .append(" 个请求，Cookie变化 ").append(hostCookies.getOrDefault(entry.getKey(), Collections.emptySet()).size())
                        .append(" 次\n");
                }
            }
            sb.append("\n");
        }

        // 附加攻击链关联分析
        String attackChains = analyzeAttackChains(results);
        if (attackChains != null && !attackChains.isEmpty())
        {
            sb.append(attackChains);
        }

        return sb.toString();
    }

    public void cancel()
    {
        cancelled.set(true);
        provider.stopStreaming();
    }

    // ==================== 过滤逻辑 ====================

    private List<ProxyHttpRequestResponse> applyFilters(List<ProxyHttpRequestResponse> targets)
    {
        List<ProxyHttpRequestResponse> filtered = new ArrayList<>(targets);

        // 域名过滤
        if (targetScopeMatcher != null && targetScopeMatcher.isEnabled())
        {
            filtered.removeIf(item -> !targetScopeMatcher.matchesHost(resolveRequestHost(item)));
        }

        if (!hostFilter.isEmpty())
        {
            String hf = hostFilter.toLowerCase();
            filtered.removeIf(item ->
            {
                String host = resolveRequestHost(item);
                return !host.toLowerCase().contains(hf);
            });
        }

        // 方法过滤
        if (!methodFilter.isEmpty() && !"全部".equals(methodFilter))
        {
            filtered.removeIf(item -> !methodFilter.equalsIgnoreCase(item.finalRequest().method()));
        }

        // 状态码过滤
        if (!statusCodeFilter.isEmpty())
        {
            filtered.removeIf(item ->
            {
                if (!item.hasResponse()) return true;
                String statusLine = item.response().statusCode() + "";
                return !matchesStatusCode(statusLine, statusCodeFilter);
            });
        }

        // 关键词过滤
        if (!keywordFilter.isEmpty())
        {
            String kw = keywordFilter.toLowerCase();
            filtered.removeIf(item ->
            {
                String req = item.finalRequest().toString().toLowerCase();
                String resp = item.hasResponse() ? TextUtils.toStringUtf8(item.response()).toLowerCase() : "";
                return !req.contains(kw) && !resp.contains(kw);
            });
        }

        return filtered;
    }

    private boolean matchesStatusCode(String actualCode, String filter)
    {
        // 支持 "200", "4xx", "2xx,3xx" 等格式
        String[] parts = filter.split(",");
        for (String part : parts)
        {
            String p = part.trim();
            if (p.length() == 3 && p.endsWith("xx"))
            {
                String prefix = p.substring(0, 1);
                if (actualCode.startsWith(prefix)) return true;
            }
            else if (actualCode.equals(p))
            {
                return true;
            }
        }
        return false;
    }

    private String resolveRequestHost(ProxyHttpRequestResponse item)
    {
        try
        {
            String host = item.finalRequest().httpService().host();
            int port = item.finalRequest().httpService().port();
            if (host == null || host.isEmpty()) return "";
            return host + ":" + port;
        }
        catch (Exception e)
        {
            String host = item.finalRequest().headerValue("Host");
            return host == null ? "" : host;
        }
    }

    // ==================== 智能排序 ====================

    private List<ProxyHttpRequestResponse> smartSort(List<ProxyHttpRequestResponse> targets)
    {
        List<ScoredEntry> scored = new ArrayList<>();
        for (ProxyHttpRequestResponse item : targets)
        {
            int score = computeSuspicionScore(item);
            scored.add(new ScoredEntry(item, score));
        }
        scored.sort((a, b) -> b.score - a.score);

        List<ProxyHttpRequestResponse> result = new ArrayList<>();
        for (ScoredEntry se : scored) result.add(se.item);
        return result;
    }

    private int computeSuspicionScore(ProxyHttpRequestResponse item)
    {
        int score = 0;
        String request = item.finalRequest().toString().toLowerCase();
        String response = item.hasResponse() ? TextUtils.toStringUtf8(item.response()).toLowerCase() : "";

        // POST/PUT/DELETE 比GET更可能有问题
        String method = item.finalRequest().method().toUpperCase();
        if ("POST".equals(method)) score += 3;
        else if ("PUT".equals(method) || "DELETE".equals(method)) score += 5;

        // 参数数量
        String url = item.finalRequest().url();
        int paramCount = countChar(url, '&') + countChar(url, '=');
        score += Math.min(paramCount, 10);

        // 响应中的可疑信号
        if (response.contains("error") || response.contains("exception")) score += 5;
        if (response.contains("sql") && response.contains("syntax")) score += 8;
        if (response.contains("stack") && response.contains("trace")) score += 6;
        if (response.contains("permission") || response.contains("denied")) score += 4;
        if (response.contains("admin") || response.contains("debug")) score += 3;

        // 认证相关
        if (request.contains("authorization") || request.contains("cookie")
            || request.contains("token") || request.contains("session"))
        {
            score += 3;
        }

        // 文件上传
        if (request.contains("multipart/form-data") || request.contains("upload")
            || request.contains("filename="))
        {
            score += 5;
        }

        // 状态码异常
        if (item.hasResponse())
        {
            int statusCode = item.response().statusCode();
            if (statusCode >= 500) score += 5;
            else if (statusCode == 403) score += 4;
            else if (statusCode == 401) score += 3;
        }

        // 时序异常：基于 Burp 原生 TimingData
        score += computeTimingScore(item);

        return score;
    }

    private int countChar(String s, char c)
    {
        int count = 0;
        for (int i = 0; i < s.length(); i++)
        {
            if (s.charAt(i) == c) count++;
        }
        return count;
    }

    // ==================== 会话流追踪 ====================

    private void updateSessionFlow(List<ProxyHttpRequestResponse> batch)
    {
        for (ProxyHttpRequestResponse item : batch)
        {
            String host = item.httpService().host();
            String url = item.finalRequest().url();

            hostSessions.computeIfAbsent(host, k -> new ArrayList<>()).add(
                item.finalRequest().method() + " " + simplifyUrl(url));

            // 追踪Cookie变化
            if (item.hasResponse())
            {
                String response = TextUtils.toStringUtf8(item.response());
                for (String line : response.split("\r\n"))
                {
                    if (line.toLowerCase().startsWith("set-cookie:"))
                    {
                        String cookieName = line.substring(11).trim().split("=")[0].trim();
                        hostCookies.computeIfAbsent(host, k -> new LinkedHashSet<>()).add(cookieName);
                    }
                }
            }
        }
    }

    private String simplifyUrl(String url)
    {
        int q = url.indexOf('?');
        return q >= 0 ? url.substring(0, q) : url;
    }

    // ==================== 固定分批 ====================

    private List<List<ProxyHttpRequestResponse>> buildFixedBatches(List<ProxyHttpRequestResponse> targets)
    {
        List<List<ProxyHttpRequestResponse>> batches = new ArrayList<>();
        for (int i = 0; i < targets.size(); i += FIXED_BATCH_SIZE)
        {
            int end = Math.min(i + FIXED_BATCH_SIZE, targets.size());
            batches.add(new ArrayList<>(targets.subList(i, end)));
        }
        return batches;
    }

    private int countItemsBeforeBatch(List<List<ProxyHttpRequestResponse>> batches, int batchIndex)
    {
        int count = 0;
        for (int i = 0; i < batchIndex; i++)
        {
            count += batches.get(i).size();
        }
        return count;
    }

    // ==================== 上下文累积 ====================

    private void accumulateContext(List<VulnReport> batchResults, List<ProxyHttpRequestResponse> batch)
    {
        synchronized (accumulatedContext)
        {
            for (VulnReport r : batchResults)
            {
                String sig = r.getVulnType() + "|" + r.getUrl() + "|" + r.getParameter();
                if (!seenVulnSignatures.contains(sig))
                {
                    seenVulnSignatures.add(sig);
                    accumulatedContext.append("- [").append(r.getSeverity().label()).append("] ")
                        .append(r.getVulnType()).append(": ").append(r.getUrl())
                        .append(" (").append(r.getParameter()).append(")\n");
                }
            }

            // 防止累积上下文超出模型 token 限制：截断最早的条目
            if (accumulatedContext.length() > MAX_ACCUMULATED_CONTEXT_CHARS)
            {
                String truncated = accumulatedContext.toString();
                // 保留最后的条目（最新的发现更重要）
                int keepFrom = truncated.length() - MAX_ACCUMULATED_CONTEXT_CHARS;
                int newlinePos = truncated.indexOf('\n', keepFrom);
                if (newlinePos > 0) keepFrom = newlinePos + 1;
                accumulatedContext.setLength(0);
                accumulatedContext.append("...(更早的发现已省略)\n").append(truncated.substring(keepFrom));
            }
        }
    }

    // ==================== Prompt构建 ====================

    private String buildBatchPromptWithContext(List<ProxyHttpRequestResponse> batch,
        String focusType, int batchIndex, int totalBatches)
    {
        StringBuilder sb = new StringBuilder();
        sb.append("你是资深Web安全审计员。请按结构化流程分析以下HTTP交换的安全风险。\n");

        if (focusType != null && !focusType.isEmpty() && !"全部".equals(focusType))
        {
            sb.append("重点关注: ").append(focusType).append("\n");
        }

        // ===== 技术感知 Prompt：检查 TechFingerprint 缓存 =====
        String techHint = buildTechAwarePrompt(batch);
        if (techHint != null && !techHint.isEmpty())
        {
            sb.append("\n## 目标技术栈识别\n");
            sb.append(techHint).append("\n");
        }

        // 注入累积上下文（第2批开始），读取时同步
        String contextSnapshot;
        synchronized (accumulatedContext)
        {
            contextSnapshot = accumulatedContext.length() > 0 ? accumulatedContext.toString() : null;
        }
        if (batchIndex > 0 && contextSnapshot != null)
        {
            sb.append("\n## 前序批次已发现的风险（不要重复报告相同的发现）:\n");
            sb.append(contextSnapshot);
            sb.append("\n请关注新的、未报告过的风险点，特别是与前序发现可能关联的攻击链。\n");
        }

        // 注入会话流信息
        String sessionInfo = buildSessionFlowContext();
        if (!sessionInfo.isEmpty())
        {
            sb.append("\n## 会话流追踪信息:\n");
            sb.append(sessionInfo).append("\n");
        }

        sb.append("\n## 分析流程\n");
        sb.append("1. 快速扫描：检查状态码异常(4xx/5xx)、响应中的错误关键字(error/exception/sql syntax)\n");
        sb.append("2. 参数分析：识别用户可控参数，评估其是否被后端处理\n");
        sb.append("3. 模式匹配：根据参数名/值/位置匹配已知漏洞模式\n");
        sb.append("4. 证据确认：仅报告有响应中直接证据支持的发现\n\n");
        sb.append("严格按以下JSON数组格式返回，不要包含其他文字：\n");
        sb.append("[{\"targetIndex\":1,\"url\":\"https://example.com/api\",\"method\":\"POST\",");
        sb.append("\"vulnType\":\"SQL注入\",\"severity\":\"高\",");
        sb.append("\"parameter\":\"username\",\"description\":\"参数未过滤\",");
        sb.append("\"suggestion\":\"使用参数化查询\",\"evidence\":\"响应包含SQL错误\",");
        sb.append("\"confidence\":0.8,\"category\":\"注入类\",\"tags\":[\"SQL\",\"数据库\"],");
        sb.append("\"verifyRequest\":\"GET /api?id=1' HTTP/1.1\\r\\nHost: example.com\\r\\n\",");
        sb.append("\"verificationPlan\":\"发送只读变体，观察错误、状态码、响应差异\"}]\n\n");
        sb.append("如果没有发现风险，返回空数组 []。\n");
        sb.append("报告条件：响应中有直接证据（错误信息、异常行为、敏感数据暴露等），且 confidence >= 0.7。\n");
        sb.append("请为每个发现提供 category（漏洞分类）和 tags（标签数组），帮助后续分析。\n\n");
        sb.append("## 报告规则\n");
        sb.append("- evidence字段必须引用响应中的具体内容，不能泛泛而谈\n");
        sb.append("- 优先报告根因型漏洞(SQL注入/越权/未授权/RCE/SSRF/XSS)，其次才是衍生现象(信息泄露/配置不当)\n");
        sb.append("- 如果响应中有错误信息、异常状态码、敏感数据(凭证/token/密钥/堆栈/SQL错误)等直接证据，积极报告\n");
        sb.append("- 每个请求最多只返回1个最有价值、证据最强、最接近根因的漏洞\n");
        sb.append("- 不要报告缺失安全头(CSP/HSTS/X-Frame-Options)、版本暴露、Banner信息等低价值泛化项\n");
        sb.append("- 信息泄露仅在响应中出现凭证/token/密钥/数据库连接串/堆栈跟踪时才报告\n");

        // 时序分析指导
        sb.append("## 时序分析指南\n");
        sb.append("每个请求/响应附带 Burp Suite 原生记录的精确响应时间数据，请结合时序进行分析：\n");
        sb.append("- TTFB(首字节时间)异常偏高(>2s) → 可能存在: 时间盲注(Blind SQLi)、SSRF、后端命令执行、服务端性能瓶颈\n");
        sb.append("- TTLB(末字节时间)远大于TTFB(差值>1s) → 可能存在: 大数据泄露、慢查询DoS、响应体异常庞大\n");
        sb.append("- 同接口不同参数间TTFB差异>500ms → 高度怀疑盲注漏洞(Blind SQLi/Boolean-based/Time-based)\n");
        sb.append("- 极短响应时间(<10ms) → 可能: WAF拦截直接丢弃、缓存命中、请求被中间件拒绝\n");
        sb.append("- 响应时间与响应体大小不成比例 → 可能: 后端sleep/wait操作、网络层面异常\n");
        sb.append("如果发现时序异常，请在 evidence 字段中引用具体的 TTFB/TTLB 数值。\n\n");

        // WAF 绕过分析指导
        sb.append(FullVulnDatabase.WAF_BYPASS_KNOWLEDGE);
        sb.append("请在分析时主动检测WAF特征，如果响应中存在WAF拦截迹象：\n");
        sb.append("1. 在 evidence 中标注检测到的WAF类型\n");
        sb.append("2. 在 suggestion 中给出具体绕过技术建议\n");
        sb.append("3. 被 WAF 拦截的请求仍可能是漏洞的间接证据，提高 suspicion 但降低 confidence\n\n");

        // OOB 带外测试域名
        String oob = FullVulnDatabase.getOobDomain();
        if (oob != null && !oob.isEmpty())
        {
            sb.append("## OOB 带外测试域名\n");
            sb.append("当前可用的带外测试域名: ").append(oob).append("\n");
            sb.append("当发现SSRF、XXE、盲注等需要带外验证的漏洞时，");
            sb.append("请在 suggestion 和 verifyRequest 中给出使用此域名的具体payload。\n\n");
        }

        if (autoVerifyEnabled)
        {
            sb.append("自动验证已启用。对适合低风险验证的发现，必须基于对应 targetIndex 的原始请求构造 verifyRequest。");
            sb.append("verifyRequest 必须包含请求行和 Host 头，尽量保持原始 Cookie、Authorization、Content-Type 等上下文。");
            sb.append("仅允许只读或低风险验证，优先使用 GET/HEAD 或不改变业务状态的参数变体。");
            sb.append("不要生成会删除、修改、支付、发短信、创建账号、登出或破坏数据的请求。");
            sb.append("verificationPlan 说明为什么这个请求可验证该风险。\n\n");
        }

        for (int i = 0; i < batch.size(); i++)
        {
            ProxyHttpRequestResponse item = batch.get(i);
            sb.append("---请求 #").append(i + 1).append("---\n");
            sb.append(TextUtils.truncateWithSuffix(item.finalRequest().toString(), 4000, "\n... [已截断]")).append("\n\n");
            if (item.hasResponse())
            {
                sb.append("---响应 #").append(i + 1).append("---\n");
                int statusCode = item.response().statusCode();
                sb.append("[状态码: ").append(statusCode).append("]\n");

                // 从 Burp 原生 TimingData 读取响应时间
                appendTimingInfo(sb, item);

                sb.append(TextUtils.truncateWithSuffix(TextUtils.toStringUtf8(item.response()), 4000, "\n... [已截断]")).append("\n\n");
            }
        }

        return sb.toString();
    }

    private String buildSessionFlowContext()
    {
        if (hostSessions.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, List<String>> entry : hostSessions.entrySet())
        {
            List<String> flows = entry.getValue();
            if (flows.size() > 1)
            {
                sb.append("- ").append(entry.getKey()).append(": ");
                sb.append(String.join(" → ", flows)).append("\n");
                Set<String> cookies = hostCookies.getOrDefault(entry.getKey(), Collections.emptySet());
                if (!cookies.isEmpty())
                {
                    sb.append("  Cookie变化: ").append(String.join(", ", cookies)).append("\n");
                }
            }
        }
        return sb.toString();
    }

    // ==================== 技术感知 Prompt ====================

    /**
     * 根据批次中请求的目标host，查询 TechFingerprint 缓存，
     * 如果存在已识别的技术栈，则生成技术感知的分析提示。
     */
    private String buildTechAwarePrompt(List<ProxyHttpRequestResponse> batch)
    {
        Set<String> hosts = new LinkedHashSet<>();
        for (ProxyHttpRequestResponse item : batch)
        {
            String host = item.httpService().host();
            if (host != null && !host.isEmpty()) hosts.add(host);
        }
        if (hosts.isEmpty()) return null;

        StringBuilder techInfo = new StringBuilder();
        for (String host : hosts)
        {
            try
            {
                TechFingerprint.TechStack techStack = TechFingerprint.get(host);
                if (techStack != null && !techStack.getTechnologies().isEmpty())
                {
                    techInfo.append("- ").append(host).append(": ");
                    techInfo.append(String.join(", ", techStack.getTechnologies())).append("\n");

                    // 根据技术栈生成重点检测建议
                    String hints = generateTechHints(techStack);
                    if (hints != null && !hints.isEmpty())
                    {
                        techInfo.append("  重点检测: ").append(hints).append("\n");
                    }
                }
            }
            catch (Exception ignored) {}
        }

        if (techInfo.length() > 0)
        {
            techInfo.append("请根据上述技术栈，特别关注与之相关的典型安全风险。\n");
        }
        return techInfo.length() > 0 ? techInfo.toString() : null;
    }

    /**
     * 根据已识别的技术栈，生成重点安全检测建议。
     */
    private String generateTechHints(TechFingerprint.TechStack techStack)
    {
        Set<String> hints = new LinkedHashSet<>();
        String techs = String.join(",", techStack.getTechnologies()).toLowerCase();

        if (techs.contains("spring"))
        {
            hints.add("反序列化漏洞");
            hints.add("SpEL注入");
            hints.add("Spring Actuator未授权访问");
            hints.add("Spring Security配置错误");
        }
        if (techs.contains("php"))
        {
            hints.add("文件包含(LFI/RFI)");
            hints.add("命令注入");
            hints.add("反序列化(phar)");
            hints.add("弱类型比较问题");
        }
        if (techs.contains("asp.net") || techs.contains(".net"))
        {
            hints.add("ViewState反序列化");
            hints.add("路径遍历");
            hints.add("XXE注入");
        }
        if (techs.contains("node") || techs.contains("express") || techs.contains("next.js"))
        {
            hints.add("原型污染");
            hints.add("SSRF");
            hints.add("路径遍历");
        }
        if (techs.contains("django") || techs.contains("flask") || techs.contains("python"))
        {
            hints.add("SSTI(模板注入)");
            hints.add("Pickle反序列化");
            hints.add("路径遍历");
        }
        if (techs.contains("rails") || techs.contains("ruby"))
        {
            hints.add("SSTI(ERB模板注入)");
            hints.add("反序列化(YAML)");
            hints.add(" mass assignment");
        }
        if (techs.contains("wordpress") || techs.contains("wp"))
        {
            hints.add("插件漏洞");
            hints.add("XML-RPC攻击");
            hints.add("文件上传");
        }
        if (techs.contains("tomcat") || techs.contains("jetty") || techs.contains("jboss"))
        {
            hints.add("管理控制台未授权");
            hints.add("WAR包部署");
            hints.add("反序列化");
        }
        if (techs.contains("nginx") || techs.contains("apache"))
        {
            hints.add("配置错误导致路径遍历");
            hints.add("反向代理SSRF");
            hints.add("路径规范化绕过");
        }
        if (techs.contains("mysql") || techs.contains("postgresql") || techs.contains("mssql") || techs.contains("sql"))
        {
            hints.add("SQL注入");
            hints.add("数据库信息泄露");
        }
        if (techs.contains("mongodb") || techs.contains("nosql"))
        {
            hints.add("NoSQL注入");
            hints.add("NoSQL运算符注入");
        }
        if (techs.contains("redis") || techs.contains("memcached"))
        {
            hints.add("未授权访问");
            hints.add("SSRF利用");
        }
        if (techs.contains("graphql"))
        {
            hints.add("GraphQL introspection泄露");
            hints.add("批量查询DoS");
            hints.add("IDOR via GraphQL");
        }
        if (techs.contains("rest") || techs.contains("api"))
        {
            hints.add("API认证绕过");
            hints.add("IDOR");
            hints.add("批量赋值");
        }

        return hints.isEmpty() ? null : String.join("、", hints);
    }

    // ==================== 攻击链关联分析 ====================

    /**
     * 分析多个漏洞之间的关联关系，生成攻击链描述。
     * 当结果中有多个相关发现时（同host、或参数关联），组合为攻击链。
     */
    public String analyzeAttackChains(List<VulnReport> results)
    {
        if (results == null || results.size() < 2) return "";

        List<String> chains = new ArrayList<>();

        // 按host分组
        Map<String, List<VulnReport>> byHost = new LinkedHashMap<>();
        for (VulnReport r : results)
        {
            String host = r.getHost() != null ? r.getHost() : extractHost(r.getUrl());
            byHost.computeIfAbsent(host != null ? host : "unknown", k -> new ArrayList<>()).add(r);
        }

        // 按漏洞类型分组
        Map<String, List<VulnReport>> byType = new LinkedHashMap<>();
        for (VulnReport r : results)
        {
            String type = r.getVulnType() != null ? r.getVulnType().toLowerCase() : "unknown";
            byType.computeIfAbsent(type, k -> new ArrayList<>()).add(r);
        }

        // 攻击链规则检测
        for (Map.Entry<String, List<VulnReport>> entry : byHost.entrySet())
        {
            String host = entry.getKey();
            List<VulnReport> hostResults = entry.getValue();
            if (hostResults.size() < 2) continue;

            Set<String> typeSet = new LinkedHashSet<>();
            for (VulnReport r : hostResults)
            {
                if (r.getVulnType() != null) typeSet.add(r.getVulnType().toLowerCase());
            }

            // 规则1: 信息泄露 + IDOR = 数据泄露链
            if (containsAny(typeSet, "信息泄露", "敏感信息泄露", "information disclosure")
                && containsAny(typeSet, "idor", "越权访问", "不安全的直接对象引用", "broken access control"))
            {
                chains.add("**数据泄露链** [" + host + "]: 信息泄露暴露了数据结构/ID模式，结合IDOR越权访问可导致大规模数据泄露。");
            }

            // 规则2: 认证问题 + 文件上传 = RCE链
            if (containsAny(typeSet, "认证绕过", "弱认证", "authentication", "broken authentication", "未授权访问")
                && containsAny(typeSet, "文件上传", "unrestricted upload", "任意文件上传"))
            {
                chains.add("**远程代码执行链(RCE)** [" + host + "]: 认证缺陷允许绕过身份校验，结合任意文件上传可上传Webshell/恶意脚本，最终实现远程代码执行。");
            }

            // 规则3: SQL注入 + 认证问题 = 数据库接管链
            if (containsAny(typeSet, "sql注入", "sql injection", "sql")
                && containsAny(typeSet, "认证绕过", "弱认证", "authentication", "broken authentication"))
            {
                chains.add("**数据库接管链** [" + host + "]: SQL注入可提取数据库内容（含凭证），结合认证缺陷可能实现数据库完全接管。");
            }

            // 规则4: XSS + CSRF = 会话劫持链
            if (containsAny(typeSet, "xss", "跨站脚本", "cross-site scripting")
                && containsAny(typeSet, "csrf", "跨站请求伪造", "cross-site request forgery"))
            {
                chains.add("**会话劫持链** [" + host + "]: XSS可窃取Cookie/Token，结合CSRF可构造恶意请求，形成完整的会话劫持攻击链。");
            }

            // 规则5: SSRF + 内网服务 = 内网渗透链
            if (containsAny(typeSet, "ssrf", "服务端请求伪造", "server-side request forgery"))
            {
                chains.add("**内网渗透链** [" + host + "]: SSRF可用于探测和访问内网服务，若内网存在未授权服务则可进一步横向渗透。");
            }

            // 规则6: 信息泄露 + SQL注入 = 提权链
            if (containsAny(typeSet, "信息泄露", "敏感信息泄露", "information disclosure")
                && containsAny(typeSet, "sql注入", "sql injection"))
            {
                chains.add("**提权攻击链** [" + host + "]: 信息泄露可能暴露数据库结构/表名，结合SQL注入可精确构造提权语句，实现数据库层面的权限提升。");
            }

            // 规则7: SSTI/模板注入 + 反序列化 = RCE链
            if (containsAny(typeSet, "ssti", "模板注入", "template injection")
                && containsAny(typeSet, "反序列化", "deserialization", "insecure deserialization"))
            {
                chains.add("**RCE组合链** [" + host + "]: 模板注入和反序列化漏洞都可能导致远程代码执行，两者同时存在时攻击面大幅增加。");
            }

            // 规则8: 文件包含 + 文件上传 = Webshell链
            if (containsAny(typeSet, "文件包含", "lfi", "rfi", "local file inclusion", "remote file inclusion")
                && containsAny(typeSet, "文件上传", "unrestricted upload"))
            {
                chains.add("**Webshell部署链** [" + host + "]: 通过文件上传上传恶意文件，再利用文件包含漏洞执行该文件，实现无直接RCE的Webshell部署。");
            }

            // 规则9: 命令注入 + 弱权限 = 系统接管链
            if (containsAny(typeSet, "命令注入", "command injection", "os command injection")
                && containsAny(typeSet, "权限提升", "privilege escalation", "弱权限", "insecure permissions"))
            {
                chains.add("**系统接管链** [" + host + "]: 命令注入已具备代码执行能力，结合权限配置错误可进一步提权至root/system级别，完全接管服务器。");
            }

            // 规则10: XXE + SSRF = 数据外带链
            if (containsAny(typeSet, "xxe", "xml外部实体", "xml external entity")
                && containsAny(typeSet, "ssrf", "服务端请求伪造"))
            {
                chains.add("**数据外带链** [" + host + "]: XXE可读取本地文件，结合SSRF可将数据外带到攻击者控制的服务器，实现盲注场景下的数据窃取。");
            }
        }

        if (chains.isEmpty()) return "";

        StringBuilder sb = new StringBuilder();
        sb.append("## 攻击链关联分析\n\n");
        sb.append("基于同一目标中多个漏洞的关联分析，发现以下潜在攻击链：\n\n");
        for (int i = 0; i < chains.size(); i++)
        {
            sb.append(i + 1).append(". ").append(chains.get(i)).append("\n\n");
        }
        sb.append("**建议**: 修复攻击链中的任一环节即可阻断整条链路，优先修复关键节点（如认证缺陷、输入校验缺失）。\n");
        return sb.toString();
    }

    // ==================== 自动验证 ====================

    private void autoVerifyReports(List<VulnReport> reports, AtomicInteger verifyCount, AnalysisCallback callback)
    {
        for (VulnReport report : reports)
        {
            if (cancelled.get()) return;
            if (verifyCount.get() >= MAX_AUTO_VERIFY_PER_RUN) return;
            String verifyRequest = report.getReproduceRequest();
            if (verifyRequest == null || verifyRequest.trim().isEmpty()) continue;

            try
            {
                callback.onProgress("自动验证: " + report.getVulnType() + " " + report.getUrl());
                HttpRequest request = buildHttpRequest(verifyRequest, report);
                report.setReproduceRequest(request.toString());
                long start = System.currentTimeMillis();
                HttpRequestResponse result = api.http().sendRequest(request);
                long durationMs = System.currentTimeMillis() - start;
                verifyCount.incrementAndGet();

                String response = result.hasResponse() ? TextUtils.toStringUtf8(result.response()) : "";
                report.setTestResponse(response);
                String verdict = analyzeVerification(report, request.toString(), response, durationMs);
                report.setVerificationDetail(verdict);
                report.setVerifyStatus(parseVerifyStatus(verdict));

                // 同步到 AI 请求页面
                if (requestSentCallback != null)
                {
                    String reqText = request.toString();
                    String respHost = request.httpService().host();
                    String method = request.method();
                    int statusCode = result.hasResponse() ? result.response().statusCode() : 0;
                    requestSentCallback.onRequestSent(reqText, response, respHost, method, statusCode, durationMs);
                }
            }
            catch (Exception e)
            {
                report.setVerifyStatus(VulnReport.VerifyStatus.UNVERIFIED);
                report.setVerificationDetail("自动验证失败: " + e.getMessage());
                callback.onProgress("自动验证失败: " + e.getMessage());
            }

            // 对 OOB 类型漏洞，检查 Collaborator 回调
            if (report.getVerifyStatus() != VulnReport.VerifyStatus.CONFIRMED
                && isOobVulnType(report.getVulnType()))
            {
                int baselineCount = CollaboratorHelper.checkOobInteractions().size();
                checkCollaboratorCallback(report, baselineCount);
            }
        }
    }

    private String analyzeVerification(VulnReport report, String request, String response, long durationMs) throws Exception
    {
        String prompt = "你是Web安全验证专家。请根据原始发现、验证请求和验证响应判断漏洞是否被确认。"
            + "验证请求响应耗时 " + durationMs + "ms"
            + (durationMs >= 1000 ? " (约" + String.format("%.1f", durationMs / 1000.0) + "秒)" : "")
            + "。如果是时间盲注类漏洞，请重点根据响应耗时判断验证是否成功。\n\n"
            + "## 判断标准\n"
            + "- confirmed: 验证响应中出现漏洞直接证据（错误信息/敏感数据/状态码变化）\n"
            + "- unverified: 验证响应与原始响应无明显差异，或被WAF拦截无法确认\n\n"
            + "严格返回 JSON 对象，不要输出其他文字："
            + "{\"status\":\"confirmed|unverified\",\"confidence\":0.0,\"evidence\":\"关键证据\","
            + "\"reason\":\"判断理由\",\"nextStep\":\"建议下一步\"}\n\n"
            + "漏洞类型: " + report.getVulnType() + "\n"
            + "参数: " + report.getParameter() + "\n"
            + "原始证据: " + report.getEvidence() + "\n\n"
            + "原始请求:\n```http\n" + TextUtils.truncateWithSuffix(report.getOriginalRequest(), 3000, "\n... [已截断]") + "\n```\n\n"
            + "验证请求:\n```http\n" + TextUtils.truncateWithSuffix(request, 4000, "\n... [已截断]") + "\n```\n\n"
            + "验证响应:\n```http\n" + TextUtils.truncateWithSuffix(response, 6000, "\n... [已截断]") + "\n```\n\n"
            + getAnalyzerOobContext();
        return provider.chat(Collections.singletonList(ChatMessage.user(prompt)));
    }

    // ==================== HTTP请求构建 ====================

    private HttpRequest buildHttpRequest(String rawRequest, VulnReport report)
    {
        if (rawRequest == null || rawRequest.trim().isEmpty())
        {
            throw new IllegalArgumentException("验证请求为空");
        }

        // 1. 标准化换行符
        String normalized = normalizeHttp(rawRequest).trim();

        // 2. 确保请求行格式正确
        int firstLineEnd = normalized.indexOf("\r\n");
        if (firstLineEnd < 0) firstLineEnd = normalized.length();
        String requestLine = normalized.substring(0, firstLineEnd);
        if (!requestLine.matches("^[A-Z]+\\s+\\S+.*"))
        {
            throw new IllegalArgumentException("请求行格式错误: " + requestLine);
        }
        // 如果请求行缺少 HTTP/1.1，补上
        if (!requestLine.matches(".*\\s+HTTP/\\d\\.\\d$"))
        {
            normalized = requestLine + " HTTP/1.1" + normalized.substring(firstLineEnd);
        }

        // 3. 提取或补全 Host 头
        String host = null;
        String[] lines = normalized.split("\r\n");
        for (String line : lines)
        {
            if (line.toLowerCase(Locale.ROOT).startsWith("host:"))
            {
                host = line.substring(5).trim();
                break;
            }
        }

        // 从请求行提取 Host（绝对 URL）
        if (host == null || host.isEmpty())
        {
            String reqTarget = requestLine.split("\\s+")[1];
            if (reqTarget.startsWith("http://") || reqTarget.startsWith("https://"))
            {
                try
                {
                    URI uri = URI.create(reqTarget);
                    host = uri.getHost();
                    if (uri.getPort() > 0) host += ":" + uri.getPort();
                }
                catch (Exception ignored) {}
            }
        }

        // 从 report.getUrl() 提取 Host
        if (host == null || host.isEmpty())
        {
            if (report != null && report.getUrl() != null && !report.getUrl().isEmpty())
            {
                try
                {
                    URI uri = URI.create(report.getUrl());
                    host = uri.getHost();
                    if (uri.getPort() > 0) host += ":" + uri.getPort();
                    else if ("https".equalsIgnoreCase(uri.getScheme())) host += ":443";
                    else host += ":80";
                }
                catch (Exception ignored) {}
            }
        }

        if (host == null || host.isEmpty())
        {
            throw new IllegalArgumentException("验证请求缺少 Host");
        }

        // 4. 如果缺少 Host 头，插入
        if (!normalized.toLowerCase(Locale.ROOT).contains("host:"))
        {
            int insertPos = normalized.indexOf("\r\n");
            if (insertPos > 0)
            {
                normalized = normalized.substring(0, insertPos) + "\r\nHost: " + host + normalized.substring(insertPos);
            }
        }

        // 5. 确保 headers 和 body 之间有 \r\n\r\n
        if (!normalized.contains("\r\n\r\n"))
        {
            normalized = normalized + "\r\n\r\n";
        }

        // 6. 解析 host 和 port
        boolean secure = false;
        int port = 80;
        int colon = host.lastIndexOf(':');
        if (colon > 0 && host.indexOf(':') == colon)
        {
            try
            {
                port = Integer.parseInt(host.substring(colon + 1));
            }
            catch (Exception ignored) {}
            host = host.substring(0, colon);
        }

        if (requestLine.matches("^[A-Z]+\\s+https://.*"))
        {
            secure = true;
        }
        else if (requestLine.matches("^[A-Z]+\\s+http://.*"))
        {
            secure = false;
        }
        else if (report != null && report.isSecure())
        {
            secure = true;
        }
        else if (report != null && report.getUrl() != null && !report.getUrl().isEmpty())
        {
            secure = report.getUrl().toLowerCase(Locale.ROOT).startsWith("https://");
        }
        else if (port == 443 || port == 8443)
        {
            secure = true;
        }

        // secure 已确定但 port 仍是默认值时，修正端口号
        if (secure && port == 80)
        {
            port = 443;
        }
        else if (!secure && port == 443)
        {
            port = 80;
        }

        HttpService service = HttpService.httpService(host, port, secure);
        return HttpRequest.httpRequest(service, fixContentLength(normalized));
    }

    // ==================== 结果解析 ====================

    private List<VulnReport> parseAnalysisResults(
        String aiResponse, List<ProxyHttpRequestResponse> batch)
    {
        List<VulnReport> reports = new ArrayList<>();
        try
        {
            for (Map<String, Object> m : AiResponseParser.parseFirstObjectArray(aiResponse))
            {
                VulnReport r = new VulnReport();
                r.setUrl(AiResponseParser.getString(m, "url"));
                r.setMethod(AiResponseParser.getString(m, "method"));
                r.setVulnType(AiResponseParser.getString(m, "vulnType"));
                r.setParameter(AiResponseParser.getString(m, "parameter"));
                r.setDescription(AiResponseParser.getString(m, "description"));
                r.setSuggestion(AiResponseParser.getString(m, "suggestion"));
                r.setEvidence(AiResponseParser.getString(m, "evidence"));
                r.setSeverity(VulnReport.Severity.fromString(AiResponseParser.getString(m, "severity")));
                r.setCategory(AiResponseParser.getString(m, "category"));
                r.setHost(extractHost(r.getUrl()));

                for (String tag : AiResponseParser.getStringList(m, "tags"))
                {
                    r.addTag(tag);
                }

                int targetIndex = AiResponseParser.getInt(m, "targetIndex", -1);
                if (targetIndex > 0 && targetIndex <= batch.size())
                {
                    ProxyHttpRequestResponse source = batch.get(targetIndex - 1);
                    r.setOriginalRequest(source.finalRequest().toString());
                    r.setSecure(source.httpService().secure());
                    if (source.hasResponse())
                    {
                        r.setResponseCode(String.valueOf(source.response().statusCode()));
                        r.setOriginalResponse(TextUtils.toStringUtf8(source.response()));
                    }
                    fillTimingData(r, source);
                    // 用 Burp 原始连接的协议信息修正 URL scheme
                    try
                    {
                        boolean actualSecure = source.httpService().secure();
                        String currentUrl = r.getUrl();
                        if (actualSecure && currentUrl != null && currentUrl.startsWith("http://"))
                        {
                            r.setUrl("https://" + currentUrl.substring(7));
                        }
                        else if (!actualSecure && currentUrl != null && currentUrl.startsWith("https://"))
                        {
                            r.setUrl("http://" + currentUrl.substring(8));
                        }
                        else if (actualSecure && (currentUrl == null || currentUrl.isEmpty()
                            || (!currentUrl.startsWith("http://") && !currentUrl.startsWith("https://"))))
                        {
                            String host = r.getHost() != null ? r.getHost() : source.httpService().host();
                            r.setUrl("https://" + host + (currentUrl != null ? currentUrl : "/"));
                        }
                    }
                    catch (Exception ignored) {}
                }
                else
                {
                    String matched = findOriginalRequestByUrl(batch, r.getUrl(), r.getMethod());
                    r.setOriginalRequest(matched);
                    // fallback: 从匹配的请求或 URL 推断 secure
                    if (matched != null && matched.contains("://"))
                    {
                        r.setSecure(matched.toLowerCase().startsWith("https://"));
                    }
                    else
                    {
                        String rUrl = r.getUrl();
                        r.setSecure(rUrl != null && rUrl.toLowerCase().startsWith("https://"));
                    }
                }
                r.setReproduceRequest(AiResponseParser.getString(m, "verifyRequest"));
                String plan = AiResponseParser.getString(m, "verificationPlan");
                if (!plan.isEmpty())
                {
                    r.setVerificationDetail("验证计划: " + plan);
                }

                r.setConfidence(AiResponseParser.getDouble(m, "confidence", 0.0));
                reports.add(r);
            }
        }
        catch (Exception e)
        {
            api.logging().logToError("[Traffic] 解析 AI 结果失败: " + e.getMessage());
        }
        return VulnFindingPolicy.keepTopOnePerRequest(reports);
    }

    private VulnReport.VerifyStatus parseVerifyStatus(String verdict)
    {
        if (verdict == null || verdict.trim().isEmpty())
        {
            return VulnReport.VerifyStatus.UNVERIFIED;
        }

        try
        {
            Map<String, Object> map = AiResponseParser.parseFirstObject(verdict);
            if (!map.isEmpty())
            {
                String status = AiResponseParser.getTrimmedLowerString(map, "status");
                if ("confirmed".equals(status))
                {
                    return VulnReport.VerifyStatus.CONFIRMED;
                }
                if ("false_positive".equals(status))
                {
                    return VulnReport.VerifyStatus.FALSE_POSITIVE;
                }
                return VulnReport.VerifyStatus.UNVERIFIED;
            }
        }
        catch (Exception ignored) {}

        return VulnReport.VerifyStatus.UNVERIFIED;
    }

    // ==================== 工具方法 ====================

    private String extractHost(String url)
    {
        if (url == null || url.isEmpty()) return null;
        try
        {
            // 简单提取 host
            int start = url.indexOf("://");
            if (start < 0) return null;
            start += 3;
            int end = url.indexOf('/', start);
            if (end < 0) end = url.indexOf('?', start);
            if (end < 0) end = url.length();
            String hostPort = url.substring(start, end);
            int colon = hostPort.lastIndexOf(':');
            if (colon > 0 && hostPort.indexOf(':') == colon)
            {
                return hostPort.substring(0, colon);
            }
            return hostPort;
        }
        catch (Exception e)
        {
            return null;
        }
    }

    private String fixContentLength(String request)
    {
        int split = request.indexOf("\r\n\r\n");
        if (split < 0) return request;
        String headers = request.substring(0, split);
        String body = request.substring(split + 4);
        String[] lines = headers.split("\r\n", -1);
        StringBuilder rebuilt = new StringBuilder();
        boolean sawLength = false;
        for (int i = 0; i < lines.length; i++)
        {
            String line = lines[i];
            if (line.toLowerCase(Locale.ROOT).startsWith("content-length:"))
            {
                line = "Content-Length: " + body.getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
                sawLength = true;
            }
            if (i > 0) rebuilt.append("\r\n");
            rebuilt.append(line);
        }
        if (!sawLength && !body.isEmpty())
        {
            rebuilt.append("\r\nContent-Length: ")
                .append(body.getBytes(java.nio.charset.StandardCharsets.UTF_8).length);
        }
        return rebuilt.append("\r\n\r\n").append(body).toString();
    }

    private String normalizeHttp(String text)
    {
        return text.replace("\r\n", "\n").replace('\r', '\n').replace("\n", "\r\n").trim();
    }

    private List<ProxyHttpRequestResponse> deduplicate(
        List<ProxyHttpRequestResponse> history, int maxCount)
    {
        LinkedHashMap<String, ProxyHttpRequestResponse> seen = new LinkedHashMap<>();
        for (int i = history.size() - 1; i >= 0 && seen.size() < maxCount; i--)
        {
            ProxyHttpRequestResponse item = history.get(i);
            if (!item.hasResponse()) continue;

            String key = buildDedupKey(item);
            if (!seen.containsKey(key))
            {
                seen.put(key, item);
            }
        }

        List<ProxyHttpRequestResponse> result = new ArrayList<>(seen.values());
        Collections.reverse(result);
        return result;
    }

    private String buildDedupKey(ProxyHttpRequestResponse item)
    {
        String requestText = item.finalRequest().toString();
        int split = requestText.indexOf("\r\n\r\n");
        String body = split >= 0 ? requestText.substring(split + 4) : "";
        String bodyFingerprint = body.isEmpty()
            ? ""
            : Integer.toHexString(TextUtils.truncate(body, 512).hashCode());
        return item.finalRequest().method() + " "
            + item.finalRequest().url() + " "
            + bodyFingerprint;
    }
    private String findOriginalRequestByUrl(List<ProxyHttpRequestResponse> batch, String url, String method)
    {
        for (ProxyHttpRequestResponse item : batch)
        {
            String itemUrl = item.finalRequest().url();
            String itemMethod = item.finalRequest().method();
            if ((url == null || url.isEmpty() || itemUrl.equals(url))
                && (method == null || method.isEmpty() || itemMethod.equalsIgnoreCase(method)))
            {
                return item.finalRequest().toString();
            }
        }
        return "";
    }

    // ==================== 时序数据工具方法 ====================

    /**
     * 将 Burp 原生 TimingData 填充到 VulnReport 模型。
     */
    private void fillTimingData(VulnReport r, ProxyHttpRequestResponse source)
    {
        try
        {
            TimingData td = source.timingData();
            if (td == null) return;
            if (td.timeBetweenRequestSentAndStartOfResponse() != null)
            {
                long ttfb = td.timeBetweenRequestSentAndStartOfResponse().toMillis();
                if (ttfb > 0) r.setTtfbMs(ttfb);
            }
            if (td.timeBetweenRequestSentAndEndOfResponse() != null)
            {
                long ttlb = td.timeBetweenRequestSentAndEndOfResponse().toMillis();
                if (ttlb > 0) r.setTtlbMs(ttlb);
            }
        }
        catch (Exception ignored) {}
    }

    /**
     * 从 Burp 原生 TimingData 提取响应时间，格式化追加到 prompt。
     * 数据来源与 Proxy 历史表格右下角显示的响应时间完全一致。
     */
    private void appendTimingInfo(StringBuilder sb, ProxyHttpRequestResponse item)
    {
        try
        {
            TimingData td = item.timingData();
            if (td == null) return;

            boolean hasTiming = false;
            if (td.timeBetweenRequestSentAndStartOfResponse() != null)
            {
                long ttfb = td.timeBetweenRequestSentAndStartOfResponse().toMillis();
                if (ttfb > 0)  // 过滤无效值（0ms 或负数无分析意义）
                {
                    sb.append("[TTFB(首字节): ").append(ttfb).append("ms");
                    hasTiming = true;
                }
            }
            if (td.timeBetweenRequestSentAndEndOfResponse() != null)
            {
                long ttlb = td.timeBetweenRequestSentAndEndOfResponse().toMillis();
                if (ttlb > 0)
                {
                    if (hasTiming)
                    {
                        sb.append(", TTLB(末字节): ").append(ttlb).append("ms");
                    }
                    else
                    {
                        sb.append("[TTLB(末字节): ").append(ttlb).append("ms");
                        hasTiming = true;
                    }
                }
            }
            if (hasTiming) sb.append("]\n");
        }
        catch (Exception ignored)
        {
            // 部分历史记录可能没有时序数据
        }
    }

    /**
     * 基于 Burp 原生 TimingData 计算时序可疑度评分。
     * - TTFB > 5s: 极度可疑（盲注/SSRF/命令执行）
     * - TTFB > 2s: 较可疑
     * - TTLB - TTFB > 3s: 响应体传输异常（大数据泄露/慢查询）
     */
    private int computeTimingScore(ProxyHttpRequestResponse item)
    {
        int score = 0;
        try
        {
            TimingData td = item.timingData();
            if (td == null) return 0;

            long ttfb = -1;
            long ttlb = -1;

            if (td.timeBetweenRequestSentAndStartOfResponse() != null)
            {
                ttfb = td.timeBetweenRequestSentAndStartOfResponse().toMillis();
            }
            if (td.timeBetweenRequestSentAndEndOfResponse() != null)
            {
                ttlb = td.timeBetweenRequestSentAndEndOfResponse().toMillis();
            }

            // 过滤无效值：0 或负数表示数据缺失
            if (ttfb <= 0) ttfb = -1;
            if (ttlb <= 0) ttlb = -1;

            // TTFB 异常：可能存在盲注、SSRF、后端命令执行
            if (ttfb > 5000) score += 8;      // >5s 极度可疑
            else if (ttfb > 2000) score += 5;  // >2s 较可疑
            else if (ttfb > 1000) score += 2;  // >1s 轻微可疑

            // 传输时间异常：TTLB 远大于 TTFB
            if (ttfb > 0 && ttlb > 0)
            {
                long transferTime = ttlb - ttfb;
                if (transferTime > 3000) score += 5;   // 传输>3s
                else if (transferTime > 1000) score += 3; // 传输>1s
            }
        }
        catch (Exception ignored) {}
        return score;
    }

    // ==================== 内部类 ====================

    /**
     * 检查类型集合中是否包含任一指定关键词（不区分大小写）。
     */
    private boolean containsAny(Set<String> typeSet, String... keywords)
    {
        for (String keyword : keywords)
        {
            String kw = keyword.toLowerCase();
            for (String type : typeSet)
            {
                if (type.contains(kw)) return true;
            }
        }
        return false;
    }

    // ==================== 内部类定义 ====================

    private static class ScoredEntry
    {
        final ProxyHttpRequestResponse item;
        final int score;
        ScoredEntry(ProxyHttpRequestResponse item, int score)
        {
            this.item = item;
            this.score = score;
        }
    }

    /**
     * 分析回调接口。
     */
    public interface AnalysisCallback
    {
        void onStarted(int totalTargets);
        void onProgress(String message);
        void onBatchSubmitted(int batchNumber, int totalBatches, int from, int to,
            List<ProxyHttpRequestResponse> batchTargets);
        void onStreamToken(String token);
        void onVulnFound(VulnReport report);
        void onBatchComplete(int batchNumber, int totalBatches, List<VulnReport> batchResults,
            List<ProxyHttpRequestResponse> batchTargets);
        void onBatchFailed(int batchNumber, int totalBatches, List<ProxyHttpRequestResponse> batchTargets,
            String errorMessage);
        void onComplete(List<VulnReport> results);
        void onNoData();
        void onError(String message);
    }

    /**
     * 构建 OOB 带外测试域名的上下文片段。
     */
    private static String getAnalyzerOobContext()
    {
        String oob = FullVulnDatabase.getOobDomain();
        if (oob == null || oob.isEmpty())
        {
            return "";
        }
        return "重要：当前可用的带外测试(OOB)域名为 " + oob
            + "。验证SSRF、XXE等带外漏洞时必须使用此域名。\n\n";
    }

    /**
     * 判断漏洞类型是否属于 OOB 带外验证类型。
     */
    private static boolean isOobVulnType(String vulnType)
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
     */
    private static void checkCollaboratorCallback(VulnReport report, int baselineCount)
    {
        try
        {
            Thread.sleep(3000);
            int afterCount = CollaboratorHelper.checkOobInteractions().size();
            if (afterCount > baselineCount)
            {
                String summary = CollaboratorHelper.getOobInteractionSummary();
                report.setVerifyStatus(VulnReport.VerifyStatus.CONFIRMED);
                report.setVerificationDetail("OOB带外验证成功: " + summary);
            }
        }
        catch (InterruptedException e)
        {
            Thread.currentThread().interrupt();
        }
    }
}
