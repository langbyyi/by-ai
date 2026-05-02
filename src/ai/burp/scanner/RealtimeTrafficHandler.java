package ai.burp.scanner;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

import ai.burp.util.TextUtils;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.TimingData;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.proxy.http.InterceptedResponse;

import ai.burp.model.ChatMessage;
import ai.burp.model.VulnReport;
import ai.burp.provider.StreamingAIProvider;
import ai.burp.util.AiResponseParser;
import ai.burp.util.TargetScopeMatcher;
import ai.burp.util.VulnFindingPolicy;

/**
 * 实时流量监控处理器。
 *
 * 自动分析新产生的代理流量，通过防抖、可疑度评分和队列消费机制，
 * 实现对实时流量的低开销安全分析。
 */
public class RealtimeTrafficHandler
{
    private final MontoyaApi api;
    private final StreamingAIProvider provider;
    private volatile boolean enabled = false;

    /** 待分析队列，容量100防止内存溢出 */
    private final BlockingQueue<TrafficData> queue = new LinkedBlockingQueue<>(100);

    /** 同一host最后分析时间戳，用于防抖 */
    private final Map<String, Long> lastAnalyzedHost = new ConcurrentHashMap<>();

    /** 实时分析发现的漏洞报告 */
    private final List<VulnReport> realtimeResults = new CopyOnWriteArrayList<>();

    /** 消费者线程引用，用于优雅停止 */
    private volatile Thread consumerThread;

    /** 结果回调 */
    private RealtimeCallback callback;

    /** 同一host防抖间隔，默认120秒(2分钟) */
    private volatile long debounceMs = 120000;

    /** 实时模式每批最多分析的请求数 */
    private volatile int maxBatchSize = 3;

    /** 可疑度阈值，低于此值的请求不入队分析 */
    private volatile int suspicionThreshold = 5;

    /** 取消标志 */
    private final AtomicBoolean cancelled = new AtomicBoolean(false);
    /** 目标范围控制 */
    private volatile TargetScopeMatcher targetScopeMatcher = TargetScopeMatcher.disabled();

    /** OOB 带外测试域名 */
    private volatile String oobDomain = "";

    // ==================== 流量数据内部类 ====================

    /**
     * 轻量级流量数据容器，解耦对 Burp API 类型的直接依赖。
     * 可由 ProxyHttpRequestResponse 或 InterceptedResponse 构造。
     */
    public static class TrafficData
    {
        private final String requestStr;
        private final String responseStr;
        private final boolean hasResponse;
        private final int statusCode;
        private final String method;
        private final String url;
        private final String host;
        private final long ttfbMs;  // TTFB 首字节时间（毫秒），-1 表示无数据
        private final long ttlbMs;  // TTLB 末字节时间（毫秒），-1 表示无数据
        private final boolean secure; // 由 proxy 捕获时确定

        private TrafficData(String requestStr, String responseStr, boolean hasResponse,
                           int statusCode, String method, String url, String host,
                           long ttfbMs, long ttlbMs, boolean secure)
        {
            this.requestStr = requestStr;
            this.responseStr = responseStr;
            this.hasResponse = hasResponse;
            this.statusCode = statusCode;
            this.method = method;
            this.url = url;
            this.host = host;
            this.ttfbMs = ttfbMs;
            this.ttlbMs = ttlbMs;
            this.secure = secure;
        }

        /** 从代理历史记录构造 */
        public static TrafficData fromProxy(ProxyHttpRequestResponse item)
        {
            String req = TextUtils.toStringUtf8(item.finalRequest());
            String resp = item.hasResponse() ? TextUtils.toStringUtf8(item.response()) : "";
            int code = item.hasResponse() ? item.response().statusCode() : 0;
            String method = item.finalRequest().method();
            String url = item.finalRequest().url();
            String host = extractHostFromProxyItem(item);

            // 从 Burp 原生 TimingData 提取响应时间
            long ttfb = -1, ttlb = -1;
            try
            {
                TimingData td = item.timingData();
                if (td != null)
                {
                    if (td.timeBetweenRequestSentAndStartOfResponse() != null)
                        ttfb = td.timeBetweenRequestSentAndStartOfResponse().toMillis();
                    if (td.timeBetweenRequestSentAndEndOfResponse() != null)
                        ttlb = td.timeBetweenRequestSentAndEndOfResponse().toMillis();
                }
            }
            catch (Exception ignored) {}

            return new TrafficData(req, resp, item.hasResponse(), code, method, url, host,
                ttfb > 0 ? ttfb : -1, ttlb > 0 ? ttlb : -1, item.finalRequest().httpService().secure());
        }

        /** 从实时拦截响应构造（InterceptedResponse 无 TimingData，使用 -1） */
        public static TrafficData fromIntercepted(InterceptedResponse intercepted)
        {
            HttpRequest req = intercepted.initiatingRequest();
            String reqStr = req.toString();
            String respStr = intercepted.toString();
            int code = intercepted.statusCode();
            String method = req.method();
            String urlStr = req.url();
            String host = extractHostFromRequest(req);
            return new TrafficData(reqStr, respStr, true, code, method, urlStr, host, -1, -1, req.httpService().secure());
        }

        public String getRequestStr() { return requestStr; }
        public String getResponseStr() { return responseStr; }
        public boolean hasResponse() { return hasResponse; }
        public int getStatusCode() { return statusCode; }
        public String getMethod() { return method; }
        public String getUrl() { return url; }
        public String getHost() { return host; }
        public boolean isSecure() { return secure; }
        public long getTtfbMs() { return ttfbMs; }
        public long getTtlbMs() { return ttlbMs; }
        public boolean hasTimingData() { return ttfbMs > 0 || ttlbMs > 0; }

        private static String extractHostFromProxyItem(ProxyHttpRequestResponse item)
        {
            try
            {
                String host = item.finalRequest().httpService().host();
                int port = item.finalRequest().httpService().port();
                if (host == null || host.isEmpty())
                {
                    return null;
                }
                return host + ":" + port;
            }
            catch (Exception e)
            {
                return null;
            }
        }

        private static String extractHostFromRequest(HttpRequest req)
        {
            try
            {
                String host = req.httpService().host();
                int port = req.httpService().port();
                if (host == null || host.isEmpty())
                {
                    return null;
                }
                return host + ":" + port;
            }
            catch (Exception e)
            {
                return null;
            }
        }
    }

    // ==================== 构造函数 ====================

    public RealtimeTrafficHandler(MontoyaApi api, StreamingAIProvider provider)
    {
        this.api = api;
        this.provider = provider;
    }

    /**
     * 设置 OOB 带外测试域名（Collaborator 或 DNSLog）。
     * 实时分析 SSRF/XXE 等漏洞时会使用此域名。
     */
    public void setOobDomain(String domain)
    {
        this.oobDomain = domain != null ? domain : "";
    }

    // ==================== 回调接口 ====================

    public interface RealtimeCallback
    {
        /** 发现新漏洞时回调 */
        void onVulnFound(VulnReport report);

        /** 一批分析完成时回调 */
        void onAnalysisComplete(String summary);
    }

    // ==================== 公开方法 ====================

    /** 启动实时监控 */
    public void enable()
    {
        if (enabled) return;
        enabled = true;
        cancelled.set(false);

        consumerThread = new Thread(this::consumeLoop, "RealtimeTrafficConsumer");
        consumerThread.setDaemon(true);
        consumerThread.start();

        api.logging().logToOutput("[Realtime] Traffic handler enabled");
    }

    /** 停止实时监控 */
    public void disable()
    {
        if (!enabled) return;
        enabled = false;
        cancelled.set(true);
        provider.stopStreaming();

        if (consumerThread != null)
        {
            consumerThread.interrupt();
            try
            {
                consumerThread.join(3000);
            }
            catch (InterruptedException ignored) {}
            consumerThread = null;
        }

        queue.clear();
        api.logging().logToOutput("[Realtime] Traffic handler disabled");
    }

    /** 接收代理历史流量 */
    public void onNewProxyResponse(ProxyHttpRequestResponse item)
    {
        if (!enabled) return;
        if (item == null || !item.hasResponse()) return;
        enqueueIfWorthy(TrafficData.fromProxy(item));
    }

    /** 接收实时拦截的代理响应 */
    public void onNewInterceptedResponse(InterceptedResponse intercepted)
    {
        if (!enabled) return;
        if (intercepted == null) return;
        enqueueIfWorthy(TrafficData.fromIntercepted(intercepted));
    }

    /** 通用入队逻辑：可疑度评分 + 防抖 + 入队 */
    private void enqueueIfWorthy(TrafficData data)
    {
        if (targetScopeMatcher != null && targetScopeMatcher.isEnabled()
            && !targetScopeMatcher.matchesHost(data.getHost()))
        {
            return;
        }

        int score = computeSuspicionScore(data);
        if (score < suspicionThreshold) return;

        String host = data.getHost();
        if (host != null && !host.isEmpty())
        {
            long now = System.currentTimeMillis();
            Long lastTime = lastAnalyzedHost.get(host);
            if (lastTime != null && (now - lastTime) < debounceMs)
            {
                return;
            }
            lastAnalyzedHost.put(host, now);
        }

        if (!queue.offer(data))
        {
            queue.poll();
            queue.offer(data);
        }
    }

    public List<VulnReport> getResults()
    {
        return new ArrayList<>(realtimeResults);
    }

    public void clearResults()
    {
        realtimeResults.clear();
    }

    public boolean isEnabled() { return enabled; }

    public void setDebounceMs(long ms)
    {
        this.debounceMs = Math.max(1000, ms);
    }

    public void setMaxBatchSize(int size)
    {
        this.maxBatchSize = Math.max(1, Math.min(size, 10));
    }

    public void setSuspicionThreshold(int threshold)
    {
        this.suspicionThreshold = Math.max(0, threshold);
    }

    public void setCallback(RealtimeCallback callback)
    {
        this.callback = callback;
    }

    public void setTargetScope(TargetScopeMatcher matcher)
    {
        this.targetScopeMatcher = matcher != null ? matcher : TargetScopeMatcher.disabled();
    }

    public int getQueueSize()
    {
        return queue.size();
    }

    // ==================== 消费者线程 ====================

    private void consumeLoop()
    {
        while (!cancelled.get())
        {
            try
            {
                Map<String, List<TrafficData>> hostBatches = new LinkedHashMap<>();
                int collected = 0;

                TrafficData first = queue.poll(5, TimeUnit.SECONDS);
                if (first == null)
                {
                    cleanupDebounceMap();
                    continue;
                }

                addToHostBatch(hostBatches, first);
                collected++;

                while (collected < maxBatchSize)
                {
                    TrafficData item = queue.poll();
                    if (item == null) break;
                    addToHostBatch(hostBatches, item);
                    collected++;
                }

                for (Map.Entry<String, List<TrafficData>> entry : hostBatches.entrySet())
                {
                    if (cancelled.get()) break;
                    analyzeBatch(entry.getValue());
                }
            }
            catch (InterruptedException e)
            {
                Thread.currentThread().interrupt();
                break;
            }
            catch (Exception e)
            {
                api.logging().logToError("[Realtime] Consumer error: " + e.getMessage());
            }
        }
    }

    private void addToHostBatch(Map<String, List<TrafficData>> batches, TrafficData item)
    {
        String host = item.getHost();
        if (host == null) host = "unknown";
        batches.computeIfAbsent(host, k -> new ArrayList<>()).add(item);
    }

    // ==================== AI分析 ====================

    private void analyzeBatch(List<TrafficData> batch)
    {
        if (batch.isEmpty()) return;

        String prompt = buildRealtimePrompt(batch);

        try
        {
            provider.chatStream(
                Collections.singletonList(ChatMessage.user(prompt)),
                new StreamingAIProvider.StreamCallback()
                {
                    @Override
                    public void onToken(String token) {}

                    @Override
                    public void onComplete(String fullResp)
                    {
                        List<VulnReport> batchResults = parseAnalysisResults(fullResp, batch);
                        if (!batchResults.isEmpty())
                        {
                            realtimeResults.addAll(batchResults);

                            // 标注代理历史
                            annotateProxyHistory(batch, batchResults);

                            for (VulnReport report : batchResults)
                            {
                                if (callback != null)
                                {
                                    try
                                    {
                                        callback.onVulnFound(report);
                                    }
                                    catch (Exception ignored) {}
                                }
                            }
                        }
                        if (callback != null)
                        {
                            try
                            {
                                String summary = buildSummary(batchResults, batch);
                                callback.onAnalysisComplete(summary);
                            }
                            catch (Exception ignored) {}
                        }
                    }

                    @Override
                    public void onError(Exception e)
                    {
                        api.logging().logToError("[Realtime] AI analysis error: " + e.getMessage());
                    }
                }
            );
        }
        catch (Exception e)
        {
            api.logging().logToError("[Realtime] Batch analysis failed: " + e.getMessage());
        }
    }

    // ==================== Prompt构建 ====================

    private String buildRealtimePrompt(List<TrafficData> batch)
    {
        StringBuilder sb = new StringBuilder();
        sb.append("你是资深Web安全审计员。以下是通过代理捕获的实时HTTP流量，请快速分析安全风险。\n");
        sb.append("重点检查：注入类漏洞的直接证据、敏感信息泄露、认证/授权问题、异常状态码。\n");
        sb.append("注意：实时分析要求快速高效，只报告有明确证据的高置信度发现。\n\n");

        sb.append("严格按以下JSON数组格式返回，不要包含其他文字：\n");
        sb.append("[{\"targetIndex\":1,\"url\":\"https://example.com/api\",\"method\":\"POST\",");
        sb.append("\"vulnType\":\"SQL注入\",\"severity\":\"高\",");
        sb.append("\"parameter\":\"username\",\"description\":\"参数未过滤\",");
        sb.append("\"suggestion\":\"使用参数化查询\",\"evidence\":\"响应包含SQL错误\",");
        sb.append("\"confidence\":0.8,\"category\":\"注入类\",\"tags\":[\"SQL\",\"数据库\"]}]\n\n");
        sb.append("如果没有发现风险，返回空数组 []。\n");
        sb.append("仅报告同时满足三条件的漏洞：可复现（能稳定重放得到一致结果）、"
            + "可利用（存在明确利用路径而非理论可能）、有实际危害（能造成数据泄露/权限提升/业务破坏等真实影响）。缺一不报。\n");
        sb.append("仅报告 confidence >= 0.7 的发现（实时分析要求更高阈值以减少误报）。\n");
        sb.append("请为每个发现提供 category 和 tags。\n");
        sb.append("evidence字段必须引用响应中的具体内容，不能泛泛描述。\n");
        sb.append("每个请求最多只返回1个最有价值、证据最强、最接近根因的漏洞。\n");
        sb.append("不要同时返回「信息泄露」「配置不当」「安全头缺失」「版本暴露」等低价值泛化项。\n");
        sb.append("如果同一请求既能归类为根因型漏洞，又能归类为衍生现象，只保留根因型漏洞。\n");
        sb.append("只有在响应中直接出现凭证/token/密钥/敏感文件/堆栈等高价值内容时，才允许报告信息泄露类问题。\n\n");

        // 时序分析指导
        sb.append("## 时序分析指南\n");
        sb.append("每个请求附带 Burp Suite 原生记录的精确响应时间数据：\n");
        sb.append("- TTFB(首字节时间)>2s → 可能: 时间盲注、SSRF、命令执行\n");
        sb.append("- TTLB(末字节时间)远大于TTFB → 可能: 大数据泄露、慢查询\n");
        sb.append("- 同接口不同参数TTFB差异>500ms → 高度怀疑盲注漏洞\n");
        sb.append("- 极短响应(<10ms) → 可能: WAF拦截、缓存、请求被拒\n");
        sb.append("发现时序异常时，请在 evidence 中引用具体 TTFB/TTLB 数值。\n\n");

        // WAF 绕过分析指导
        sb.append(FullVulnDatabase.WAF_BYPASS_KNOWLEDGE);
        sb.append("请在分析时主动检测WAF特征，如果响应中存在WAF拦截迹象：\n");
        sb.append("1. 在 evidence 中标注检测到的WAF类型\n");
        sb.append("2. 在 suggestion 中给出具体绕过技术建议\n");
        sb.append("3. 被 WAF 拦截的请求仍可能是漏洞的间接证据\n\n");

        // OOB 带外测试域名
        if (oobDomain != null && !oobDomain.isEmpty())
        {
            sb.append("## OOB 带外测试域名\n");
            sb.append("当前可用的带外测试域名: ").append(oobDomain).append("\n");
            sb.append("当发现SSRF、XXE、盲注等需要带外验证的漏洞时，");
            sb.append("请在 suggestion 中给出使用此域名的具体payload。\n\n");
        }

        for (int i = 0; i < batch.size(); i++)
        {
            TrafficData item = batch.get(i);
            sb.append("---请求 #").append(i + 1).append("---\n");
            sb.append(truncate(item.getRequestStr(), 3000)).append("\n\n");
            if (item.hasResponse())
            {
                sb.append("---响应 #").append(i + 1).append("---\n");
                sb.append("[状态码: ").append(item.getStatusCode()).append("]\n");

                // 从 TrafficData 中读取时序数据
                if (item.hasTimingData())
                {
                    sb.append("[响应时间: ");
                    boolean first = true;
                    if (item.getTtfbMs() > 0)
                    {
                        sb.append("TTFB=").append(item.getTtfbMs()).append("ms");
                        first = false;
                    }
                    if (item.getTtlbMs() > 0)
                    {
                        if (!first) sb.append(", ");
                        sb.append("TTLB=").append(item.getTtlbMs()).append("ms");
                    }
                    sb.append("]\n");
                }

                sb.append(truncate(item.getResponseStr(), 2000)).append("\n\n");
            }
        }

        return sb.toString();
    }

    // ==================== 结果解析 ====================

    private List<VulnReport> parseAnalysisResults(String aiResponse, List<TrafficData> batch)
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
                r.setHost(extractHostFromUrl(r.getUrl()));

                for (String tag : AiResponseParser.getStringList(m, "tags"))
                {
                    r.addTag(tag);
                }

                int targetIndex = AiResponseParser.getInt(m, "targetIndex", -1);
                if (targetIndex > 0 && targetIndex <= batch.size())
                {
                    TrafficData source = batch.get(targetIndex - 1);
                    r.setOriginalRequest(source.getRequestStr());
                    r.setSecure(source.isSecure());
                    if (source.hasResponse())
                    {
                        r.setResponseCode(String.valueOf(source.getStatusCode()));
                        r.setOriginalResponse(source.getResponseStr());
                    }
                    if (source.getTtfbMs() > 0) r.setTtfbMs(source.getTtfbMs());
                    if (source.getTtlbMs() > 0) r.setTtlbMs(source.getTtlbMs());
                }
                else
                {
                    // fallback: 从 URL 推断 secure
                    String rUrl = r.getUrl();
                    r.setSecure(rUrl != null && rUrl.toLowerCase().startsWith("https://"));
                }
                r.setReproduceRequest(AiResponseParser.getString(m, "verifyRequest"));

                r.setConfidence(AiResponseParser.getDouble(m, "confidence", 0.0));
                reports.add(r);
            }
        }
        catch (Exception ignored) {}
        return VulnFindingPolicy.keepTopOnePerRequest(reports);
    }

    // ==================== 可疑度评分 ====================

    private int computeSuspicionScore(TrafficData data)
    {
        int score = 0;
        String request = data.getRequestStr().toLowerCase();
        String response = data.hasResponse() ? data.getResponseStr().toLowerCase() : "";

        String method = data.getMethod().toUpperCase();
        if ("POST".equals(method)) score += 3;
        else if ("PUT".equals(method) || "DELETE".equals(method)) score += 5;

        String url = data.getUrl();
        int paramCount = countChar(url, '&') + countChar(url, '=');
        score += Math.min(paramCount, 10);

        if (response.contains("error") || response.contains("exception")) score += 5;
        if (response.contains("sql") && response.contains("syntax")) score += 8;
        if (response.contains("stack") && response.contains("trace")) score += 6;
        if (response.contains("permission") || response.contains("denied")) score += 4;
        if (response.contains("admin") || response.contains("debug")) score += 3;

        if (request.contains("authorization") || request.contains("cookie")
            || request.contains("token") || request.contains("session"))
        {
            score += 3;
        }

        if (request.contains("multipart/form-data") || request.contains("upload")
            || request.contains("filename="))
        {
            score += 5;
        }

        if (data.hasResponse())
        {
            int statusCode = data.getStatusCode();
            if (statusCode >= 500) score += 5;
            else if (statusCode == 403) score += 4;
            else if (statusCode == 401) score += 3;
        }

        // 时序异常评分
        if (data.getTtfbMs() > 5000) score += 8;
        else if (data.getTtfbMs() > 2000) score += 5;
        else if (data.getTtfbMs() > 1000) score += 2;

        if (data.getTtfbMs() > 0 && data.getTtlbMs() > 0)
        {
            long transferTime = data.getTtlbMs() - data.getTtfbMs();
            if (transferTime > 3000) score += 5;
            else if (transferTime > 1000) score += 3;
        }

        return score;
    }

    // ==================== 工具方法 ====================

    private String extractHostFromUrl(String url)
    {
        if (url == null || url.isEmpty()) return null;
        try
        {
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

    private int countChar(String s, char c)
    {
        int count = 0;
        for (int i = 0; i < s.length(); i++)
        {
            if (s.charAt(i) == c) count++;
        }
        return count;
    }

    private void cleanupDebounceMap()
    {
        long now = System.currentTimeMillis();
        Iterator<Map.Entry<String, Long>> it = lastAnalyzedHost.entrySet().iterator();
        while (it.hasNext())
        {
            Map.Entry<String, Long> entry = it.next();
            if ((now - entry.getValue()) > debounceMs * 2)
            {
                it.remove();
            }
        }
    }

    private String buildSummary(List<VulnReport> results, List<TrafficData> batch)
    {
        if (results.isEmpty())
        {
            return "实时分析完成：分析 " + batch.size() + " 个请求，未发现安全风险。";
        }

        StringBuilder sb = new StringBuilder();
        sb.append("实时分析完成：分析 ").append(batch.size()).append(" 个请求，发现 ")
            .append(results.size()).append(" 个风险点。");

        Map<VulnReport.Severity, Integer> severityCount = new EnumMap<>(VulnReport.Severity.class);
        for (VulnReport r : results)
        {
            severityCount.merge(r.getSeverity(), 1, Integer::sum);
        }

        sb.append(" [");
        boolean first = true;
        for (VulnReport.Severity sev : VulnReport.Severity.values())
        {
            int c = severityCount.getOrDefault(sev, 0);
            if (c > 0)
            {
                if (!first) sb.append(", ");
                sb.append(sev.label()).append(": ").append(c);
                first = false;
            }
        }
        sb.append("]");

        return sb.toString();
    }

    private String truncate(String text, int maxLen)
    {
        if (text == null) return "";
        if (text.length() <= maxLen) return text;
        return text.substring(0, maxLen) + "\n... [已截断]";
    }

    /**
     * 标注代理历史 - AI分析发现漏洞后，在Proxy HTTP History中标记对应条目。
     */
    private void annotateProxyHistory(List<TrafficData> batch, List<VulnReport> reports)
    {
        try
        {
            // 获取代理历史
            List<ProxyHttpRequestResponse> history = api.proxy().history();
            if (history == null || history.isEmpty()) return;

            for (VulnReport report : reports)
            {
                String reportUrl = report.getUrl();
                String reportMethod = report.getMethod();
                if (reportUrl == null || reportUrl.isEmpty()) continue;

                // 在代理历史中查找匹配项（从最近的开始）
                for (int i = history.size() - 1; i >= Math.max(0, history.size() - 50); i--)
                {
                    try
                    {
                        ProxyHttpRequestResponse item = history.get(i);
                        String itemUrl = item.finalRequest().url();
                        String itemMethod = item.finalRequest().method();

                        // URL和Method匹配
                        if (reportUrl.equals(itemUrl) && (reportMethod == null || reportMethod.equals(itemMethod)))
                        {
                            // 设置高亮颜色
                            burp.api.montoya.core.HighlightColor color;
                            VulnReport.Severity severity = report.getSeverity();
                            if (severity == VulnReport.Severity.CRITICAL || severity == VulnReport.Severity.HIGH)
                            {
                                color = burp.api.montoya.core.HighlightColor.RED;
                            }
                            else if (severity == VulnReport.Severity.MEDIUM)
                            {
                                color = burp.api.montoya.core.HighlightColor.ORANGE;
                            }
                            else
                            {
                                color = burp.api.montoya.core.HighlightColor.YELLOW;
                            }

                            // 更新注释和高亮
                            String note = "AI发现: " + report.getVulnType()
                                + " [" + report.getSeverity().label() + "]"
                                + (report.getParameter() != null && !report.getParameter().isEmpty()
                                ? " 参数: " + report.getParameter() : "");

                            item.annotations().setNotes(note);
                            item.annotations().setHighlightColor(color);

                            api.logging().logToOutput("[Proxy] 已标注: " + report.getVulnType()
                                + " - " + truncate(reportUrl, 60));
                            break; // 每个报告只标注第一个匹配项
                        }
                    }
                    catch (Exception ignored) {}
                }
            }
        }
        catch (Exception e)
        {
            api.logging().logToError("[Proxy] Annotation error: " + e.getMessage());
        }
    }
}
