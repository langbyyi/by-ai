package ai.burp.scanner;

import java.util.*;
import java.util.stream.Collectors;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.sitemap.SiteMap;

import ai.burp.model.ChatMessage;
import ai.burp.provider.StreamingAIProvider;
import ai.burp.util.AiResponseParser;
import ai.burp.util.SimpleJson;

/**
 * 攻击面测绘引擎 - 全量爬取目标HTTP请求/响应/接口/功能点/隐藏接口。
 * 合并SiteMap和Proxy历史，AI分析生成完整攻击面图谱。
 */
public class AttackSurfaceMapper
{
    private final MontoyaApi api;
    private final StreamingAIProvider provider;
    private final AuditLogger logger;

    public AttackSurfaceMapper(MontoyaApi api, StreamingAIProvider provider, AuditLogger logger)
    {
        this.api = api;
        this.provider = provider;
        this.logger = logger;
    }

    /**
     * 执行攻击面测绘（所有主机）。
     */
    public AttackSurface map()
    {
        return map(null);
    }

    /**
     * 执行攻击面测绘（指定主机）。
     * @param targetHost 目标主机名，null 表示扫描所有主机。
     */
    public AttackSurface map(String targetHost)
    {
        // 收集所有已知URL
        Set<String> allUrls = new LinkedHashSet<>();
        Map<String, String> urlMethodMap = new LinkedHashMap<>(); // url → method+path

        // 从SiteMap获取
        List<HttpRequestResponse> siteMapItems = api.siteMap().requestResponses();
        for (HttpRequestResponse item : siteMapItems)
        {
            try
            {
                String h = item.httpService().host();
                if (targetHost != null && !targetHost.equals(h)) continue;
                String url = item.request().url();
                String method = item.request().method();
                String key = method + " " + simplifyUrl(url);
                if (!urlMethodMap.containsKey(key))
                {
                    urlMethodMap.put(key, method + " " + truncate(url, 120));
                    allUrls.add(url);
                }
            }
            catch (Exception ignored) {}
        }

        // 从Proxy历史获取
        List<ProxyHttpRequestResponse> proxyHistory = api.proxy().history();
        for (ProxyHttpRequestResponse item : proxyHistory)
        {
            try
            {
                String h = item.finalRequest().httpService().host();
                if (targetHost != null && !targetHost.equals(h)) continue;
                String url = item.finalRequest().url();
                String method = item.finalRequest().method();
                String key = method + " " + simplifyUrl(url);
                if (!urlMethodMap.containsKey(key))
                {
                    urlMethodMap.put(key, method + " " + truncate(url, 120));
                    allUrls.add(url);
                }
            }
            catch (Exception ignored) {}
        }

        logger.log("攻击面测绘", targetHost != null ? targetHost : "",
            "收集到 " + urlMethodMap.size() + " 个唯一端点");

        AttackSurface surface = new AttackSurface();
        surface.host = targetHost;
        surface.totalEndpoints = urlMethodMap.size();
        surface.allEndpoints = new ArrayList<>(urlMethodMap.values());

        // 基础统计
        analyzeBasics(urlMethodMap, surface);

        // AI深度分析（如果已配置且端点数合理）
        if (provider.isConfigured() && urlMethodMap.size() <= 500)
        {
            try
            {
                String endpoints = String.join("\n", surface.allEndpoints);
                String prompt = FullVulnDatabase.buildAttackSurfacePrompt(endpoints);
                String aiResult = provider.chat(Collections.singletonList(ChatMessage.user(prompt)));

                parseAIResult(aiResult, surface);
                logger.log("攻击面测绘", "", "AI分析完成: " + surface.highRisk.size() + " 个高风险端点");
            }
            catch (Exception e)
            {
                logger.log("攻击面测绘", "", "AI分析失败: " + e.getMessage());
            }
        }

        return surface;
    }

    private void analyzeBasics(Map<String, String> urlMethodMap, AttackSurface surface)
    {
        for (Map.Entry<String, String> entry : urlMethodMap.entrySet())
        {
            String key = entry.getKey().toLowerCase();
            String url = entry.getValue().toLowerCase();

            // 高风险端点检测
            if (key.contains("/admin") || key.contains("/manager") || key.contains("/console"))
            {
                surface.highRisk.add(new RiskEndpoint(entry.getValue(), "管理接口"));
            }
            if (key.contains("upload") || key.contains("file"))
            {
                surface.highRisk.add(new RiskEndpoint(entry.getValue(), "文件操作"));
            }
            if (key.contains("delete") || key.contains("remove"))
            {
                surface.highRisk.add(new RiskEndpoint(entry.getValue(), "删除操作"));
            }
            if (key.contains("login") || key.contains("auth") || key.contains("token"))
            {
                surface.authEndpoints.add(entry.getValue());
            }
            if (key.contains("api") || key.contains("/v1/") || key.contains("/v2/"))
            {
                surface.apiEndpoints.add(entry.getValue());
            }

            // 隐藏接口检测
            if (key.contains("/.git") || key.contains("/.svn") || key.contains("/.env")
                || key.contains("/debug") || key.contains("/test") || key.contains("/internal"))
            {
                surface.hiddenEndpoints.add(entry.getValue());
            }
        }
    }

    @SuppressWarnings("unchecked")
    private void parseAIResult(String aiResult, AttackSurface surface)
    {
        try
        {
            Map<String, Object> parsed = AiResponseParser.parseFirstObject(aiResult);
            if (parsed.isEmpty()) return;

            // 高风险端点
            for (Map<String, Object> m : AiResponseParser.getObjectList(parsed, "highRisk"))
            {
                surface.highRisk.add(new RiskEndpoint(
                    AiResponseParser.getString(m, "url"),
                    AiResponseParser.getString(m, "reason")));
            }

            // 可能遗漏的接口
            for (String item : AiResponseParser.getStringList(parsed, "missingEndpoints"))
            {
                surface.missingEndpoints.add(item);
            }

            // 业务流程
            for (String item : AiResponseParser.getStringList(parsed, "businessFlows"))
            {
                surface.businessFlows.add(item);
            }

            // 攻击面统计
            Map<String, Object> attackSurfaceMap = SimpleJson.getMap(parsed, "attackSurface");
            if (attackSurfaceMap != null)
            {
                surface.unauthenticatedCount = getInt(attackSurfaceMap, "unauthenticated");
                surface.fileUploadCount = getInt(attackSurfaceMap, "fileUpload");
                surface.databaseOpsCount = getInt(attackSurfaceMap, "databaseOps");
                surface.adminPanelCount = getInt(attackSurfaceMap, "adminPanels");
            }
        }
        catch (Exception ignored) {}
    }

    private String getStr(Map<String, Object> m, String key)
    {
        Object v = m.get(key);
        return v instanceof String ? (String) v : "";
    }

    private int getInt(Map<String, Object> m, String key)
    {
        Object v = m.get(key);
        return v instanceof Number ? ((Number) v).intValue() : 0;
    }

    private String simplifyUrl(String url)
    {
        int q = url.indexOf('?');
        String path = q >= 0 ? url.substring(0, q) : url;
        // 去掉协议和host
        int slash3 = path.indexOf("//");
        if (slash3 >= 0)
        {
            int pathStart = path.indexOf("/", slash3 + 2);
            if (pathStart >= 0) return path.substring(pathStart);
        }
        return path;
    }

    private String truncate(String s, int max)
    {
        return s.length() <= max ? s : s.substring(0, max) + "...";
    }

    // ==================== 数据模型 ====================

    public static class AttackSurface
    {
        public String host = null;  // 目标主机，null 表示全局
        public int totalEndpoints = 0;
        public List<String> allEndpoints = new ArrayList<>();
        public List<RiskEndpoint> highRisk = new ArrayList<>();
        public List<String> authEndpoints = new ArrayList<>();
        public List<String> apiEndpoints = new ArrayList<>();
        public List<String> hiddenEndpoints = new ArrayList<>();
        public List<String> missingEndpoints = new ArrayList<>();
        public List<String> businessFlows = new ArrayList<>();
        public int unauthenticatedCount = 0;
        public int fileUploadCount = 0;
        public int databaseOpsCount = 0;
        public int adminPanelCount = 0;
    }

    public static class RiskEndpoint
    {
        public String url;
        public String reason;

        public RiskEndpoint(String url, String reason)
        {
            this.url = url;
            this.reason = reason;
        }
    }
}
