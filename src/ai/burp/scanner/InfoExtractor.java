package ai.burp.scanner;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import ai.burp.util.TextUtils;
import burp.api.montoya.http.message.HttpRequestResponse;

import ai.burp.model.ChatMessage;
import ai.burp.provider.StreamingAIProvider;
import ai.burp.util.AiResponseParser;

/**
 * 关键信息提取器 - AI语义分析提取漏洞利用关键信息。
 * 包括：绝对路径、上传目录、密钥/签名、账号密码、源码泄露、
 * 接口参数规则、业务逻辑流程、隐藏接口。
 */
public class InfoExtractor
{
    /** 已提取的信息缓存（按host索引） */
    private static final ConcurrentHashMap<String, ExtractedInfo> cache = new ConcurrentHashMap<>();

    private final StreamingAIProvider provider;
    private final AuditLogger logger;

    public InfoExtractor(StreamingAIProvider provider, AuditLogger logger)
    {
        this.provider = provider;
        this.logger = logger;
    }

    /**
     * 从HTTP交换中提取关键信息。
     */
    public ExtractedInfo extract(HttpRequestResponse httpData)
    {
        String host = httpData.httpService().host();
        String request = TextUtils.toStringUtf8(httpData.request());
        String response = httpData.hasResponse() ? TextUtils.toStringUtf8(httpData.response()) : "";

        ExtractedInfo info = cache.computeIfAbsent(host, k -> new ExtractedInfo(host));

        // 同一 host 的并发请求可能拿到同一个 ExtractedInfo，对其内部 Set 的修改需要同步
        synchronized (info)
        {
            // 规则快速提取
            ruleBasedExtract(request, response, info);

            // AI深度提取
            if (provider.isConfigured())
            {
                try
                {
                    String prompt = FullVulnDatabase.buildInfoExtractPrompt(request, response);
                    String aiResult = provider.chat(Collections.singletonList(ChatMessage.user(prompt)));
                    aiBasedExtract(aiResult, info);
                }
                catch (Exception ignored) {}
            }

            logger.log("信息提取", host, info.summary());
        }
        return info;
    }

    /**
     * 规则快速提取。
     */
    private void ruleBasedExtract(String request, String response, ExtractedInfo info)
    {
        String lower = response.toLowerCase();

        // 绝对路径检测
        extractPaths(response, info);

        // 源码泄露检测
        if (lower.contains(".git/") || lower.contains(".git/config")) info.addSourceLeak(".git 目录泄露");
        if (lower.contains(".svn/") || lower.contains(".svn/entries")) info.addSourceLeak(".svn 目录泄露");
        if (lower.contains(".env") && (lower.contains("db_") || lower.contains("secret"))) info.addSourceLeak(".env 文件泄露");
        if (lower.contains(".ds_store")) info.addSourceLeak(".DS_Store 文件泄露");
        if (lower.contains("web.config") && lower.contains("<?xml")) info.addSourceLeak("web.config 泄露");
        if (lower.contains("backup") && (lower.contains(".sql") || lower.contains(".zip"))) info.addSourceLeak("备份文件泄露");

        // 堆栈跟踪检测
        if (lower.contains("exception") && lower.contains("at ") && lower.contains(".java:"))
        {
            info.addSourceLeak("Java堆栈跟踪泄露");
        }
        if (lower.contains("traceback (most recent call last)"))
        {
            info.addSourceLeak("Python堆栈跟踪泄露");
        }

        // 数据库错误
        if (lower.contains("sql syntax") || lower.contains("mysql") && lower.contains("error"))
        {
            info.addDatabaseInfo("MySQL 错误信息泄露");
        }
        if (lower.contains("ora-") && lower.contains("error")) info.addDatabaseInfo("Oracle 错误信息泄露");
        if (lower.contains("microsoft sql server") && lower.contains("error")) info.addDatabaseInfo("MSSQL 错误信息泄露");

        // 内部IP检测
        extractInternalIPs(response, info);

        // 隐藏接口检测
        extractHiddenEndpoints(request, response, info);

        // API文档泄露
        if (lower.contains("swagger") || lower.contains("openapi")) info.addSourceLeak("API文档(Swagger)泄露");
        if (lower.contains("graphql") && lower.contains("schema")) info.addSourceLeak("GraphQL Schema泄露");

        // 调试接口
        if (lower.contains("/debug/") || lower.contains("/actuator/")) info.addHiddenEndpoint("调试/监控接口");
    }

    private void extractPaths(String response, ExtractedInfo info)
    {
        // Linux绝对路径
        extractPattern(response, "/var/www/", info.absolutePaths);
        extractPattern(response, "/home/", info.absolutePaths);
        extractPattern(response, "/usr/local/", info.absolutePaths);
        extractPattern(response, "/opt/", info.absolutePaths);
        // Windows绝对路径
        extractPattern(response, "C:\\\\", info.absolutePaths);
        extractPattern(response, "D:\\\\", info.absolutePaths);
        extractPattern(response, "C:/", info.absolutePaths);
    }

    private void extractPattern(String text, String prefix, Set<String> collection)
    {
        int idx = 0;
        while ((idx = text.indexOf(prefix, idx)) != -1)
        {
            int end = Math.min(idx + 80, text.length());
            String path = text.substring(idx, end).split("[\\s\"'<>\\\\]", 2)[0];
            if (path.length() > 5 && path.length() < 80)
            {
                collection.add(path);
            }
            idx++;
        }
    }

    private void extractInternalIPs(String response, ExtractedInfo info)
    {
        extractPattern(response, "192.168.", info.internalIPs);
        extractPattern(response, "10.", info.internalIPs);
        extractPattern(response, "172.16.", info.internalIPs);
        extractPattern(response, "172.17.", info.internalIPs);
    }

    private void extractHiddenEndpoints(String request, String response, ExtractedInfo info)
    {
        String[] sensitivePaths = {
            "/admin", "/manager", "/console", "/debug",
            "/api/v2/", "/internal/", "/test/", "/backup/",
            "/.env", "/.git", "/.svn", "/.htaccess",
            "/server-status", "/server-info", "/phpinfo",
            "/wp-admin", "/wp-config", "/xmlrpc.php",
            "/swagger-ui", "/api-docs", "/graphiql"
        };
        String lower = (request + " " + response).toLowerCase();
        for (String path : sensitivePaths)
        {
            if (lower.contains(path.toLowerCase()))
            {
                info.addHiddenEndpoint(path);
            }
        }
    }

    /**
     * AI深度提取。
     */
    private void aiBasedExtract(String aiResult, ExtractedInfo info)
    {
        try
        {
            Map<String, Object> parsed = AiResponseParser.parseFirstObject(aiResult);
            if (parsed.isEmpty()) return;

            extractListField(parsed, "absolutePaths", info.absolutePaths);
            extractListField(parsed, "uploadDirs", info.uploadDirs);
            extractListField(parsed, "keys", info.keys);
            extractListField(parsed, "credentials", info.credentials);
            extractListField(parsed, "sourceCodeLeak", info.sourceLeaks);
            extractListField(parsed, "hiddenEndpoints", info.hiddenEndpoints);
            extractListField(parsed, "internalIPs", info.internalIPs);

            String webRoot = AiResponseParser.getString(parsed, "webRoot");
            if (!webRoot.isEmpty()) info.webRoot = webRoot;

            String paramRules = AiResponseParser.getString(parsed, "parameterRules");
            if (!paramRules.isEmpty()) info.parameterRules = paramRules;

            String businessLogic = AiResponseParser.getString(parsed, "businessLogic");
            if (!businessLogic.isEmpty()) info.businessLogic = businessLogic;

            String dbInfo = AiResponseParser.getString(parsed, "databaseInfo");
            if (!dbInfo.isEmpty()) info.addDatabaseInfo(dbInfo);
        }
        catch (Exception ignored) {}
    }

    private void extractListField(Map<String, Object> parsed, String key, Set<String> target)
    {
        for (String item : AiResponseParser.getStringList(parsed, key))
        {
            target.add(item);
        }
    }

    public static ExtractedInfo getInfo(String host)
    {
        return cache.get(host);
    }

    /**
     * 清除指定 host 的缓存，强制下次重新分析。
     */
    public static void invalidate(String host)
    {
        cache.remove(host);
    }

    /**
     * 提取信息数据模型。
     */
    public static class ExtractedInfo
    {
        public final String host;
        public final Set<String> absolutePaths = new LinkedHashSet<>();
        public final Set<String> uploadDirs = new LinkedHashSet<>();
        public String webRoot = "";
        public final Set<String> keys = new LinkedHashSet<>();
        public final Set<String> credentials = new LinkedHashSet<>();
        public final Set<String> sourceLeaks = new LinkedHashSet<>();
        public String parameterRules = "";
        public String businessLogic = "";
        public final Set<String> hiddenEndpoints = new LinkedHashSet<>();
        public final Set<String> databaseInfos = new LinkedHashSet<>();
        public final Set<String> internalIPs = new LinkedHashSet<>();

        public ExtractedInfo(String host) { this.host = host; }

        public void addSourceLeak(String v) { sourceLeaks.add(v); }
        public void addDatabaseInfo(String v) { databaseInfos.add(v); }
        public void addHiddenEndpoint(String v) { hiddenEndpoints.add(v); }
        public void addCredential(String v) { credentials.add(v); }
        public void addKey(String v) { keys.add(v); }

        public String summary()
        {
            StringBuilder sb = new StringBuilder();
            if (!absolutePaths.isEmpty()) sb.append("路径:").append(absolutePaths.size()).append(" ");
            if (!sourceLeaks.isEmpty()) sb.append("泄露:").append(sourceLeaks.size()).append(" ");
            if (!credentials.isEmpty()) sb.append("凭证:").append(credentials.size()).append(" ");
            if (!hiddenEndpoints.isEmpty()) sb.append("隐藏接口:").append(hiddenEndpoints.size()).append(" ");
            return sb.length() > 0 ? sb.toString() : "无特殊信息";
        }
    }
}
