package ai.burp.config;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.Properties;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.Preferences;

/**
 * by ai 扩展配置管理。
 * 独立配置文件持久化 (~/.byai/config.properties)，Burp Preferences 作为兼容回退。
 */
public class ExtensionConfig
{
    private static final String CONFIG_DIR_NAME = ".byai";
    private static final String CONFIG_FILE_NAME = "config.properties";

    private static final String KEY_API_URL = "apiUrl";
    private static final String KEY_API_KEY = "apiKey";
    private static final String KEY_MODEL = "model";
    private static final String KEY_SYSTEM_PROMPT = "systemPrompt";
    private static final String KEY_PROXY_ENABLED = "proxyEnabled";
    private static final String KEY_STREAMING_ENABLED = "streamingEnabled";
    private static final String KEY_PASSIVE_SCAN_ENABLED = "passiveScanEnabled";
    private static final String KEY_ACTIVE_SCAN_ENABLED = "activeScanEnabled";
    private static final String KEY_MAX_SCAN_ENDPOINTS = "maxScanEndpoints";
    private static final String KEY_SUSPICION_THRESHOLD = "suspicionThreshold";
    private static final String KEY_DEBOUNCE_MS = "debounceMs";
    private static final String KEY_DNSLOG_DOMAIN = "dnslogDomain";
    private static final String KEY_USE_COLLABORATOR = "useCollaborator";

    // 旧版 Preferences 键名（用于迁移）
    private static final String OLD_KEY_API_URL = "ai.apiUrl";
    private static final String OLD_KEY_API_KEY = "ai.apiKey";
    private static final String OLD_KEY_MODEL = "ai.model";
    private static final String OLD_KEY_SYSTEM_PROMPT = "ai.systemPrompt";
    private static final String OLD_KEY_PROXY_ENABLED = "ai.proxyEnabled";
    private static final String OLD_KEY_STREAMING_ENABLED = "ai.streamingEnabled";
    private static final String OLD_KEY_PASSIVE_SCAN_ENABLED = "ai.passiveScanEnabled";
    private static final String OLD_KEY_ACTIVE_SCAN_ENABLED = "ai.activeScanEnabled";
    private static final String OLD_KEY_MAX_SCAN_ENDPOINTS = "ai.maxScanEndpoints";
    private static final String OLD_KEY_SUSPICION_THRESHOLD = "ai.suspicionThreshold";
    private static final String OLD_KEY_DEBOUNCE_MS = "ai.debounceMs";
    private static final String OLD_KEY_DNSLOG_DOMAIN = "ai.dnslogDomain";
    private static final String OLD_KEY_USE_COLLABORATOR = "ai.useCollaborator";

    // Defaults
    public static final String DEFAULT_API_URL = "https://api.openai.com/v1";
    public static final String DEFAULT_MODEL = "gpt-4o";
    public static final String DEFAULT_SYSTEM_PROMPT =
        "你是 by ai 安全助手，集成在 Burp Suite 中的 AI 安全测试平台。\n\n" +
        "## 能力\n" +
        "- 分析 HTTP 请求/响应，识别安全漏洞\n" +
        "- 生成针对性的安全测试载荷\n" +
        "- 解释安全概念和攻击原理\n" +
        "- 提供漏洞修复建议\n\n" +
        "## 输出规范\n" +
        "- 回答简洁专业，使用 Markdown 格式\n" +
        "- 测试请求放在 ```http 代码块中，用户可直接发送并获取分析\n" +
        "- 每个测试请求自包含完整请求行和必要请求头\n" +
        "- 仅生成用于授权安全测试的探测类载荷";

    private final Preferences prefs;
    private final Path configDir;
    private final Path configFile;

    // Current values (cached for fast access)
    private String apiUrl;
    private String apiKey;
    private String model;
    private String systemPrompt;
    private boolean proxyEnabled;
    private boolean streamingEnabled;
    private boolean passiveScanEnabled;
    private boolean activeScanEnabled;
    private int maxScanEndpoints;
    private int suspicionThreshold;
    private long debounceMs;
    private String dnslogDomain;
    private boolean useCollaborator;
    private String oobDomain = "";

    public ExtensionConfig(MontoyaApi api)
    {
        this.prefs = api.persistence().preferences();
        this.configDir = Paths.get(System.getProperty("user.home"), CONFIG_DIR_NAME);
        this.configFile = configDir.resolve(CONFIG_FILE_NAME);
        ensureConfigDir();
        load();
    }

    /**
     * 获取配置目录路径。
     */
    public Path getConfigDir() { return configDir; }

    /**
     * 获取配置文件路径。
     */
    public Path getConfigFile() { return configFile; }

    /**
     * 确保配置目录存在。
     */
    private void ensureConfigDir()
    {
        try
        {
            if (!Files.exists(configDir))
            {
                Files.createDirectories(configDir);
            }
        }
        catch (Exception ignored) {}
    }

    /**
     * 从独立配置文件加载 Properties。
     */
    private Properties loadFromFile()
    {
        Properties props = new Properties();
        if (Files.exists(configFile))
        {
            try (InputStream is = Files.newInputStream(configFile))
            {
                props.load(new InputStreamReader(is, StandardCharsets.UTF_8));
            }
            catch (Exception ignored) {}
        }
        return props;
    }

    /**
     * 保存 Properties 到独立配置文件。
     */
    private void saveToFile(Properties props)
    {
        try (OutputStream os = Files.newOutputStream(configFile))
        {
            props.store(new OutputStreamWriter(os, StandardCharsets.UTF_8), "by ai configuration");
        }
        catch (Exception ignored) {}
    }

    /**
     * 从旧版 Burp Preferences 迁移配置到独立文件。
     * 仅在文件不存在且 Preferences 有数据时执行。
     */
    private void migrateFromPrefs()
    {
        if (Files.exists(configFile)) return;

        // 检查 Preferences 中是否有配置数据
        String oldKey = prefs.getString(OLD_KEY_API_KEY);
        if (oldKey == null || oldKey.isEmpty()) return;

        Properties props = new Properties();

        String val;
        Boolean bVal;
        Integer iVal;

        val = prefs.getString(OLD_KEY_API_URL);
        if (val != null) props.setProperty(KEY_API_URL, val);

        val = prefs.getString(OLD_KEY_API_KEY);
        if (val != null) props.setProperty(KEY_API_KEY, val);

        val = prefs.getString(OLD_KEY_MODEL);
        if (val != null) props.setProperty(KEY_MODEL, val);

        val = prefs.getString(OLD_KEY_SYSTEM_PROMPT);
        if (val != null) props.setProperty(KEY_SYSTEM_PROMPT, val);

        bVal = prefs.getBoolean(OLD_KEY_PROXY_ENABLED);
        if (bVal != null) props.setProperty(KEY_PROXY_ENABLED, String.valueOf(bVal));

        bVal = prefs.getBoolean(OLD_KEY_STREAMING_ENABLED);
        if (bVal != null) props.setProperty(KEY_STREAMING_ENABLED, String.valueOf(bVal));

        bVal = prefs.getBoolean(OLD_KEY_PASSIVE_SCAN_ENABLED);
        if (bVal != null) props.setProperty(KEY_PASSIVE_SCAN_ENABLED, String.valueOf(bVal));

        bVal = prefs.getBoolean(OLD_KEY_ACTIVE_SCAN_ENABLED);
        if (bVal != null) props.setProperty(KEY_ACTIVE_SCAN_ENABLED, String.valueOf(bVal));

        iVal = prefs.getInteger(OLD_KEY_MAX_SCAN_ENDPOINTS);
        if (iVal != null) props.setProperty(KEY_MAX_SCAN_ENDPOINTS, String.valueOf(iVal));

        iVal = prefs.getInteger(OLD_KEY_SUSPICION_THRESHOLD);
        if (iVal != null) props.setProperty(KEY_SUSPICION_THRESHOLD, String.valueOf(iVal));

        val = prefs.getString(OLD_KEY_DEBOUNCE_MS);
        if (val != null && !val.isEmpty()) props.setProperty(KEY_DEBOUNCE_MS, val);

        val = prefs.getString(OLD_KEY_DNSLOG_DOMAIN);
        if (val != null) props.setProperty(KEY_DNSLOG_DOMAIN, val);

        bVal = prefs.getBoolean(OLD_KEY_USE_COLLABORATOR);
        if (bVal != null) props.setProperty(KEY_USE_COLLABORATOR, String.valueOf(bVal));

        saveToFile(props);
    }

    public void load()
    {
        // 先尝试迁移旧配置
        migrateFromPrefs();

        // 从独立文件加载
        Properties props = loadFromFile();

        apiUrl = props.getProperty(KEY_API_URL, DEFAULT_API_URL);
        apiKey = props.getProperty(KEY_API_KEY, "");
        model = props.getProperty(KEY_MODEL, DEFAULT_MODEL);
        systemPrompt = props.getProperty(KEY_SYSTEM_PROMPT, DEFAULT_SYSTEM_PROMPT);
        proxyEnabled = Boolean.parseBoolean(props.getProperty(KEY_PROXY_ENABLED, "false"));
        streamingEnabled = Boolean.parseBoolean(props.getProperty(KEY_STREAMING_ENABLED, "true"));
        passiveScanEnabled = Boolean.parseBoolean(props.getProperty(KEY_PASSIVE_SCAN_ENABLED, "true"));
        activeScanEnabled = Boolean.parseBoolean(props.getProperty(KEY_ACTIVE_SCAN_ENABLED, "true"));
        maxScanEndpoints = parseIntSafe(props.getProperty(KEY_MAX_SCAN_ENDPOINTS), 500);
        suspicionThreshold = parseIntSafe(props.getProperty(KEY_SUSPICION_THRESHOLD), 5);
        debounceMs = parseLongSafe(props.getProperty(KEY_DEBOUNCE_MS), 120000L);
        dnslogDomain = props.getProperty(KEY_DNSLOG_DOMAIN, "");
        useCollaborator = Boolean.parseBoolean(props.getProperty(KEY_USE_COLLABORATOR, "true"));
    }

    public void save()
    {
        // 保存到独立配置文件
        Properties props = new Properties();
        props.setProperty(KEY_API_URL, apiUrl != null ? apiUrl : "");
        props.setProperty(KEY_API_KEY, apiKey != null ? apiKey : "");
        props.setProperty(KEY_MODEL, model != null ? model : "");
        props.setProperty(KEY_SYSTEM_PROMPT, systemPrompt != null ? systemPrompt : "");
        props.setProperty(KEY_PROXY_ENABLED, String.valueOf(proxyEnabled));
        props.setProperty(KEY_STREAMING_ENABLED, String.valueOf(streamingEnabled));
        props.setProperty(KEY_PASSIVE_SCAN_ENABLED, String.valueOf(passiveScanEnabled));
        props.setProperty(KEY_ACTIVE_SCAN_ENABLED, String.valueOf(activeScanEnabled));
        props.setProperty(KEY_MAX_SCAN_ENDPOINTS, String.valueOf(maxScanEndpoints));
        props.setProperty(KEY_SUSPICION_THRESHOLD, String.valueOf(suspicionThreshold));
        props.setProperty(KEY_DEBOUNCE_MS, String.valueOf(debounceMs));
        props.setProperty(KEY_DNSLOG_DOMAIN, dnslogDomain != null ? dnslogDomain : "");
        props.setProperty(KEY_USE_COLLABORATOR, String.valueOf(useCollaborator));
        saveToFile(props);

        // 同步保存到 Burp Preferences（兼容回退）
        prefs.setString(OLD_KEY_API_URL, apiUrl);
        prefs.setString(OLD_KEY_API_KEY, apiKey);
        prefs.setString(OLD_KEY_MODEL, model);
        prefs.setString(OLD_KEY_SYSTEM_PROMPT, systemPrompt);
        prefs.setBoolean(OLD_KEY_PROXY_ENABLED, proxyEnabled);
        prefs.setBoolean(OLD_KEY_STREAMING_ENABLED, streamingEnabled);
        prefs.setBoolean(OLD_KEY_PASSIVE_SCAN_ENABLED, passiveScanEnabled);
        prefs.setBoolean(OLD_KEY_ACTIVE_SCAN_ENABLED, activeScanEnabled);
        prefs.setInteger(OLD_KEY_MAX_SCAN_ENDPOINTS, maxScanEndpoints);
        prefs.setInteger(OLD_KEY_SUSPICION_THRESHOLD, suspicionThreshold);
        prefs.setString(OLD_KEY_DEBOUNCE_MS, String.valueOf(debounceMs));
        prefs.setString(OLD_KEY_DNSLOG_DOMAIN, dnslogDomain != null ? dnslogDomain : "");
        prefs.setBoolean(OLD_KEY_USE_COLLABORATOR, useCollaborator);
    }

    private static int parseIntSafe(String val, int def)
    {
        if (val == null || val.isEmpty()) return def;
        try { return Integer.parseInt(val); }
        catch (NumberFormatException e) { return def; }
    }

    private static long parseLongSafe(String val, long def)
    {
        if (val == null || val.isEmpty()) return def;
        try { return Long.parseLong(val); }
        catch (NumberFormatException e) { return def; }
    }

    public boolean isConfigured()
    {
        return apiKey != null && !apiKey.trim().isEmpty()
            && apiUrl != null && !apiUrl.trim().isEmpty();
    }

    // Getters and setters

    public String getApiUrl() { return apiUrl; }
    public void setApiUrl(String apiUrl) { this.apiUrl = apiUrl; }

    public String getApiKey() { return apiKey; }
    public void setApiKey(String apiKey) { this.apiKey = apiKey; }

    public String getModel() { return model; }
    public void setModel(String model) { this.model = model; }

    public String getSystemPrompt() { return systemPrompt; }
    public void setSystemPrompt(String systemPrompt) { this.systemPrompt = systemPrompt; }

    public boolean isProxyEnabled() { return proxyEnabled; }
    public void setProxyEnabled(boolean proxyEnabled) { this.proxyEnabled = proxyEnabled; }

    public boolean isStreamingEnabled() { return streamingEnabled; }
    public void setStreamingEnabled(boolean streamingEnabled) { this.streamingEnabled = streamingEnabled; }

    public boolean isPassiveScanEnabled() { return passiveScanEnabled; }
    public void setPassiveScanEnabled(boolean passiveScanEnabled) { this.passiveScanEnabled = passiveScanEnabled; }

    public boolean isActiveScanEnabled() { return activeScanEnabled; }
    public void setActiveScanEnabled(boolean activeScanEnabled) { this.activeScanEnabled = activeScanEnabled; }

    public int getMaxScanEndpoints() { return maxScanEndpoints; }
    public void setMaxScanEndpoints(int maxScanEndpoints) { this.maxScanEndpoints = maxScanEndpoints; }

    public int getSuspicionThreshold() { return suspicionThreshold; }
    public void setSuspicionThreshold(int suspicionThreshold) { this.suspicionThreshold = suspicionThreshold; }

    public long getDebounceMs() { return debounceMs; }
    public void setDebounceMs(long debounceMs) { this.debounceMs = debounceMs; }

    public String getDnslogDomain() { return dnslogDomain; }
    public void setDnslogDomain(String dnslogDomain) { this.dnslogDomain = dnslogDomain; }

    public boolean isUseCollaborator() { return useCollaborator; }
    public void setUseCollaborator(boolean useCollaborator) { this.useCollaborator = useCollaborator; }

    /**
     * 获取当前有效的 OOB 域名（Collaborator 或自定义 DNSLog）。
     * @return OOB 域名，未配置则返回空字符串
     */
    public String getEffectiveOobDomain()
    {
        return oobDomain;
    }

    /**
     * 设置运行时 OOB 域名（由 by ai 主入口初始化时根据配置生成）。
     */
    public void setEffectiveOobDomain(String domain)
    {
        this.oobDomain = domain != null ? domain : "";
    }
}
