package ai.burp;

import javax.swing.*;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.Scanner;
import burp.api.montoya.scanner.scancheck.ScanCheckType;

import ai.burp.config.ExtensionConfig;
import ai.burp.provider.StreamingAIProvider;
import ai.burp.provider.OpenAIStreamingProvider;
import ai.burp.scanner.AuditLogger;
import ai.burp.scanner.RealtimeTrafficHandler;
import ai.burp.scanner.AIPassiveScanner;
import ai.burp.scanner.AIActiveScanner;
import ai.burp.scanner.AIIntruderProvider;
import ai.burp.scanner.TechFingerprint;
import ai.burp.scanner.InfoExtractor;
import ai.burp.scanner.FullVulnDatabase;
import ai.burp.scanner.CollaboratorHelper;
import ai.burp.ui.MainTabPanel;
import ai.burp.ui.ContextMenuHandler;

import static ai.burp.ui.ChineseUI.*;

/**
 * by ai - AI 驱动的企业级安全测试平台。
 *
 * 深度集成 Burp Suite 四大核心模块:
 * - Proxy: 被动扫描器自动分析所有流量
 * - Scanner: 主动扫描器AI生成针对性Payload
 * - Intruder: AI智能载荷生成器
 * - Repeater: 漏洞验证结果自动发送
 */
public class BurpAIExtension implements BurpExtension
{
    /** 当前版本号 */
    public static final String VERSION = "1.0.0";

    private MontoyaApi api;
    private ExtensionConfig config;
    private StreamingAIProvider provider;
    private StreamingAIProvider scannerProvider;
    private StreamingAIProvider realtimeProvider;
    private StreamingAIProvider intruderProvider;
    private StreamingAIProvider trafficProvider;
    private MainTabPanel mainTabPanel;
    private AuditLogger auditLogger;
    private AIPassiveScanner passiveScanner;
    private RealtimeTrafficHandler realtimeHandler;

    /**
     * Montoya 扩展加载要求的 public 无参构造函数。
     */
    public BurpAIExtension()
    {
    }

    @Override
    public void initialize(MontoyaApi api)
    {
        this.api = api;

        // 设置扩展名
        api.extension().setName(TAB_MAIN);

        // 初始化配置
        config = new ExtensionConfig(api);

        // 初始化 OOB 带外测试域名
        initializeOobDomain(api);

        // 初始化流式 AI 提供者
        provider = new OpenAIStreamingProvider(config, api);
        scannerProvider = new OpenAIStreamingProvider(config, api);
        realtimeProvider = new OpenAIStreamingProvider(config, api);
        intruderProvider = new OpenAIStreamingProvider(config, api);
        trafficProvider = new OpenAIStreamingProvider(config, api);

        // 初始化审计日志
        auditLogger = new AuditLogger(api);
        auditLogger.loadVulnReports();

        // 初始化技术指纹和信息提取器
        TechFingerprint fingerprint = new TechFingerprint(scannerProvider, auditLogger);
        InfoExtractor infoExtractor = new InfoExtractor(scannerProvider, auditLogger);

        // 初始化被动扫描器
        passiveScanner = new AIPassiveScanner(scannerProvider, fingerprint, infoExtractor, auditLogger);
        passiveScanner.setApi(api);

        // 漏洞报告清空时重置被动扫描器的已扫描缓存
        auditLogger.setReportsClearedCallback(() -> passiveScanner.clearScannedCache());

        // 创建主标签面板（6个标签页）
        mainTabPanel = new MainTabPanel(provider, trafficProvider, config, api, auditLogger,
            fingerprint, infoExtractor);

        // 恢复持久化的漏洞报告到报告面板
        if (!auditLogger.getVulnReports().isEmpty())
        {
            SwingUtilities.invokeLater(() -> {
                mainTabPanel.getReportPanel().refreshVulnReports(auditLogger.getVulnReports());
            });
        }

        // 初始化实时流量监控处理器
        realtimeHandler = new RealtimeTrafficHandler(api, realtimeProvider);
        realtimeHandler.setOobDomain(config.getEffectiveOobDomain());

        // 接线：被动扫描器 → 仪表盘同步
        passiveScanner.setCallback(new AIPassiveScanner.ScanCallback()
        {
            @Override
            public void onTechStackIdentified(ai.burp.scanner.TechFingerprint.TechStack tech)
            {
                SwingUtilities.invokeLater(() -> mainTabPanel.getDashboardPanel().updateTechStack(tech));
            }

            @Override
            public void onVulnerabilityFound()
            {
                SwingUtilities.invokeLater(() -> {
                    mainTabPanel.getReportPanel().refreshVulnReports(auditLogger.getVulnReports());
                });
            }
        });

        // 注册 Suite 标签页
        api.userInterface().registerSuiteTab(TAB_MAIN, mainTabPanel);

        // 注册右键菜单
        api.userInterface().registerContextMenuItemsProvider(
            new ContextMenuHandler(mainTabPanel, provider, api, auditLogger));

        // 注册 Burp 原生被动扫描器
        if (config.isPassiveScanEnabled())
        {
            try
            {
                Scanner scanner = api.scanner();
                scanner.registerPassiveScanCheck(passiveScanner, ScanCheckType.PER_REQUEST);
                api.logging().logToOutput("[Scanner] AI Passive Scanner registered (enabled)");
            }
            catch (Exception e)
            {
                api.logging().logToError("[Scanner] Passive scanner registration failed: " + e.getMessage());
            }
        }
        else
        {
            api.logging().logToOutput("[Scanner] AI Passive Scanner disabled by config");
        }

        // 注册 Burp 原生主动扫描器
        if (config.isActiveScanEnabled())
        {
            try
            {
                Scanner scanner = api.scanner();
                AIActiveScanner activeScanner = new AIActiveScanner(scannerProvider, api, auditLogger);
                activeScanner.setCallback(() ->
                    SwingUtilities.invokeLater(() -> {
                        mainTabPanel.getReportPanel().refreshVulnReports(auditLogger.getVulnReports());
                    })
                );
                scanner.registerActiveScanCheck(activeScanner, ScanCheckType.PER_INSERTION_POINT);
                api.logging().logToOutput("[Scanner] AI Active Scanner registered (enabled)");
            }
            catch (Exception e)
            {
                api.logging().logToError("[Scanner] Active scanner registration failed: " + e.getMessage());
            }
        }
        else
        {
            api.logging().logToOutput("[Scanner] AI Active Scanner disabled by config");
        }

        // 注册 Intruder AI 载荷生成器
        try
        {
            api.intruder().registerPayloadGeneratorProvider(
                new AIIntruderProvider(intruderProvider, auditLogger));
            api.logging().logToOutput("[Intruder] AI Payload Generator registered");
        }
        catch (Exception e)
        {
            api.logging().logToError("[Intruder] Payload generator registration failed: " + e.getMessage());
        }

        // 将实时流量监控处理器传递给流量面板
        mainTabPanel.getTrafficPanel().setRealtimeHandler(realtimeHandler);

        // 注册代理请求处理器：对发出请求进行轻量可疑度检测并标注
        try
        {
            api.proxy().registerRequestHandler(new burp.api.montoya.proxy.http.ProxyRequestHandler()
            {
                @Override
                public burp.api.montoya.proxy.http.ProxyRequestReceivedAction handleRequestReceived(
                    burp.api.montoya.proxy.http.InterceptedRequest interceptedRequest)
                {
                    try
                    {
                        String method = interceptedRequest.method();
                        String url = interceptedRequest.url();
                        String body = interceptedRequest.bodyToString();

                        // 轻量级启发式检测（不调用AI，避免每个请求都消耗API）
                        boolean suspicious = false;
                        String reason = "";

                        String urlLower = url.toLowerCase();
                        String bodyLower = body.toLowerCase();

                        // 检测路径遍历
                        if (urlLower.contains("../") || urlLower.contains("..%2f") || urlLower.contains("..%5c"))
                        {
                            suspicious = true;
                            reason = "路径遍历特征";
                        }
                        // 检测SQL注入特征
                        else if (urlLower.contains("' or ") || urlLower.contains("union select")
                            || bodyLower.contains("' or ") || bodyLower.contains("union select"))
                        {
                            suspicious = true;
                            reason = "SQL注入特征";
                        }
                        // 检测XSS特征
                        else if (urlLower.contains("<script") || bodyLower.contains("<script")
                            || urlLower.contains("javascript:") || urlLower.contains("onerror="))
                        {
                            suspicious = true;
                            reason = "XSS特征";
                        }
                        // 检测SSRF特征
                        else if (urlLower.contains("url=http://127.0.0.1") || urlLower.contains("url=http://localhost")
                            || bodyLower.contains("url=http://127.0.0.1") || bodyLower.contains("url=http://localhost"))
                        {
                            suspicious = true;
                            reason = "SSRF特征";
                        }
                        // 检测命令注入特征
                        else if (urlLower.contains("; cat ") || urlLower.contains("| whoami")
                            || bodyLower.contains("; cat ") || bodyLower.contains("| whoami"))
                        {
                            suspicious = true;
                            reason = "命令注入特征";
                        }
                        // 检测敏感路径访问
                        else if (urlLower.contains("/.env") || urlLower.contains("/wp-config.php")
                            || urlLower.contains("/.git/config") || urlLower.contains("/web.config"))
                        {
                            suspicious = true;
                            reason = "敏感文件访问";
                        }

                        if (suspicious)
                        {
                            burp.api.montoya.core.Annotations annotations =
                                burp.api.montoya.core.Annotations.annotations(
                                    "by ai: " + reason,
                                    burp.api.montoya.core.HighlightColor.YELLOW
                                );
                            return burp.api.montoya.proxy.http.ProxyRequestReceivedAction
                                .continueWith(interceptedRequest, annotations);
                        }
                    }
                    catch (Exception e)
                    {
                        api.logging().logToError("[Proxy] Request handler error: " + e.getMessage());
                    }
                    return burp.api.montoya.proxy.http.ProxyRequestReceivedAction
                        .continueWith(interceptedRequest);
                }

                @Override
                public burp.api.montoya.proxy.http.ProxyRequestToBeSentAction handleRequestToBeSent(
                    burp.api.montoya.proxy.http.InterceptedRequest interceptedRequest)
                {
                    return burp.api.montoya.proxy.http.ProxyRequestToBeSentAction
                        .continueWith(interceptedRequest);
                }
            });
            api.logging().logToOutput("[Proxy] Request handler registered (lightweight suspicious pattern detection)");
        }
        catch (Exception e)
        {
            api.logging().logToError("[Proxy] Request handler registration failed: " + e.getMessage());
        }

        // 注册代理响应处理器：将代理流量转发给实时监控
        try
        {
            api.proxy().registerResponseHandler(new burp.api.montoya.proxy.http.ProxyResponseHandler()
            {
                @Override
                public burp.api.montoya.proxy.http.ProxyResponseReceivedAction handleResponseReceived(
                    burp.api.montoya.proxy.http.InterceptedResponse interceptedResponse)
                {
                    try
                    {
                        realtimeHandler.onNewInterceptedResponse(interceptedResponse);
                    }
                    catch (Exception e)
                    {
                        api.logging().logToError("[Proxy] Realtime handler error: " + e.getMessage());
                    }
                    return burp.api.montoya.proxy.http.ProxyResponseReceivedAction.continueWith(interceptedResponse);
                }

                @Override
                public burp.api.montoya.proxy.http.ProxyResponseToBeSentAction handleResponseToBeSent(
                    burp.api.montoya.proxy.http.InterceptedResponse interceptedResponse)
                {
                    return burp.api.montoya.proxy.http.ProxyResponseToBeSentAction.continueWith(interceptedResponse);
                }
            });
            api.logging().logToOutput("[Proxy] Realtime traffic handler registered");
        }
        catch (Exception e)
        {
            api.logging().logToError("[Proxy] Response handler registration failed: " + e.getMessage());
        }

        // 日志输出
        api.logging().logToOutput("=== by ai v" + VERSION + " Loaded ===");
        api.logging().logToOutput("API URL: " + config.getApiUrl());
        api.logging().logToOutput("Model: " + config.getModel());
        api.logging().logToOutput("Streaming: " + (config.isStreamingEnabled() ? "enabled" : "disabled"));
        api.logging().logToOutput("Passive Scanner: " + (config.isPassiveScanEnabled() ? "enabled" : "disabled"));
        api.logging().logToOutput("Active Scanner: " + (config.isActiveScanEnabled() ? "enabled" : "disabled"));
        api.logging().logToOutput("Max Scan Endpoints: " + config.getMaxScanEndpoints());
        api.logging().logToOutput("Configured: " + config.isConfigured());

        // 从 Proxy 历史预加载主机列表到仪表盘
        try
        {
            java.util.Set<String> proxyHosts = new java.util.LinkedHashSet<>();
            for (var item : api.proxy().history())
            {
                try
                {
                    var svc = item.finalRequest().httpService();
                    String host = svc.host();
                    int port = svc.port();
                    if (host != null && !host.isEmpty())
                    {
                        proxyHosts.add(host + ":" + port);
                    }
                }
                catch (Exception ignored) {}
            }
            if (!proxyHosts.isEmpty())
            {
                SwingUtilities.invokeLater(() -> {
                    mainTabPanel.getDashboardPanel().loadProxyHosts(new java.util.ArrayList<>(proxyHosts));
                    mainTabPanel.getTrafficPanel().loadProxyHosts(new java.util.ArrayList<>(proxyHosts));
                    api.logging().logToOutput("[Dashboard] Loaded " + proxyHosts.size() + " hosts from proxy history");
                });
            }
        }
        catch (Exception e)
        {
            api.logging().logToError("[Dashboard] Failed to load proxy history: " + e.getMessage());
        }
        api.logging().logToOutput("[Modules] Proxy(request analysis + annotations) | Scanner(passive=" + config.isPassiveScanEnabled()
            + ",active=" + config.isActiveScanEnabled()
            + ") | Intruder(AI payloads) | Repeater(auto-send)");

        if (!config.isConfigured())
        {
            api.logging().logToOutput("Hint: Configure API key and URL in the Settings tab.");
        }

        api.logging().logToOutput("Right-click any HTTP message to use AI analysis.");
        api.logging().logToOutput("Passive scanner auto-analyzes all traffic through Burp.");
        api.logging().logToOutput("Select 'AI Payload Generator' in Intruder for AI-generated payloads.");

        // 注册卸载处理器
        api.extension().registerUnloadingHandler(() -> {
            api.logging().logToOutput("=== by ai Unloading ===");
            auditLogger.saveVulnReports();
            realtimeHandler.disable();
            mainTabPanel.cleanup(); // 内部会调用 provider.stopStreaming()
            scannerProvider.stopStreaming();
            realtimeProvider.stopStreaming();
            intruderProvider.stopStreaming();
            trafficProvider.stopStreaming();
            api.logging().logToOutput("=== by ai Unloaded ===");
        });
    }

    /**
     * 初始化 OOB 带外测试域名。
     * 优先使用 Burp Collaborator，否则使用用户配置的自定义 DNSLog 域名。
     */
    private void initializeOobDomain(MontoyaApi api)
    {
        String domain = "";

        if (config.isUseCollaborator())
        {
            try
            {
                // 使用 Burp Suite 原生 Collaborator（Professional only）
                var collaborator = api.collaborator();
                if (collaborator == null)
                {
                    api.logging().logToError("[OOB] Burp Collaborator is not available "
                        + "(Burp Suite Professional required). Falling back to custom DNSLog domain.");
                    domain = config.getDnslogDomain() != null ? config.getDnslogDomain() : "";
                }
                else
                {
                    var client = collaborator.createClient();
                    var payload = client.generatePayload();
                    // payload.toString() 返回完整的带外域名（如 xxxxxxxx.burpcollaborator.net）
                    domain = payload.toString();
                    // 保留 CollaboratorClient 引用，供后续查询交互回调
                    CollaboratorHelper.setCollaboratorClient(client);
                    api.logging().logToOutput("[OOB] Burp Collaborator payload generated: " + domain);
                }
            }
            catch (Exception e)
            {
                api.logging().logToError("[OOB] Collaborator initialization failed: " + e.getMessage()
                    + ". Burp Collaborator requires Burp Suite Professional. "
                    + "Falling back to custom DNSLog domain.");
                domain = config.getDnslogDomain() != null ? config.getDnslogDomain() : "";
            }
        }
        else
        {
            // 使用用户自定义 DNSLog 域名
            domain = config.getDnslogDomain() != null ? config.getDnslogDomain() : "";
        }

        config.setEffectiveOobDomain(domain);

        // 同步设置到 FullVulnDatabase 的静态 OOB 域名
        FullVulnDatabase.setOobDomain(domain);

        if (!domain.isEmpty())
        {
            api.logging().logToOutput("[OOB] Active OOB domain: " + domain);
        }
        else
        {
            api.logging().logToOutput("[OOB] No OOB domain configured (SSRF/XXE out-of-band detection disabled)");
        }
    }
}
