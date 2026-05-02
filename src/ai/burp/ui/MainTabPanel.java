package ai.burp.ui;

import java.awt.*;

import javax.swing.*;
import javax.swing.border.EmptyBorder;

import ai.burp.config.ExtensionConfig;
import ai.burp.provider.StreamingAIProvider;
import ai.burp.scanner.AuditLogger;
import ai.burp.scanner.TechFingerprint;
import ai.burp.scanner.InfoExtractor;

import static ai.burp.ui.ChineseUI.*;

/**
 * 主标签容器 - 包含 AI对话、安全仪表盘、流量分析、AI请求、漏洞报告、设置 六个子标签。
 */
public class MainTabPanel extends JPanel
{
    private final JTabbedPane tabbedPane;
    private final AIChatPanel chatPanel;
    private final DashboardPanel dashboardPanel;
    private final TrafficPanel trafficPanel;
    private final AIRequestPanel aiRequestPanel;
    private final ReportPanel reportPanel;
    private final SettingsPanel settingsPanel;
    private final StreamingAIProvider provider;

    public MainTabPanel(StreamingAIProvider provider, StreamingAIProvider trafficProvider,
        ExtensionConfig config,
        burp.api.montoya.MontoyaApi api, AuditLogger auditLogger,
        TechFingerprint fingerprint, InfoExtractor infoExtractor)
    {
        this.provider = provider;
        setLayout(new BorderLayout());
        setBorder(new EmptyBorder(4, 4, 4, 4));

        tabbedPane = new JTabbedPane(JTabbedPane.TOP);
        tabbedPane.setFont(tabbedPane.getFont().deriveFont(Font.PLAIN, 13f));

        chatPanel = new AIChatPanel(provider, config, api, auditLogger);
        dashboardPanel = new DashboardPanel(api, provider, fingerprint, infoExtractor, auditLogger);
        trafficPanel = new TrafficPanel(trafficProvider, config, api);
        trafficPanel.setAuditLogger(auditLogger);
        aiRequestPanel = new AIRequestPanel(api);
        reportPanel = new ReportPanel();
        reportPanel.setApi(api);
        reportPanel.setOnReportsChanged(() -> auditLogger.replaceVulnReports(reportPanel.getCurrentReports()));
        settingsPanel = new SettingsPanel(config, provider);

        tabbedPane.addTab(TAB_CHAT, chatPanel);
        tabbedPane.addTab(TAB_DASHBOARD, dashboardPanel);
        tabbedPane.addTab(TAB_TRAFFIC, trafficPanel);
        tabbedPane.addTab(TAB_AI_REQUEST, aiRequestPanel);
        tabbedPane.addTab(TAB_REPORT, reportPanel);
        tabbedPane.addTab(TAB_SETTINGS, settingsPanel);

        chatPanel.setOpenSettingsCallback(() -> switchToSettings());

        // AI Chat 发送请求后同步到 AI 请求面板
        chatPanel.setHttpRequestCallback((req, resp, host, method, statusCode, durationMs) ->
            SwingUtilities.invokeLater(() -> aiRequestPanel.addEntry(req, resp, host, method, statusCode, durationMs)));

        // 主动扫描发送请求后也同步到 AI 请求面板
        auditLogger.setHttpRequestCallback((req, resp, host, method, statusCode, durationMs) ->
            SwingUtilities.invokeLater(() -> aiRequestPanel.addEntry(req, resp, host, method, statusCode, durationMs)));

        // 流量分析自动验证请求同步到 AI 请求面板
        trafficPanel.setRequestSentCallback((req, resp, host, method, statusCode, durationMs) ->
            SwingUtilities.invokeLater(() -> aiRequestPanel.addEntry(req, resp, host, method, statusCode, durationMs)));
        trafficPanel.setReportRefreshCallback(() ->
            SwingUtilities.invokeLater(() -> reportPanel.refreshVulnReports(auditLogger.getVulnReports())));

        // "查看详情"按钮回调 → 跳转到 AI 请求标签页
        chatPanel.setTabSwitchCallback(() -> switchToAiRequest());

        // AI 验证确认漏洞后 → 刷新漏洞报告面板
        chatPanel.setVulnReportCallback(() ->
            SwingUtilities.invokeLater(() -> reportPanel.refreshVulnReports(auditLogger.getVulnReports())));

        add(tabbedPane, BorderLayout.CENTER);

        trafficPanel.setChatSessionCallback(new TrafficPanel.ChatSessionCallback()
        {
            @Override
            public String createBatchSession(String title, String context)
            {
                return chatPanel.createBackgroundAnalysisSession(title, context);
            }

            @Override
            public void appendBatchResult(String sessionId, String context)
            {
                chatPanel.appendAnalysisUpdateToSession(sessionId, context);
            }

            @Override
            public void createSessionFromAnalysis(String title, String context,
                java.util.List<ai.burp.model.VulnReport> reports)
            {
                SwingUtilities.invokeLater(() -> {
                    chatPanel.createSessionFromAnalysis(title, context);
                    switchToChat();
                });
            }

            @Override
            public void createAndAnalyzeSession(String title, String context)
            {
                SwingUtilities.invokeLater(() -> {
                    String sid = chatPanel.createBackgroundAnalysisSession(title, context);
                    chatPanel.sendBackgroundPromptForSession(sid,
                        "请分析以上信息，给出详细的风险评估和修复建议。");
                    switchToChat();
                });
            }

            @Override
            public void createAndVerifySession(String title, String context)
            {
                SwingUtilities.invokeLater(() -> {
                    String sid = chatPanel.createBackgroundAnalysisSession(title, context);
                    chatPanel.sendBackgroundPromptForSession(sid,
                        "请基于以上上下文生成并发送验证请求，确认该漏洞是否真实存在。");
                    switchToChat();
                });
            }
        });

        // 流量分析 → 仪表盘集成：分析完成后更新仪表盘数据
        trafficPanel.setDashboardUpdateCallback(results ->
            SwingUtilities.invokeLater(() -> dashboardPanel.updateFromTrafficAnalysis(results))
        );
    }

    /**
     * 获取AI聊天面板（供右键菜单使用）。
     */
    public AIChatPanel getChatPanel()
    {
        return chatPanel;
    }

    /**
     * 获取安全仪表盘面板。
     */
    public DashboardPanel getDashboardPanel()
    {
        return dashboardPanel;
    }

    /**
     * 获取流量分析面板。
     */
    public TrafficPanel getTrafficPanel()
    {
        return trafficPanel;
    }

    /**
     * 获取AI请求面板。
     */
    public AIRequestPanel getAiRequestPanel()
    {
        return aiRequestPanel;
    }

    /**
     * 获取漏洞报告面板。
     */
    public ReportPanel getReportPanel()
    {
        return reportPanel;
    }

    /**
     * 获取设置面板。
     */
    public SettingsPanel getSettingsPanel()
    {
        return settingsPanel;
    }

    /**
     * 切换到AI对话标签页。
     */
    public void switchToChat()
    {
        tabbedPane.setSelectedIndex(0);
    }

    /**
     * 切换到安全仪表盘标签页。
     */
    public void switchToDashboard()
    {
        tabbedPane.setSelectedIndex(1);
    }

    /**
     * 切换到流量分析标签页。
     */
    public void switchToTraffic()
    {
        tabbedPane.setSelectedIndex(2);
    }

    /**
     * 切换到AI请求标签页。
     */
    public void switchToAiRequest()
    {
        tabbedPane.setSelectedIndex(3);
    }

    /**
     * 切换到漏洞报告标签页。
     */
    public void switchToReport()
    {
        tabbedPane.setSelectedIndex(4);
    }

    /**
     * 切换到设置标签页。
     */
    public void switchToSettings()
    {
        tabbedPane.setSelectedIndex(5);
    }

    /**
     * 扩展卸载时清理资源。
     */
    public void cleanup()
    {
        chatPanel.cleanup();
        provider.stopStreaming();
    }
}
