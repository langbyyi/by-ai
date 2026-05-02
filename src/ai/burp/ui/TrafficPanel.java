package ai.burp.ui;

import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.OutputStreamWriter;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import javax.swing.*;
import javax.swing.RowFilter;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableColumnModel;

import ai.burp.config.ExtensionConfig;
import ai.burp.model.VulnReport;
import ai.burp.provider.StreamingAIProvider;
import ai.burp.util.TargetScopeMatcher;
import ai.burp.scanner.TrafficAnalyzer;
import ai.burp.util.TextUtils;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import static ai.burp.ui.ChineseUI.*;

/**
 * 流量分析面板 - 批量分析代理历史，找出安全风险。
 * v2: 高级过滤、统计摘要、严重性着色、导出、聊天会话集成。
 */
public class TrafficPanel extends JPanel
{
    private final StreamingAIProvider provider;
    private final ExtensionConfig config;
    private final MontoyaApi api;
    private ai.burp.scanner.AuditLogger auditLogger;

    private JSpinner maxCountSpinner;
    private JComboBox<String> focusTypeCombo;
    private JComboBox<String> methodFilterCombo;
    private JCheckBox autoVerifyCheckbox;
    private JComboBox<String> targetScopeCombo;
    private final Set<String> hostsInCombo = new LinkedHashSet<>();
    private JButton analyzeButton;
    private JButton stopButton;
    private JTextPane logPane;
    private JTable resultTable;
    private VulnTableModel tableModel;
    private JLabel summaryLabel;
    private JTextArea detailArea;

    // 过滤组件
    private JTextField hostFilterField;
    private JTextField statusCodeFilterField;
    private JTextField keywordFilterField;
    private JPanel filterPanel;
    private boolean filterVisible = false;

    // 操作按钮
    private JButton exportButton;
    private JButton toChatButton;
    private JButton statsButton;
    private JButton filterToggleButton;

    private TrafficAnalyzer analyzer;
    private volatile boolean isAnalyzing = false;
    private volatile boolean stopRequested = false;
    private SwingWorker<Void, Object[]> activeWorker;
    private int analysisRunId = 0;
    private TrafficAnalyzer.RequestSentCallback requestSentCallback;

    // 分析结果缓存（用于导出和发送到聊天）
    private List<VulnReport> lastResults = new ArrayList<>();
    private String latestProgressMessage = " ";
    private final Map<Integer, String> batchSessionIds = new LinkedHashMap<>();

    // 聊天面板回调
    private ChatSessionCallback chatSessionCallback;

    // 仪表盘回调
    private DashboardUpdateCallback dashboardCallback;
    // 报告面板刷新回调
    private Runnable reportRefreshCallback;

    // 实时处理器
    private ai.burp.scanner.RealtimeTrafficHandler realtimeHandler;

    // 实时监控开关
    private JCheckBox realtimeCheckbox;
    private boolean suppressRealtimeToggle = false;
    private boolean suppressComboUpdate = false;

    /**
     * 聊天会话回调 - 用于将分析结果发送到 AI 对话面板。
     */
    public interface ChatSessionCallback
    {
        String createBatchSession(String title, String context);
        void appendBatchResult(String sessionId, String context);
        void createSessionFromAnalysis(String title, String context, List<VulnReport> reports);
        /** 创建会话并自动触发 AI 分析 */
        void createAndAnalyzeSession(String title, String context);
        /** 创建会话并自动触发 AI 验证（生成并发送真实请求） */
        void createAndVerifySession(String title, String context);
    }

    /**
     * 仪表盘更新回调 - 流量分析完成后通知仪表盘。
     */
    public interface DashboardUpdateCallback
    {
        void onTrafficAnalysisComplete(List<VulnReport> results);
    }

    public TrafficPanel(StreamingAIProvider provider, ExtensionConfig config, MontoyaApi api)
    {
        this.provider = provider;
        this.config = config;
        this.api = api;
        this.analyzer = new TrafficAnalyzer(api, provider);
        initUI();
    }

    public void setChatSessionCallback(ChatSessionCallback callback)
    {
        this.chatSessionCallback = callback;
    }

    public void setDashboardUpdateCallback(DashboardUpdateCallback callback)
    {
        this.dashboardCallback = callback;
    }

    public void setReportRefreshCallback(Runnable callback)
    {
        this.reportRefreshCallback = callback;
    }

    public void setAuditLogger(ai.burp.scanner.AuditLogger logger)
    {
        this.auditLogger = logger;
    }

    public void setRequestSentCallback(TrafficAnalyzer.RequestSentCallback callback)
    {
        this.requestSentCallback = callback;
        if (analyzer != null)
        {
            analyzer.setRequestSentCallback(callback);
        }
    }

    public void setRealtimeHandler(ai.burp.scanner.RealtimeTrafficHandler handler)
    {
        this.realtimeHandler = handler;
        // 启用/禁用实时监控复选框
        if (realtimeCheckbox != null)
        {
            updateRealtimeAvailability(false);
        }
        // 设置实时分析回调：发现漏洞时添加到表格
        if (handler != null)
        {
            handler.setCallback(new ai.burp.scanner.RealtimeTrafficHandler.RealtimeCallback()
            {
                @Override
                public void onVulnFound(VulnReport report)
                {
                    SwingUtilities.invokeLater(() -> {
                        tableModel.addVuln(report);
                        if (auditLogger != null)
                        {
                            auditLogger.logVulnReport(report);
                            auditLogger.bridgeToSiteMap(report);
                        }
                        if (reportRefreshCallback != null) reportRefreshCallback.run();
                        String color = getSeverityColor(report.getSeverity());
                        appendLog("<div style='color:" + color + ";margin:2px 0;'>[实时] 发现风险: "
                            + TextUtils.escapeHtml(report.getVulnType()) + " (" + report.getSeverity().label() + ") - "
                            + TextUtils.escapeHtml(TextUtils.truncate(report.getUrl(), 80)) + "</div>");
                    });
                }

                @Override
                public void onAnalysisComplete(String summary)
                {
                    SwingUtilities.invokeLater(() -> {
                        appendLog("<div style='color:#1565c0;margin:2px 0;'>[实时] " + summary + "</div>");
                    });
                }
            });

            // 从配置读取分析参数
            if (config != null)
            {
                handler.setSuspicionThreshold(config.getSuspicionThreshold());
                handler.setDebounceMs(config.getDebounceMs());
            }
        }
    }

    private void initUI()
    {
        setLayout(new BorderLayout(4, 4));
        setBorder(BorderFactory.createEmptyBorder(3, 3, 3, 3));

        // ===== 顶部：配置 + 操作 =====
        JPanel topPanel = new JPanel(new BorderLayout(4, 2));

        // 配置行
        JPanel configPanel = UIStyle.toolbar();

        configPanel.add(new JLabel(TRAFFIC_RECENT));
        maxCountSpinner = new JSpinner(new SpinnerNumberModel(100, 10, 1000, 10));
        configPanel.add(maxCountSpinner);
        configPanel.add(new JLabel(TRAFFIC_ITEMS));

        configPanel.add(Box.createHorizontalStrut(10));

        configPanel.add(new JLabel(TRAFFIC_FOCUS));
        focusTypeCombo = new JComboBox<>(TRAFFIC_TYPE_OPTIONS);
        configPanel.add(focusTypeCombo);

        configPanel.add(Box.createHorizontalStrut(10));

        configPanel.add(new JLabel("目标主机:"));
        targetScopeCombo = new JComboBox<>();
        targetScopeCombo.setEditable(true);
        targetScopeCombo.setFont(targetScopeCombo.getFont().deriveFont(Font.PLAIN, 12f));
        targetScopeCombo.setPreferredSize(new Dimension(220, 28));
        targetScopeCombo.setToolTipText("选择或输入目标主机，如 example.com:8080");
        targetScopeCombo.addActionListener(e -> { if (!suppressComboUpdate) updateRealtimeAvailability(true); });
        Component editorComponent = targetScopeCombo.getEditor().getEditorComponent();
        if (editorComponent instanceof JTextField)
        {
            ((JTextField) editorComponent).getDocument().addDocumentListener(new javax.swing.event.DocumentListener()
            {
                @Override public void insertUpdate(javax.swing.event.DocumentEvent e) { if (!suppressComboUpdate) updateRealtimeAvailability(true); }
                @Override public void removeUpdate(javax.swing.event.DocumentEvent e) { if (!suppressComboUpdate) updateRealtimeAvailability(true); }
                @Override public void changedUpdate(javax.swing.event.DocumentEvent e) { if (!suppressComboUpdate) updateRealtimeAvailability(true); }
            });
        }
        configPanel.add(targetScopeCombo);

        configPanel.add(Box.createHorizontalStrut(10));

        autoVerifyCheckbox = new JCheckBox("自动验证");
        autoVerifyCheckbox.setToolTipText("允许 AI 基于分析结果构造低风险验证请求并自动发送，最多验证少量目标");
        autoVerifyCheckbox.setSelected(true);
        configPanel.add(autoVerifyCheckbox);

        configPanel.add(Box.createHorizontalStrut(10));

        analyzeButton = new JButton(BTN_START_ANALYZE);
        UIStyle.primaryButton(analyzeButton);
        analyzeButton.addActionListener(e -> startAnalysis());
        configPanel.add(analyzeButton);

        stopButton = new JButton(BTN_STOP_ANALYZE);
        UIStyle.compactButton(stopButton);
        stopButton.setEnabled(false);
        stopButton.addActionListener(e -> stopAnalysis());
        configPanel.add(stopButton);

        exportButton = new JButton(TRAFFIC_EXPORT);
        UIStyle.compactButton(exportButton);
        exportButton.setToolTipText("导出分析报告");
        exportButton.addActionListener(e -> showExportMenu());
        configPanel.add(exportButton);

        topPanel.add(configPanel, BorderLayout.NORTH);

        // 操作行
        JPanel actionPanel = UIStyle.toolbar();

        filterToggleButton = new JButton(TRAFFIC_FILTER_SHOW);
        UIStyle.compactButton(filterToggleButton);
        filterToggleButton.setToolTipText("展开/收起筛选条件");
        filterToggleButton.addActionListener(e -> toggleFilter());
        actionPanel.add(filterToggleButton);

        actionPanel.add(Box.createHorizontalStrut(6));

        actionPanel.add(new JLabel(TRAFFIC_FILTER_METHOD));
        methodFilterCombo = new JComboBox<>(TRAFFIC_METHOD_OPTIONS);
        methodFilterCombo.setFont(methodFilterCombo.getFont().deriveFont(Font.PLAIN, 12f));
        methodFilterCombo.setToolTipText("同时影响表格显示和分析范围");
        methodFilterCombo.addActionListener(e -> applyTableFilter());
        actionPanel.add(methodFilterCombo);

        actionPanel.add(Box.createHorizontalStrut(10));

        toChatButton = new JButton(TRAFFIC_TO_CHAT);
        UIStyle.compactButton(toChatButton);
        toChatButton.setToolTipText(TRAFFIC_TO_CHAT_TIP);
        toChatButton.addActionListener(e -> sendToChat());
        actionPanel.add(toChatButton);

        statsButton = new JButton(TRAFFIC_STATS);
        UIStyle.compactButton(statsButton);
        statsButton.setToolTipText("查看分析统计摘要");
        statsButton.addActionListener(e -> showStats());
        actionPanel.add(statsButton);

        actionPanel.add(Box.createHorizontalStrut(10));

        realtimeCheckbox = new JCheckBox(TRAFFIC_REALTIME);
        realtimeCheckbox.setToolTipText(TRAFFIC_REALTIME_TIP);
        realtimeCheckbox.setSelected(false);
        realtimeCheckbox.setEnabled(false); // 直到 realtimeHandler 被设置
        realtimeCheckbox.addActionListener(e -> {
            if (suppressRealtimeToggle) return;
            if (realtimeHandler == null) return;
            if (realtimeCheckbox.isSelected())
            {
                if (!applyRealtimeScope())
                {
                    realtimeCheckbox.setSelected(false);
                    return;
                }
                realtimeHandler.enable();
                appendLog("<div style='color:#1565c0;'>实时流量监控已启用。</div>");
            }
            else
            {
                realtimeHandler.disable();
                appendLog("<div style='color:#e65100;'>实时流量监控已停用。</div>");
            }
        });
        actionPanel.add(realtimeCheckbox);

        topPanel.add(actionPanel, BorderLayout.SOUTH);

        // 过滤面板（默认隐藏）
        filterPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        filterPanel.setBorder(BorderFactory.createTitledBorder("高级筛选"));
        filterPanel.setVisible(false);

        filterPanel.add(new JLabel(TRAFFIC_FILTER_HOST));
        hostFilterField = new JTextField(15);
        hostFilterField.setToolTipText("输入域名关键字，如: example.com");
        hostFilterField.addActionListener(e -> applyTableFilter());
        filterPanel.add(hostFilterField);

        filterPanel.add(new JLabel(TRAFFIC_FILTER_STATUS));
        statusCodeFilterField = new JTextField(8);
        statusCodeFilterField.setToolTipText("状态码筛选，如: 200, 4xx, 5xx");
        statusCodeFilterField.addActionListener(e -> applyTableFilter());
        filterPanel.add(statusCodeFilterField);

        filterPanel.add(new JLabel(TRAFFIC_FILTER_KEYWORD));
        keywordFilterField = new JTextField(12);
        keywordFilterField.setToolTipText("在请求/响应中搜索关键字");
        keywordFilterField.addActionListener(e -> applyTableFilter());
        filterPanel.add(keywordFilterField);

        JButton applyFilterBtn = new JButton("应用");
        UIStyle.compactButton(applyFilterBtn);
        applyFilterBtn.addActionListener(e -> applyTableFilter());
        filterPanel.add(applyFilterBtn);

        JButton clearFilterBtn = new JButton("清空");
        UIStyle.compactButton(clearFilterBtn);
        clearFilterBtn.addActionListener(e -> {
            hostFilterField.setText("");
            statusCodeFilterField.setText("");
            keywordFilterField.setText("");
            methodFilterCombo.setSelectedIndex(0);
            applyTableFilter();
        });
        filterPanel.add(clearFilterBtn);

        // 将topPanel和filterPanel包装
        JPanel northWrapper = new JPanel(new BorderLayout());
        northWrapper.add(topPanel, BorderLayout.NORTH);
        northWrapper.add(filterPanel, BorderLayout.SOUTH);

        add(northWrapper, BorderLayout.NORTH);

        // ===== 中间：日志区 + 结果表格 分割 =====
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setResizeWeight(0.4);
        splitPane.setDividerSize(6);
        splitPane.setOneTouchExpandable(true);
        splitPane.setContinuousLayout(true);

        // 日志区
        logPane = new JTextPane();
        logPane.setEditable(false);
        logPane.setContentType("text/html");
        logPane.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, Boolean.TRUE);
        logPane.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
        JScrollPane logScroll = UIStyle.scroll(logPane);
        logScroll.setPreferredSize(new Dimension(600, 200));
        splitPane.setLeftComponent(logScroll);

        // 结果表格
        JPanel resultPanel = new JPanel(new BorderLayout());
        summaryLabel = UIStyle.mutedLabel(" ");
        summaryLabel.setBorder(BorderFactory.createEmptyBorder(0, 2, 3, 2));
        resultPanel.add(summaryLabel, BorderLayout.NORTH);

        tableModel = new VulnTableModel();
        resultTable = new JTable(tableModel);
        UIStyle.table(resultTable);
        resultTable.setRowHeight(26);

        // 启用 RowSorter 以支持过滤
        resultTable.setAutoCreateRowSorter(true);

        // 列宽设置
        TableColumnModel colModel = resultTable.getColumnModel();
        colModel.getColumn(0).setPreferredWidth(200); // URL
        colModel.getColumn(1).setPreferredWidth(50);  // 方法
        colModel.getColumn(2).setPreferredWidth(80);  // 风险类型
        colModel.getColumn(3).setPreferredWidth(50);  // 严重性
        colModel.getColumn(4).setPreferredWidth(60);  // 参数
        colModel.getColumn(5).setPreferredWidth(120); // AI 建议
        colModel.getColumn(6).setPreferredWidth(120); // 状态
        colModel.getColumn(7).setPreferredWidth(70);  // 操作

        // 严重性颜色渲染
        colModel.getColumn(3).setCellRenderer(new SeverityCellRenderer());

        // 操作列渲染器 - 让 "Repeater" 看起来像可点击链接
        colModel.getColumn(7).setCellRenderer(new ActionCellRenderer());

        // 表格鼠标监听 - 处理操作列点击
        resultTable.addMouseListener(new MouseAdapter()
        {
            @Override
            public void mouseClicked(MouseEvent e)
            {
                int col = resultTable.columnAtPoint(e.getPoint());
                if (col == 7) // 操作列
                {
                    int row = resultTable.rowAtPoint(e.getPoint());
                    if (row >= 0)
                    {
                        int modelRow = resultTable.convertRowIndexToModel(row);
                        VulnReport report = tableModel.getRow(modelRow);
                        if (report != null)
                        {
                            sendToRepeater(report);
                        }
                    }
                }
            }
        });
        resultTable.addMouseMotionListener(new MouseAdapter()
        {
            @Override
            public void mouseMoved(MouseEvent e)
            {
                int col = resultTable.columnAtPoint(e.getPoint());
                resultTable.setCursor(
                    col == 7 ? Cursor.getPredefinedCursor(Cursor.HAND_CURSOR)
                             : Cursor.getDefaultCursor());
            }
        });

        resultTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) showSelectedDetail();
        });

        JPopupMenu resultPopup = new JPopupMenu();
        JMenuItem copyDetailItem = new JMenuItem("复制详情");
        copyDetailItem.addActionListener(e -> copySelectedDetail());
        resultPopup.add(copyDetailItem);

        JMenuItem sendToChatItem = new JMenuItem("发送到对话");
        sendToChatItem.addActionListener(e -> sendSelectedToChat());
        resultPopup.add(sendToChatItem);

        JMenuItem verifyItem = new JMenuItem("验证此漏洞");
        verifyItem.addActionListener(e -> verifySelected());
        resultPopup.add(verifyItem);

        JMenuItem repeaterItem = new JMenuItem("发送到 Repeater");
        repeaterItem.addActionListener(e -> {
            VulnReport report = getSelectedReport();
            if (report != null) sendToRepeater(report);
        });
        resultPopup.add(repeaterItem);

        resultTable.setComponentPopupMenu(resultPopup);
        JScrollPane tableScroll = UIStyle.scroll(resultTable);

        detailArea = new JTextArea(5, 80);
        UIStyle.textArea(detailArea);
        JScrollPane detailScroll = UIStyle.scroll(detailArea);
        detailScroll.setPreferredSize(new Dimension(600, 150));

        // 表格与详情区之间也支持拖动调整高度
        JSplitPane resultSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, detailScroll);
        resultSplit.setResizeWeight(0.75);
        resultSplit.setDividerSize(6);
        resultSplit.setOneTouchExpandable(true);
        resultSplit.setContinuousLayout(true);

        resultPanel.add(resultSplit, BorderLayout.CENTER);

        splitPane.setRightComponent(resultPanel);

        add(splitPane, BorderLayout.CENTER);
    }

    // ==================== 表格过滤 ====================

    private void applyTableFilter()
    {
        if (resultTable.getRowSorter() == null) return;

        String methodFilter = (String) methodFilterCombo.getSelectedItem();
        String hostFilter = hostFilterField.getText().trim();
        String statusFilter = statusCodeFilterField.getText().trim();
        String keywordFilter = keywordFilterField.getText().trim();

        // 构建组合过滤器列表
        List<RowFilter<Object, Object>> filters = new ArrayList<>();

        // 方法过滤 - column 1
        if (methodFilter != null && !methodFilter.equals("全部"))
        {
            final String mf = methodFilter;
            filters.add(RowFilter.regexFilter("^" + java.util.regex.Pattern.quote(mf) + "$", 1));
        }

        // 域名过滤 - column 0 (URL)
        if (!hostFilter.isEmpty())
        {
            filters.add(RowFilter.regexFilter("(?i)" + java.util.regex.Pattern.quote(hostFilter), 0));
        }

        // 状态码过滤 - column 6 (验证状态)
        if (!statusFilter.isEmpty())
        {
            final String sf = statusFilter;
            filters.add(new RowFilter<Object, Object>()
            {
                @Override
                public boolean include(Entry<? extends Object, ? extends Object> entry)
                {
                    Object identifier = entry.getIdentifier();
                    if (!(identifier instanceof Integer))
                    {
                        return false;
                    }
                    VulnReport report = tableModel.getRow((Integer) identifier);
                    if (report == null) return false;
                    String code = safe(report.getResponseCode());
                    return matchesStatusFilter(code, sf);
                }
            });
        }

        // 关键词过滤 - 全列搜索
        if (!keywordFilter.isEmpty())
        {
            filters.add(RowFilter.regexFilter("(?i)" + java.util.regex.Pattern.quote(keywordFilter)));
        }

        if (filters.isEmpty())
        {
            ((javax.swing.table.TableRowSorter<?>) resultTable.getRowSorter()).setRowFilter(null);
        }
        else
        {
            ((javax.swing.table.TableRowSorter<?>) resultTable.getRowSorter()).setRowFilter(RowFilter.andFilter(filters));
        }
    }

    private boolean matchesStatusFilter(String actualCode, String filter)
    {
        if (actualCode == null || actualCode.isEmpty()) return false;
        String[] parts = filter.split(",");
        for (String part : parts)
        {
            String p = part.trim().toLowerCase();
            if (p.length() == 3 && p.endsWith("xx"))
            {
                if (actualCode.startsWith(p.substring(0, 1))) return true;
            }
            else if (actualCode.equalsIgnoreCase(p))
            {
                return true;
            }
        }
        return false;
    }

    // ==================== Repeater 集成 ====================

    private void sendToRepeater(VulnReport report)
    {
        try
        {
            String url = report.getUrl();
            String method = report.getMethod();
            if (url == null || url.isEmpty())
            {
                appendLog("<div style='color:#f57c00;'>无法发送到 Repeater: 缺少 URL 信息。</div>");
                return;
            }

            // 构建请求
            String originalReq = report.getOriginalRequest();
            String requestStr;
            if (originalReq != null && !originalReq.isEmpty())
            {
                requestStr = originalReq;
            }
            else
            {
                String path = "/";
                try
                {
                    java.net.URI uri = new java.net.URI(url);
                    path = uri.getRawPath();
                    if (path == null || path.isEmpty()) path = "/";
                    if (uri.getRawQuery() != null && !uri.getRawQuery().isEmpty())
                    {
                        path += "?" + uri.getRawQuery();
                    }
                }
                catch (Exception ignored) {}
                requestStr = (method != null ? method : "GET") + " " + path
                    + " HTTP/1.1\r\nHost: " + safe(report.getHost()) + "\r\n\r\n";
            }

            // 解析URL绑定HttpService
            boolean secure = report.isSecure();
            String host = report.getHost() != null ? report.getHost() : "";
            int port = secure ? 443 : 80;
            // 从URL提取端口
            try
            {
                java.net.URI uri = new java.net.URI(url);
                if (uri.getPort() > 0) port = uri.getPort();
                if (host.isEmpty()) host = uri.getHost();
            }
            catch (Exception ignored) {}
            // 端口推断 HTTPS：如果 port 已经被设为 443，升级为 HTTPS
            if (!secure && port == 443) secure = true;

            burp.api.montoya.http.HttpService service =
                burp.api.montoya.http.HttpService.httpService(host, port, secure);
            HttpRequest httpRequest = HttpRequest.httpRequest(service, requestStr);
            api.repeater().sendToRepeater(httpRequest,
                report.getVulnType() != null ? report.getVulnType() : "TrafficAnalysis");

            appendLog("<div style='color:#2e7d32;'>已发送到 Repeater: "
                + TextUtils.escapeHtml(safe(report.getVulnType())) + " - "
                + TextUtils.escapeHtml(TextUtils.truncate(url, 60)) + "</div>");
        }
        catch (Exception ex)
        {
            appendLog("<div style='color:red;'>发送到 Repeater 失败: "
                + TextUtils.escapeHtml(ex.getMessage()) + "</div>");
        }
    }

    // ==================== 过滤面板切换 ====================

    private void toggleFilter()
    {
        filterVisible = !filterVisible;
        filterPanel.setVisible(filterVisible);
        filterToggleButton.setText(filterVisible ? "隐藏筛选" : TRAFFIC_FILTER_SHOW);
        revalidate();
    }

    private void startAnalysis()
    {
        if (isAnalyzing) return;
        if (!provider.isConfigured())
        {
            appendLog("<span style='color:red;'>API 未配置。请先在「设置」中配置。</span>");
            return;
        }

        isAnalyzing = true;
        analyzeButton.setEnabled(false);
        stopButton.setEnabled(true);
        tableModel.clear();
        logPane.setText("");
        lastResults.clear();
        batchSessionIds.clear();
        stopRequested = false;
        latestProgressMessage = "正在准备分析...";
        summaryLabel.setText(latestProgressMessage);

        final int maxCount = (Integer) maxCountSpinner.getValue();
        final String focusType = (String) focusTypeCombo.getSelectedItem();
        final TargetScopeMatcher targetScopeMatcher;
        try
        {
            targetScopeMatcher = buildTargetScopeMatcher();
        }
        catch (IllegalArgumentException e)
        {
            isAnalyzing = false;
            analyzeButton.setEnabled(true);
            stopButton.setEnabled(false);
            appendLog("<div style='color:red;'>" + TextUtils.escapeHtml(e.getMessage()) + "</div>");
            summaryLabel.setText("目标范围无效");
            return;
        }
        final int runId = ++analysisRunId;
        analyzer = new TrafficAnalyzer(api, provider);
        analyzer.setAutoVerifyEnabled(autoVerifyCheckbox.isSelected());
        analyzer.setTargetScope(targetScopeMatcher);
        if (requestSentCallback != null)
        {
            analyzer.setRequestSentCallback(requestSentCallback);
        }

        // 设置过滤条件
        analyzer.setHostFilter(hostFilterField.getText());
        analyzer.setMethodFilter((String) methodFilterCombo.getSelectedItem());
        analyzer.setStatusCodeFilter(statusCodeFilterField.getText());
        analyzer.setKeywordFilter(keywordFilterField.getText());

        if (autoVerifyCheckbox.isSelected())
        {
            appendLog("<div style='color:#1565c0;margin:2px 0;'>已启用自动验证：AI 将构造低风险验证请求并自动发送。</div>");
        }
        appendLog("<div style='color:#1565c0;margin:4px 0;padding:4px;background:#eef6ff;'>"
            + "已开始流量分析：最大 " + maxCount + " 条，聚焦类型 "
            + TextUtils.escapeHtml(String.valueOf(focusType)) + "。</div>");

        SwingWorker<Void, Object[]> worker = new SwingWorker<>()
        {
            @Override
            protected Void doInBackground() throws Exception
            {
                final AtomicInteger streamedChars = new AtomicInteger(0);
                final AtomicLong lastStreamStatusAt = new AtomicLong(0L);
                analyzer.analyzeHistory(maxCount, focusType, new TrafficAnalyzer.AnalysisCallback()
                {
                    @Override
                    public void onStarted(int totalTargets)
                    {
                        publish(new Object[]{"log", "开始分析代理历史，共 " + totalTargets + " 条记录..."});
                        publish(new Object[]{"status", "开始分析代理历史，共 " + totalTargets + " 条记录..."});
                    }

                    @Override
                    public void onProgress(String message)
                    {
                        publish(new Object[]{"log", message});
                        publish(new Object[]{"status", message});
                    }

                    @Override
                    public void onBatchSubmitted(int batchNumber, int totalBatches, int from, int to,
                        List<ProxyHttpRequestResponse> batchTargets)
                    {
                        publish(new Object[]{"batchSubmitted", batchNumber, totalBatches, from, to,
                            new ArrayList<>(batchTargets)});
                    }

                    @Override
                    public void onStreamToken(String token)
                    {
                        int totalChars = streamedChars.addAndGet(token != null ? token.length() : 0);
                        long now = System.currentTimeMillis();
                        long last = lastStreamStatusAt.get();
                        if (totalChars > 0 && (totalChars % 400 == 0 || now - last >= 1200))
                        {
                            if (lastStreamStatusAt.compareAndSet(last, now))
                            {
                                publish(new Object[]{"status", "AI 正在返回分析结果，已接收约 " + totalChars + " 个字符..."});
                            }
                        }
                    }

                    @Override
                    public void onVulnFound(VulnReport report)
                    {
                        publish(new Object[]{"vuln", report});
                    }

                    @Override
                    public void onBatchComplete(int batchNumber, int totalBatches,
                        List<VulnReport> batchResults, List<ProxyHttpRequestResponse> batchTargets)
                    {
                        publish(new Object[]{"batchComplete", batchNumber, totalBatches,
                            new ArrayList<>(batchResults), new ArrayList<>(batchTargets)});
                    }

                    @Override
                    public void onBatchFailed(int batchNumber, int totalBatches,
                        List<ProxyHttpRequestResponse> batchTargets, String errorMessage)
                    {
                        publish(new Object[]{"batchFailed", batchNumber, totalBatches,
                            new ArrayList<>(batchTargets), errorMessage});
                    }

                    @Override
                    public void onComplete(List<VulnReport> results)
                    {
                        publish(new Object[]{"done", results});
                    }

                    @Override
                    public void onNoData()
                    {
                        publish(new Object[]{"log", MSG_NO_HISTORY});
                        publish(new Object[]{"done", new ArrayList<VulnReport>()});
                    }

                    @Override
                    public void onError(String message)
                    {
                        publish(new Object[]{"log", "<span style='color:red;'>" + message + "</span>"});
                        publish(new Object[]{"done", new ArrayList<VulnReport>()});
                    }
                });
                return null;
            }

            @Override
            protected void process(List<Object[]> chunks)
            {
                if (activeWorker != this || runId != analysisRunId)
                {
                    return;
                }
                for (Object[] chunk : chunks)
                {
                    String type = (String) chunk[0];
                    if ("log".equals(type))
                    {
                        String msg = (String) chunk[1];
                        String text = String.valueOf(msg);
                        if (looksLikeHtml(text))
                        {
                            appendLog(text);
                        }
                        else
                        {
                            appendLog("<div style='color:#333;margin:2px 0;'>"
                                + TextUtils.escapeHtmlWithBr(text) + "</div>");
                        }
                    }
                    else if ("status".equals(type))
                    {
                        latestProgressMessage = String.valueOf(chunk[1]);
                        summaryLabel.setText(latestProgressMessage);
                    }
                    else if ("batchSubmitted".equals(type))
                    {
                        int batchNumber = (Integer) chunk[1];
                        int totalBatches = (Integer) chunk[2];
                        int from = (Integer) chunk[3];
                        int to = (Integer) chunk[4];
                        @SuppressWarnings("unchecked")
                        List<ProxyHttpRequestResponse> batchTargets = (List<ProxyHttpRequestResponse>) chunk[5];
                        handleBatchSubmitted(batchNumber, totalBatches, from, to, batchTargets);
                    }
                    else if ("vuln".equals(type))
                    {
                        VulnReport r = (VulnReport) chunk[1];
                        tableModel.addVuln(r);
                        if (auditLogger != null)
                        {
                            auditLogger.logVulnReport(r);
                            auditLogger.bridgeToSiteMap(r);
                        }
                        if (reportRefreshCallback != null) reportRefreshCallback.run();
                        String color = getSeverityColor(r.getSeverity());
                        appendLog("<div style='color:" + color + ";margin:2px 0;'>发现风险: "
                            + TextUtils.escapeHtml(r.getVulnType()) + " (" + r.getSeverity().label() + ") - "
                            + TextUtils.escapeHtml(TextUtils.truncate(r.getUrl(), 80))
                            + " [" + TextUtils.escapeHtml(safe(r.getParameter())) + "]</div>");
                    }
                    else if ("batchComplete".equals(type))
                    {
                        int batchNumber = (Integer) chunk[1];
                        int totalBatches = (Integer) chunk[2];
                        @SuppressWarnings("unchecked")
                        List<VulnReport> batchResults = (List<VulnReport>) chunk[3];
                        @SuppressWarnings("unchecked")
                        List<ProxyHttpRequestResponse> batchTargets = (List<ProxyHttpRequestResponse>) chunk[4];
                        handleBatchComplete(batchNumber, totalBatches, batchResults, batchTargets);
                    }
                    else if ("batchFailed".equals(type))
                    {
                        int batchNumber = (Integer) chunk[1];
                        int totalBatches = (Integer) chunk[2];
                        @SuppressWarnings("unchecked")
                        List<ProxyHttpRequestResponse> batchTargets = (List<ProxyHttpRequestResponse>) chunk[3];
                        String errorMessage = String.valueOf(chunk[4]);
                        handleBatchFailed(batchNumber, totalBatches, batchTargets, errorMessage);
                    }
                    else if ("done".equals(type))
                    {
                        @SuppressWarnings("unchecked")
                        List<VulnReport> results = (List<VulnReport>) chunk[1];
                        finishAnalysis(results);
                    }
                }
            }
        };
        activeWorker = worker;
        worker.execute();
    }

    private void stopAnalysis()
    {
        stopRequested = true;
        analyzer.cancel();
        if (activeWorker != null)
        {
            activeWorker.cancel(true);
        }
        markPendingBatchSessionsStopped();
        activeWorker = null;
        isAnalyzing = false;
        analyzeButton.setEnabled(true);
        stopButton.setEnabled(false);
        appendLog("<div style='color:#e65100;margin:4px 0;'>分析已停止。</div>");
        summaryLabel.setText("分析已停止");
    }

    private void finishAnalysis(List<VulnReport> results)
    {
        activeWorker = null;
        isAnalyzing = false;
        analyzeButton.setEnabled(true);
        stopButton.setEnabled(false);
        lastResults = new ArrayList<>(results);

        if (results.isEmpty())
        {
            summaryLabel.setText(MSG_ANALYSIS_EMPTY);
        }
        else
        {
            int confirmed = 0, pending = 0;
            for (VulnReport r : results)
            {
                if (r.getVerifyStatus() == VulnReport.VerifyStatus.CONFIRMED) confirmed++;
                else pending++;
            }
            summaryLabel.setText(String.format(TRAFFIC_FOUND_COUNT, results.size(), confirmed, pending));
        }

        if (stopRequested)
        {
            appendLog("<div style='color:#e65100;margin:6px 0;padding:4px;background:#fff8e1;'>"
                + "流量分析已停止，已保留已完成批次的独立会话和当前结果。</div>");
        }
        else
        {
            appendLog("<div style='color:#2e7d32;margin:6px 0;padding:4px;background:#f1f8e9;'>"
                + "流量分析完成。每个批次都已创建独立 AI 会话，可分别继续追问和验证。</div>");
        }

        // 通知仪表盘更新
        if (dashboardCallback != null && !results.isEmpty())
        {
            dashboardCallback.onTrafficAnalysisComplete(results);
        }
    }

    private void handleBatchSubmitted(int batchNumber, int totalBatches, int from, int to,
        List<ProxyHttpRequestResponse> batchTargets)
    {
        if (chatSessionCallback == null) return;
        String title = "流量分析 第 " + batchNumber + "/" + totalBatches + " 批";
        String context = buildBatchPendingContext(batchNumber, totalBatches, from, to, batchTargets);
        String sessionId = chatSessionCallback.createBatchSession(title, context);
        if (sessionId != null && !sessionId.isEmpty())
        {
            batchSessionIds.put(batchNumber, sessionId);
            appendLog("<div style='color:#1565c0;margin:2px 0;'>已为第 " + batchNumber + "/" + totalBatches
                + " 批创建独立会话。</div>");
        }
    }

    private void handleBatchComplete(int batchNumber, int totalBatches,
        List<VulnReport> batchResults, List<ProxyHttpRequestResponse> batchTargets)
    {
        String sessionId = batchSessionIds.get(batchNumber);
        if (sessionId == null || sessionId.isEmpty() || chatSessionCallback == null)
        {
            return;
        }
        String context = buildBatchResultContext(batchNumber, totalBatches, batchResults, batchTargets);
        chatSessionCallback.appendBatchResult(sessionId, context);
        batchSessionIds.remove(batchNumber);
    }

    private void handleBatchFailed(int batchNumber, int totalBatches,
        List<ProxyHttpRequestResponse> batchTargets, String errorMessage)
    {
        String sessionId = batchSessionIds.get(batchNumber);
        if (sessionId == null || sessionId.isEmpty() || chatSessionCallback == null)
        {
            return;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("# 第 ").append(batchNumber).append("/").append(totalBatches).append(" 批分析失败\n\n");
        sb.append("- 请求数量: ").append(batchTargets.size()).append("\n");
        sb.append("- 错误信息: ").append(errorMessage == null ? "未知错误" : errorMessage).append("\n");
        sb.append("- 状态: 本批次未获得 AI 分析结果。\n");
        chatSessionCallback.appendBatchResult(sessionId, sb.toString());
        batchSessionIds.remove(batchNumber);
    }

    private String buildBatchPendingContext(int batchNumber, int totalBatches, int from, int to,
        List<ProxyHttpRequestResponse> batchTargets)
    {
        StringBuilder sb = new StringBuilder();
        sb.append("# 批次信息\n\n");
        sb.append("- 批次: ").append(batchNumber).append("/").append(totalBatches).append("\n");
        sb.append("- 范围: 第 ").append(from).append(" 到 ").append(to).append(" 条代理记录\n");
        sb.append("- 聚焦类型: ").append(String.valueOf(focusTypeCombo.getSelectedItem())).append("\n");
        sb.append("- 目标范围: ").append(describeCurrentTargetScope()).append("\n");
        sb.append("- 状态: 已提交给 AI 分析，等待结果返回\n\n");
        sb.append("## 本批请求概览\n\n");
        for (int i = 0; i < batchTargets.size(); i++)
        {
            ProxyHttpRequestResponse item = batchTargets.get(i);
            sb.append(i + 1).append(". ")
                .append(item.finalRequest().method()).append(" ")
                .append(TextUtils.truncate(item.finalRequest().url(), 120));
            if (item.hasResponse())
            {
                sb.append(" [").append(item.response().statusCode()).append("]");
            }
            sb.append("\n");
        }
        return sb.toString();
    }

    private String buildBatchResultContext(int batchNumber, int totalBatches,
        List<VulnReport> batchResults, List<ProxyHttpRequestResponse> batchTargets)
    {
        StringBuilder sb = new StringBuilder();
        sb.append("# 第 ").append(batchNumber).append("/").append(totalBatches).append(" 批分析结果\n\n");
        sb.append("- 请求数量: ").append(batchTargets.size()).append("\n");
        sb.append("- 风险点数量: ").append(batchResults.size()).append("\n\n");
        if (batchResults.isEmpty())
        {
            sb.append("本批次未发现达到阈值的风险点。\n");
            return sb.toString();
        }
        for (int i = 0; i < batchResults.size(); i++)
        {
            sb.append("## 发现 ").append(i + 1).append("\n\n");
            sb.append(batchResults.get(i).toChatContext()).append("\n\n");
        }
        return sb.toString();
    }

    private String describeCurrentTargetScope()
    {
        String pattern = getTargetScopePattern();
        return pattern.isEmpty() ? "未设置" : pattern;
    }

    /** 从下拉框获取用户输入的目标模式 */
    private String getTargetScopePattern()
    {
        Object item = targetScopeCombo.getSelectedItem();
        return item == null ? "" : item.toString().trim();
    }

    private TargetScopeMatcher buildTargetScopeMatcher()
    {
        String pattern = getTargetScopePattern();
        if (pattern.isEmpty())
        {
            return TargetScopeMatcher.disabled();
        }
        return TargetScopeMatcher.create(TargetScopeMatcher.Mode.EXACT, pattern);
    }

    private boolean applyRealtimeScope()
    {
        if (realtimeHandler == null) return false;
        if (getTargetScopePattern().isEmpty())
        {
            appendLog("<div style='color:red;'>请先设置实时监控目标主机，再启用实时监控。</div>");
            return false;
        }
        try
        {
            realtimeHandler.setTargetScope(buildTargetScopeMatcher());
            return true;
        }
        catch (IllegalArgumentException e)
        {
            appendLog("<div style='color:red;'>" + TextUtils.escapeHtml(e.getMessage()) + "</div>");
            return false;
        }
    }

    private void updateRealtimeAvailability(boolean reapplyWhenEnabled)
    {
        if (realtimeCheckbox == null) return;

        boolean hasTarget = !getTargetScopePattern().isEmpty();
        boolean canEnable = realtimeHandler != null && hasTarget;

        realtimeCheckbox.setEnabled(canEnable);
        realtimeCheckbox.setToolTipText(canEnable
            ? "已启用按目标主机过滤的实时 Proxy 流量分析"
            : "请先选择或输入目标主机，再启用实时监控");

        if (!canEnable && realtimeHandler != null && realtimeHandler.isEnabled())
        {
            suppressRealtimeToggle = true;
            try
            {
                realtimeCheckbox.setSelected(false);
            }
            finally
            {
                suppressRealtimeToggle = false;
            }
            realtimeHandler.disable();
            appendLog("<div style='color:#e65100;'>实时流量监控已停用：未设置目标主机。</div>");
            return;
        }

        if (canEnable && reapplyWhenEnabled && realtimeHandler != null && realtimeHandler.isEnabled())
        {
            if (applyRealtimeScope())
            {
                appendLog("<div style='color:#1565c0;'>实时流量监控目标已更新为: "
                    + TextUtils.escapeHtml(getTargetScopePattern()) + "</div>");
            }
        }
    }

    private void markPendingBatchSessionsStopped()
    {
        if (chatSessionCallback == null || batchSessionIds.isEmpty()) return;
        for (Map.Entry<Integer, String> entry : new ArrayList<>(batchSessionIds.entrySet()))
        {
            String sessionId = entry.getValue();
            if (sessionId == null || sessionId.isEmpty()) continue;
            chatSessionCallback.appendBatchResult(sessionId,
                "# 第 " + entry.getKey() + " 批分析已停止\n\n- 状态: 用户手动停止，当前批次未完成。\n");
        }
        batchSessionIds.clear();
    }

    // ==================== 操作功能 ====================

    private void exportReportAsHtml()
    {
        if (lastResults.isEmpty())
        {
            appendLog("<div style='color:#f57c00;'>没有可导出的分析结果。</div>");
            return;
        }

        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("导出分析报告");
        fileChooser.setSelectedFile(new File("traffic-report.html"));
        fileChooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("HTML 文件", "html"));

        int userChoice = fileChooser.showSaveDialog(this);
        if (userChoice != JFileChooser.APPROVE_OPTION) return;

        File file = fileChooser.getSelectedFile();
        if (!file.getName().toLowerCase().endsWith(".html"))
        {
            file = new File(file.getAbsolutePath() + ".html");
        }

        if (file.exists())
        {
            int confirm = JOptionPane.showConfirmDialog(this,
                "文件已存在，是否覆盖？\n" + file.getName(),
                "确认覆盖", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            if (confirm != JOptionPane.YES_OPTION) return;
        }

        try
        {
            String html = generateHtmlReport();
            try (OutputStreamWriter writer = new OutputStreamWriter(
                new FileOutputStream(file), StandardCharsets.UTF_8))
            {
                writer.write(html);
            }
            appendLog("<div style='color:#2e7d32;'>报告已导出到: "
                + TextUtils.escapeHtml(file.getAbsolutePath()) + "</div>");
        }
        catch (IOException ex)
        {
            appendLog("<div style='color:red;'>导出失败: " + TextUtils.escapeHtml(ex.getMessage()) + "</div>");
        }
    }

    private String generateHtmlReport()
    {
        StringBuilder sb = new StringBuilder();
        sb.append("<!DOCTYPE html>\n<html lang='zh-CN'>\n<head>\n");
        sb.append("<meta charset='UTF-8'>\n");
        sb.append("<title>流量安全分析报告</title>\n");
        sb.append("<style>\n");
        sb.append("body { font-family: 'Microsoft YaHei', Arial, sans-serif; margin: 20px; background: #fafafa; }\n");
        sb.append("h1 { color: #1565c0; border-bottom: 2px solid #1565c0; padding-bottom: 8px; }\n");
        sb.append("h2 { color: #333; margin-top: 24px; }\n");
        sb.append("table { border-collapse: collapse; width: 100%; margin: 12px 0; }\n");
        sb.append("th { background: #e3f2fd; padding: 8px 12px; text-align: left; border: 1px solid #ddd; }\n");
        sb.append("td { padding: 8px 12px; border: 1px solid #ddd; }\n");
        sb.append("tr:nth-child(even) { background: #f5f5f5; }\n");
        sb.append(".critical { color: #b71c1c; font-weight: bold; }\n");
        sb.append(".high { color: #d32f2f; font-weight: bold; }\n");
        sb.append(".medium { color: #f57c00; font-weight: bold; }\n");
        sb.append(".low { color: #1976d2; }\n");
        sb.append(".info { color: #616161; }\n");
        sb.append(".meta { color: #666; font-size: 0.9em; }\n");
        sb.append("</style>\n</head>\n<body>\n");

        sb.append("<h1>流量安全分析报告</h1>\n");
        sb.append("<p class='meta'>生成时间: ").append(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date())).append("</p>\n");
        sb.append("<p class='meta'>共发现 ").append(lastResults.size()).append(" 个风险点</p>\n");

        // 统计摘要
        sb.append("<h2>严重性分布</h2>\n<table><tr><th>严重性</th><th>数量</th></tr>\n");
        Map<VulnReport.Severity, Integer> severityCount = new LinkedHashMap<>();
        for (VulnReport r : lastResults)
        {
            severityCount.merge(r.getSeverity(), 1, Integer::sum);
        }
        for (Map.Entry<VulnReport.Severity, Integer> entry : severityCount.entrySet())
        {
            String cssClass = getSeverityCssClass(entry.getKey());
            sb.append("<tr><td class='").append(cssClass).append("'>").append(entry.getKey().label())
              .append("</td><td>").append(entry.getValue()).append("</td></tr>\n");
        }
        sb.append("</table>\n");

        // 详细列表
        sb.append("<h2>详细结果</h2>\n");
        sb.append("<table><tr><th>URL</th><th>方法</th><th>风险类型</th><th>严重性</th>"
            + "<th>参数</th><th>状态</th><th>AI 建议</th></tr>\n");

        for (VulnReport r : lastResults)
        {
            String cssClass = getSeverityCssClass(r.getSeverity());
            sb.append("<tr>");
            sb.append("<td>").append(TextUtils.escapeHtml(safe(r.getUrl()))).append("</td>");
            sb.append("<td>").append(TextUtils.escapeHtml(safe(r.getMethod()))).append("</td>");
            sb.append("<td>").append(TextUtils.escapeHtml(safe(r.getVulnType()))).append("</td>");
            sb.append("<td class='").append(cssClass).append("'>").append(r.getSeverity().label()).append("</td>");
            sb.append("<td>").append(TextUtils.escapeHtml(safe(r.getParameter()))).append("</td>");
            sb.append("<td>").append(r.getVerifyStatus().label()).append("</td>");
            sb.append("<td>").append(TextUtils.escapeHtml(TextUtils.truncate(safe(r.getSuggestion()), 80))).append("</td>");
            sb.append("</tr>\n");
        }
        sb.append("</table>\n");

        // 每个漏洞的详细描述
        sb.append("<h2>漏洞详情</h2>\n");
        int idx = 1;
        for (VulnReport r : lastResults)
        {
            String cssClass = getSeverityCssClass(r.getSeverity());
            sb.append("<div style='margin:12px 0;padding:12px;border:1px solid #ddd;border-radius:4px;'>\n");
            sb.append("<h3 style='margin:0 0 8px 0;'>#").append(idx++).append(" ")
              .append("<span class='").append(cssClass).append("'>[").append(r.getSeverity().label())
              .append("]</span> ").append(TextUtils.escapeHtml(safe(r.getVulnType()))).append("</h3>\n");
            sb.append("<p><strong>URL:</strong> ").append(TextUtils.escapeHtml(safe(r.getUrl()))).append("</p>\n");
            if (r.getMethod() != null) sb.append("<p><strong>方法:</strong> ").append(TextUtils.escapeHtml(r.getMethod())).append("</p>\n");
            if (r.getParameter() != null) sb.append("<p><strong>参数:</strong> ").append(TextUtils.escapeHtml(r.getParameter())).append("</p>\n");
            if (r.getDescription() != null) sb.append("<p><strong>描述:</strong> ").append(TextUtils.escapeHtml(r.getDescription())).append("</p>\n");
            if (r.getEvidence() != null) sb.append("<p><strong>证据:</strong> ").append(TextUtils.escapeHtml(r.getEvidence())).append("</p>\n");
            if (r.getSuggestion() != null) sb.append("<p><strong>建议:</strong> ").append(TextUtils.escapeHtml(r.getSuggestion())).append("</p>\n");
            sb.append("<p><strong>验证状态:</strong> ").append(r.getVerifyStatus().label());
            if (r.getConfidence() > 0) sb.append(" | <strong>置信度:</strong> ").append(String.format("%.0f%%", r.getConfidence() * 100));
            sb.append("</p>\n");
            sb.append("</div>\n");
        }

        sb.append("</body>\n</html>");
        return sb.toString();
    }

    private String getSeverityCssClass(VulnReport.Severity severity)
    {
        switch (severity)
        {
            case CRITICAL: return "critical";
            case HIGH: return "high";
            case MEDIUM: return "medium";
            case LOW: return "low";
            default: return "info";
        }
    }

    private void sendToChat()
    {
        if (lastResults.isEmpty())
        {
            appendLog("<div style='color:#f57c00;'>没有分析结果可发送。</div>");
            return;
        }
        if (chatSessionCallback == null)
        {
            appendLog("<div style='color:#f57c00;'>聊天面板未连接。</div>");
            return;
        }

        String summary = analyzer.generateAnalysisSummary(lastResults);
        String title = "流量分析 - " + lastResults.size() + " 个风险点";
        chatSessionCallback.createAndAnalyzeSession(title, summary);
        appendLog("<div style='color:#1565c0;'>分析结果已发送到 AI 对话并自动触发分析。</div>");
    }

    private void sendSelectedToChat()
    {
        VulnReport report = getSelectedReport();
        if (report == null)
        {
            appendLog("<div style='color:#f57c00;'>请先选择表格中的一行。</div>");
            return;
        }
        if (chatSessionCallback == null) return;

        List<VulnReport> singleList = new ArrayList<>();
        singleList.add(report);
        String summary = analyzer.generateAnalysisSummary(singleList);
        chatSessionCallback.createAndAnalyzeSession(
            "漏洞详情 - " + report.getVulnType(), summary);
    }

    private void verifySelected()
    {
        VulnReport report = getSelectedReport();
        if (report == null)
        {
            appendLog("<div style='color:#f57c00;'>请先选择表格中的一行。</div>");
            return;
        }
        if (chatSessionCallback == null) return;

        String context = "请帮我验证以下漏洞发现：\n\n" + report.toChatContext();
        if (report.getOriginalRequest() != null && !report.getOriginalRequest().isEmpty())
        {
            context += "\n\n原始请求:\n```http\n" + report.getOriginalRequest() + "\n```";
        }
        chatSessionCallback.createAndVerifySession(
            "验证漏洞 - " + report.getVulnType(), context);
    }

    // ==================== 导出功能 ====================

    private void showExportMenu()
    {
        JPopupMenu exportMenu = new JPopupMenu();

        JMenuItem toClipboardItem = new JMenuItem("复制摘要到剪贴板");
        toClipboardItem.addActionListener(e -> exportSummaryToClipboard());
        exportMenu.add(toClipboardItem);

        JMenuItem toFileItem = new JMenuItem("导出到文件");
        toFileItem.addActionListener(e -> exportToFile());
        exportMenu.add(toFileItem);

        JMenuItem toHtmlItem = new JMenuItem("导出 HTML 报告");
        toHtmlItem.addActionListener(e -> exportReportAsHtml());
        exportMenu.add(toHtmlItem);

        exportMenu.show(exportButton, 0, exportButton.getHeight());
    }

    private void exportSummaryToClipboard()
    {
        if (lastResults.isEmpty())
        {
            appendLog("<div style='color:#f57c00;'>没有可导出的分析结果。</div>");
            return;
        }
        String summary = analyzer.generateAnalysisSummary(lastResults);
        java.awt.Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
            new java.awt.datatransfer.StringSelection(summary), null);
        appendLog("<div style='color:#2e7d32;'>分析摘要已复制到剪贴板。</div>");
    }

    private void exportToFile()
    {
        if (lastResults.isEmpty())
        {
            appendLog("<div style='color:#f57c00;'>没有可导出的分析结果。</div>");
            return;
        }

        // 默认保存到桌面
        String desktopPath = System.getProperty("user.home") + File.separator + "Desktop";
        JFileChooser fileChooser = new JFileChooser(desktopPath);
        fileChooser.setDialogTitle("导出分析报告到文件");

        // 添加文件格式过滤器
        javax.swing.filechooser.FileNameExtensionFilter txtFilter =
            new javax.swing.filechooser.FileNameExtensionFilter("文本文件 (*.txt)", "txt");
        javax.swing.filechooser.FileNameExtensionFilter mdFilter =
            new javax.swing.filechooser.FileNameExtensionFilter("Markdown 文件 (*.md)", "md");
        fileChooser.addChoosableFileFilter(txtFilter);
        fileChooser.addChoosableFileFilter(mdFilter);
        fileChooser.setFileFilter(txtFilter);

        fileChooser.setSelectedFile(new File(desktopPath, "traffic-analysis-report.txt"));

        int userChoice = fileChooser.showSaveDialog(this);
        if (userChoice != JFileChooser.APPROVE_OPTION) return;

        File file = fileChooser.getSelectedFile();
        String fileName = file.getName().toLowerCase();

        // 自动补充扩展名
        if (!fileName.endsWith(".txt") && !fileName.endsWith(".md"))
        {
            javax.swing.filechooser.FileFilter selectedFilter = fileChooser.getFileFilter();
            if (selectedFilter == mdFilter)
            {
                file = new File(file.getAbsolutePath() + ".md");
            }
            else
            {
                file = new File(file.getAbsolutePath() + ".txt");
            }
        }

        // 覆盖确认
        if (file.exists())
        {
            int confirm = JOptionPane.showConfirmDialog(this,
                "文件已存在，是否覆盖？\n" + file.getName(),
                "确认覆盖", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            if (confirm != JOptionPane.YES_OPTION) return;
        }

        // 生成内容
        String content;
        String extension = file.getName().toLowerCase();
        if (extension.endsWith(".md"))
        {
            content = generateMarkdownReport();
        }
        else
        {
            content = analyzer.generateAnalysisSummary(lastResults);
        }

        try (OutputStreamWriter writer = new OutputStreamWriter(
            new FileOutputStream(file), StandardCharsets.UTF_8))
        {
            writer.write(content);
            appendLog("<div style='color:#2e7d32;'>报告已导出到: "
                + TextUtils.escapeHtml(file.getAbsolutePath()) + "</div>");
        }
        catch (IOException ex)
        {
            appendLog("<div style='color:red;'>导出失败: " + TextUtils.escapeHtml(ex.getMessage()) + "</div>");
        }
    }

    private String generateMarkdownReport()
    {
        StringBuilder sb = new StringBuilder();
        sb.append("# 流量安全分析报告\n\n");
        sb.append("**生成时间:** ").append(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date())).append("\n\n");
        sb.append("**总发现:** ").append(lastResults.size()).append(" 个风险点\n\n");

        // 严重性分布
        sb.append("## 严重性分布\n\n");
        Map<VulnReport.Severity, Integer> severityCount = new LinkedHashMap<>();
        for (VulnReport r : lastResults)
        {
            severityCount.merge(r.getSeverity(), 1, Integer::sum);
        }
        sb.append("| 严重性 | 数量 |\n| --- | --- |\n");
        for (Map.Entry<VulnReport.Severity, Integer> entry : severityCount.entrySet())
        {
            sb.append("| ").append(entry.getKey().label()).append(" | ").append(entry.getValue()).append(" |\n");
        }
        sb.append("\n");

        // 详细列表
        sb.append("## 详细结果\n\n");
        sb.append("| URL | 方法 | 风险类型 | 严重性 | 参数 | 状态 |\n");
        sb.append("| --- | --- | --- | --- | --- | --- |\n");
        for (VulnReport r : lastResults)
        {
            sb.append("| ").append(escapeMarkdownCell(safe(r.getUrl())))
              .append(" | ").append(escapeMarkdownCell(safe(r.getMethod())))
              .append(" | ").append(escapeMarkdownCell(safe(r.getVulnType())))
              .append(" | ").append(r.getSeverity().label())
              .append(" | ").append(escapeMarkdownCell(safe(r.getParameter())))
              .append(" | ").append(r.getVerifyStatus().label())
              .append(" |\n");
        }
        sb.append("\n");

        // 漏洞详情
        sb.append("## 漏洞详情\n\n");
        int idx = 1;
        for (VulnReport r : lastResults)
        {
            sb.append("### #").append(idx++).append(" [")
              .append(r.getSeverity().label()).append("] ")
              .append(escapeMarkdownCell(safe(r.getVulnType()))).append("\n\n");
            sb.append("- **URL:** ").append(escapeMarkdownCell(safe(r.getUrl()))).append("\n");
            if (r.getMethod() != null) sb.append("- **方法:** ").append(escapeMarkdownCell(r.getMethod())).append("\n");
            if (r.getParameter() != null) sb.append("- **参数:** ").append(escapeMarkdownCell(r.getParameter())).append("\n");
            if (r.getDescription() != null) sb.append("- **描述:** ").append(escapeMarkdownCell(r.getDescription())).append("\n");
            if (r.getEvidence() != null) sb.append("- **证据:** ").append(escapeMarkdownCell(r.getEvidence())).append("\n");
            if (r.getSuggestion() != null) sb.append("- **建议:** ").append(escapeMarkdownCell(r.getSuggestion())).append("\n");
            sb.append("- **验证状态:** ").append(r.getVerifyStatus().label());
            if (r.getConfidence() > 0) sb.append(" | **置信度:** ").append(String.format("%.0f%%", r.getConfidence() * 100));
            sb.append("\n\n");
        }

        return sb.toString();
    }

    private String escapeMarkdownCell(String text)
    {
        return safe(text).replace("|", "\\|").replace("\r", " ").replace("\n", "<br>");
    }

    private void showStats()
    {
        if (lastResults.isEmpty())
        {
            appendLog("<div style='color:#f57c00;'>暂无分析结果可统计。</div>");
            return;
        }

        // 统计分析
        Map<VulnReport.Severity, Integer> severityCount = new LinkedHashMap<>();
        Map<String, Integer> typeCount = new LinkedHashMap<>();
        Map<String, Integer> hostCount = new LinkedHashMap<>();
        int confirmed = 0, unverified = 0, falsePositive = 0, pending = 0;

        for (VulnReport r : lastResults)
        {
            severityCount.merge(r.getSeverity(), 1, Integer::sum);
            typeCount.merge(r.getVulnType(), 1, Integer::sum);
            if (r.getHost() != null) hostCount.merge(r.getHost(), 1, Integer::sum);

            switch (r.getVerifyStatus())
            {
                case CONFIRMED: confirmed++; break;
                case UNVERIFIED: unverified++; break;
                case FALSE_POSITIVE: falsePositive++; break;
                case PENDING: pending++; break;
            }
        }

        StringBuilder sb = new StringBuilder();
        sb.append("<div style='padding:8px;'>");
        sb.append("<h3>分析统计</h3>");
        sb.append("<table style='width:100%;border-collapse:collapse;'>");
        sb.append("<tr style='background:#e3f2fd;'><th style='padding:4px;text-align:left;'>指标</th>"
            + "<th style='padding:4px;'>数量</th></tr>");
        sb.append(statRow("总发现", String.valueOf(lastResults.size())));
        sb.append(statRow("已确认", String.valueOf(confirmed), "#2e7d32"));
        sb.append(statRow("待验证", String.valueOf(pending), "#f57c00"));
        sb.append(statRow("无法验证", String.valueOf(unverified)));
        sb.append(statRow("误报", String.valueOf(falsePositive), "#999"));
        sb.append("</table>");

        sb.append("<h4>严重性分布</h4>");
        for (Map.Entry<VulnReport.Severity, Integer> entry : severityCount.entrySet())
        {
            String color = getSeverityColor(entry.getKey());
            sb.append("<div style='color:").append(color).append(";'>")
                .append(entry.getKey().label()).append(": ").append(entry.getValue())
                .append(" 个</div>");
        }

        sb.append("<h4>漏洞类型分布</h4>");
        typeCount.entrySet().stream()
            .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
            .forEach(e -> sb.append("<div>").append(e.getKey()).append(": ").append(e.getValue()).append(" 个</div>"));

        if (!hostCount.isEmpty())
        {
            sb.append("<h4>按主机分布</h4>");
            hostCount.entrySet().stream()
                .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
                .limit(10)
                .forEach(e -> sb.append("<div>").append(e.getKey()).append(": ").append(e.getValue()).append(" 个</div>"));
        }

        sb.append("</div>");
        appendLog(sb.toString());
    }

    private String statRow(String label, String value)
    {
        return "<tr><td style='padding:4px;border-bottom:1px solid #ddd;'>" + label
            + "</td><td style='padding:4px;text-align:center;border-bottom:1px solid #ddd;'>"
            + value + "</td></tr>";
    }

    private String statRow(String label, String value, String color)
    {
        return "<tr><td style='padding:4px;border-bottom:1px solid #ddd;'>" + label
            + "</td><td style='padding:4px;text-align:center;border-bottom:1px solid #ddd;color:"
            + color + ";font-weight:bold;'>" + value + "</td></tr>";
    }

    // ==================== UI辅助方法 ====================

    private void appendLog(String html)
    {
        SwingUtilities.invokeLater(() -> {
            try
            {
                javax.swing.text.html.HTMLDocument doc =
                    (javax.swing.text.html.HTMLDocument) logPane.getDocument();
                // 裁剪：超过 500KB 时移除前半部分
                if (doc.getLength() > 500000)
                {
                    String text = logPane.getText();
                    int cutPoint = text.indexOf("</table>", text.length() / 2);
                    if (cutPoint > 0)
                    {
                        logPane.setText(text.substring(cutPoint + 8));
                        doc = (javax.swing.text.html.HTMLDocument) logPane.getDocument();
                    }
                }
                javax.swing.text.html.HTMLEditorKit kit =
                    (javax.swing.text.html.HTMLEditorKit) logPane.getEditorKit();
                kit.insertHTML(doc, doc.getLength(), html, 0, 0, null);
                logPane.setCaretPosition(doc.getLength());
            }
            catch (Exception e)
            {
                logPane.setText(logPane.getText() + html);
            }
        });
    }

    private String getSeverityColor(VulnReport.Severity severity)
    {
        switch (severity)
        {
            case CRITICAL: return "#b71c1c";
            case HIGH: return "#d32f2f";
            case MEDIUM: return "#f57c00";
            case LOW: return "#1976d2";
            default: return "#616161";
        }
    }

    private boolean looksLikeHtml(String text)
    {
        if (text == null) return false;
        String t = text.trim();
        return t.startsWith("<div") || t.startsWith("<span") || t.startsWith("<font")
            || t.startsWith("<b") || t.startsWith("<i") || t.startsWith("<table");
    }

    private void showSelectedDetail()
    {
        VulnReport report = getSelectedReport();
        detailArea.setText(report == null ? "" : formatReport(report));
        detailArea.setCaretPosition(0);
    }

    private VulnReport getSelectedReport()
    {
        int row = resultTable.getSelectedRow();
        if (row < 0) return null;
        int modelRow = resultTable.convertRowIndexToModel(row);
        return tableModel.getRow(modelRow);
    }

    private void copySelectedDetail()
    {
        VulnReport report = getSelectedReport();
        if (report == null) return;
        java.awt.Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
            new java.awt.datatransfer.StringSelection(formatReport(report)), null);
    }

    private String formatReport(VulnReport r)
    {
        StringBuilder sb = new StringBuilder();
        sb.append("URL: ").append(safe(r.getUrl())).append("\n");
        sb.append("方法: ").append(safe(r.getMethod())).append("\n");
        sb.append("主机: ").append(safe(r.getHost())).append("\n");
        sb.append("风险: ").append(safe(r.getVulnType())).append("\n");
        sb.append("分类: ").append(safe(r.getCategory())).append("\n");
        sb.append("严重性: ").append(r.getSeverity().label()).append("\n");
        sb.append("参数: ").append(safe(r.getParameter())).append("\n");
        sb.append("置信度: ").append(String.format("%.2f", r.getConfidence())).append("\n");
        sb.append("描述: ").append(safe(r.getDescription())).append("\n");
        sb.append("证据: ").append(safe(r.getEvidence())).append("\n");
        sb.append("建议: ").append(safe(r.getSuggestion())).append("\n");
        sb.append("状态: ").append(r.getVerifyStatus().label()).append("\n");
        if (!r.getTags().isEmpty())
        {
            sb.append("标签: ").append(String.join(", ", r.getTags())).append("\n");
        }
        if (r.getVerificationDetail() != null && !r.getVerificationDetail().isEmpty())
        {
            sb.append("验证详情: ").append(r.getVerificationDetail()).append("\n");
        }
        if (r.getResponseCode() != null && !r.getResponseCode().isEmpty())
        {
            sb.append("响应状态码: ").append(r.getResponseCode()).append("\n");
        }
        return sb.toString();
    }

    private String safe(String text)
    {
        return text == null ? "" : text;
    }

    // ==================== 严重性颜色渲染 ====================

    private class SeverityCellRenderer extends DefaultTableCellRenderer
    {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
            boolean isSelected, boolean hasFocus, int row, int column)
        {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (!isSelected && value instanceof String)
            {
                String text = (String) value;
                if (text.contains("严重")) c.setForeground(new Color(0xb7, 0x1c, 0x1c));
                else if (text.contains("高")) c.setForeground(new Color(0xd3, 0x2f, 0x2f));
                else if (text.contains("中")) c.setForeground(new Color(0xf5, 0x7c, 0x00));
                else if (text.contains("低")) c.setForeground(new Color(0x19, 0x76, 0xd2));
                else c.setForeground(new Color(0x61, 0x61, 0x61));
            }
            else if (isSelected)
            {
                c.setForeground(Color.WHITE);
            }
            return c;
        }
    }

    // ==================== 操作列渲染器 ====================

    private class ActionCellRenderer extends DefaultTableCellRenderer
    {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
            boolean isSelected, boolean hasFocus, int row, int column)
        {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            setHorizontalAlignment(SwingConstants.CENTER);
            if (!isSelected)
            {
                setForeground(new Color(0x15, 0x65, 0xc0)); // 蓝色链接样式
            }
            else
            {
                setForeground(Color.WHITE);
            }
            return c;
        }
    }

    // ==================== 表格模型 ====================

    private class VulnTableModel extends AbstractTableModel
    {
        private final String[] columns = {
            COL_URL, COL_METHOD, COL_RISK_TYPE, COL_SEVERITY,
            COL_PARAMETER, COL_SUGGESTION, COL_STATUS, COL_ACTION
        };
        private final List<VulnReport> data = new ArrayList<>();

        public void addVuln(VulnReport r)
        {
            data.add(r);
            fireTableRowsInserted(data.size() - 1, data.size() - 1);
        }

        public void clear()
        {
            data.clear();
            fireTableDataChanged();
        }

        public VulnReport getRow(int row)
        {
            return row >= 0 && row < data.size() ? data.get(row) : null;
        }

        public List<VulnReport> getAllData()
        {
            return new ArrayList<>(data);
        }

        @Override
        public int getRowCount() { return data.size(); }

        @Override
        public int getColumnCount() { return columns.length; }

        @Override
        public String getColumnName(int col) { return columns[col]; }

        @Override
        public Object getValueAt(int row, int col)
        {
            VulnReport r = data.get(row);
            switch (col)
            {
                case 0: return TextUtils.truncate(r.getUrl(), 50);
                case 1: return r.getMethod();
                case 2: return r.getVulnType();
                case 3: return r.getSeverity().label();
                case 4: return r.getParameter();
                case 5: return TextUtils.truncate(r.getSuggestion(), 40);
                case 6: return r.getVerifyStatus().label();
                case 7: return BTN_TO_REPEATER; // "Repeater"
                default: return "";
            }
        }
    }

    // ==================== 主机列表加载（仿仪表盘风格） ====================

    /**
     * 从代理历史加载主机列表到目标选择下拉框。
     * 与仪表盘的 loadProxyHosts 设计一致。
     */
    public void loadProxyHosts(java.util.List<String> hosts)
    {
        if (hosts == null || hosts.isEmpty()) return;
        String firstKey = null;
        suppressComboUpdate = true;
        try
        {
            for (String hostPort : hosts)
            {
                if (hostPort == null || hostPort.isEmpty()) continue;
                if (hostsInCombo.contains(hostPort)) continue;
                hostsInCombo.add(hostPort);
                targetScopeCombo.addItem(hostPort);
                if (firstKey == null) firstKey = hostPort;
            }
            // editable combo: 必须显式选中第一个 item，否则下拉列表虽已填充但看起来为空
            if (firstKey != null && targetScopeCombo.getSelectedIndex() < 0)
            {
                targetScopeCombo.setSelectedItem(firstKey);
            }
        }
        finally
        {
            suppressComboUpdate = false;
        }
    }

    /**
     * 动态添加发现的新主机到目标选择下拉框。
     */
    public void ensureHostInCombo(String hostPort)
    {
        if (hostPort == null || hostPort.isEmpty() || hostsInCombo.contains(hostPort)) return;
        hostsInCombo.add(hostPort);
        suppressComboUpdate = true;
        try { targetScopeCombo.addItem(hostPort); }
        finally { suppressComboUpdate = false; }
    }
}
