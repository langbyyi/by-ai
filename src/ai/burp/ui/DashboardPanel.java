package ai.burp.ui;

import java.awt.*;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import ai.burp.model.VulnReport;

import ai.burp.provider.StreamingAIProvider;
import ai.burp.scanner.AttackSurfaceMapper;
import ai.burp.scanner.AttackSurfaceMapper.AttackSurface;
import ai.burp.scanner.AttackSurfaceMapper.RiskEndpoint;
import ai.burp.scanner.TechFingerprint;
import ai.burp.scanner.TechFingerprint.TechStack;
import ai.burp.scanner.InfoExtractor;
import ai.burp.scanner.InfoExtractor.ExtractedInfo;
import ai.burp.scanner.AuditLogger;

import static ai.burp.ui.ChineseUI.*;

/**
 * 安全仪表盘面板 - 攻击面概览、漏洞统计、技术栈、关键信息。
 * 顶部工具栏包含主机选择器和开始/暂停分析按钮。
 */
public class DashboardPanel extends JPanel
{
    private JTable statsTable;
    private JTextArea flowArea;
    private JTable techTable;
    private JTable riskTable;
    private JTextArea techDetailArea;

    private final JComboBox<String> hostSelector = new JComboBox<>();
    private final Map<String, TechStack> techStackMap = new ConcurrentHashMap<>();
    private final Map<String, String> hostToKey = new ConcurrentHashMap<>();
    private String currentHost = null;
    private boolean hostSelectorChanging = false;
    private final Set<String> hostsInSelector = new LinkedHashSet<>();

    private final MontoyaApi api;
    private final StreamingAIProvider provider;
    private final TechFingerprint fingerprint;
    private final InfoExtractor infoExtractor;
    private final AuditLogger logger;

    private JButton startButton;
    private JLabel statusLabel;
    private final AtomicBoolean analysing = new AtomicBoolean(false);
    private SwingWorker<String, String> currentWorker;
    private SwingWorker<?, ?> activePostWorker;
    private AttackSurface currentSurface;
    private final Map<String, AttackSurface> surfaceMap = new ConcurrentHashMap<>();

    public DashboardPanel(MontoyaApi api, StreamingAIProvider provider,
        TechFingerprint fingerprint, InfoExtractor infoExtractor, AuditLogger logger)
    {
        this.api = api;
        this.provider = provider;
        this.fingerprint = fingerprint;
        this.infoExtractor = infoExtractor;
        this.logger = logger;
        initUI();
    }

    private void initUI()
    {
        setLayout(new BorderLayout(4, 4));
        setBorder(new EmptyBorder(3, 3, 3, 3));

        JTabbedPane innerTabs = new JTabbedPane();

        // ===== 顶部工具栏 =====
        JPanel hostToolbar = UIStyle.toolbar();
        hostToolbar.add(UIStyle.mutedLabel(DASHBOARD_HOST_LABEL));
        hostSelector.setFont(hostSelector.getFont().deriveFont(Font.PLAIN, 12f));
        hostSelector.setPreferredSize(new Dimension(200, 28));
        hostSelector.setToolTipText("选择要查看的目标主机");
        hostSelector.addActionListener(e -> {
            if (hostSelectorChanging) return;
            onHostSelected();
        });
        hostToolbar.add(hostSelector);

        hostToolbar.add(Box.createHorizontalStrut(8));

        startButton = new JButton(DASHBOARD_BTN_START);
        UIStyle.primaryButton(startButton);
        startButton.setToolTipText("对选中主机运行全量攻击面分析（SiteMap + Proxy 历史）");
        startButton.addActionListener(e -> toggleAnalysis());
        hostToolbar.add(startButton);

        JButton clearDashBtn = new JButton(BTN_CLEAR);
        UIStyle.compactButton(clearDashBtn);
        clearDashBtn.setToolTipText("清空当前主机的分析数据");
        clearDashBtn.addActionListener(e -> clearCurrentHost());
        hostToolbar.add(clearDashBtn);

        hostToolbar.add(Box.createHorizontalStrut(6));
        statusLabel = UIStyle.mutedLabel(" ");
        hostToolbar.add(statusLabel);

        add(hostToolbar, BorderLayout.NORTH);

        // ===== 概览标签 =====
        JPanel overviewPanel = new JPanel(new BorderLayout(4, 4));
        String[] statsCols = {"指标", "数值"};
        Object[][] statsData = {
            {"总端点数", "-"},
            {"高风险端点", "-"},
            {"认证相关", "-"},
            {"API接口", "-"},
            {"隐藏接口", "-"},
            {"可能遗漏", "-"},
            {"未认证接口", "-"},
            {"文件上传", "-"},
            {"数据库操作", "-"},
            {"管理面板", "-"}
        };
        statsTable = new JTable(statsData, statsCols);
        configureTable(statsTable);
        // 点击概览行展示该分类的端点详情
        statsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        statsTable.addMouseListener(new java.awt.event.MouseAdapter()
        {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e)
            {
                int row = statsTable.rowAtPoint(e.getPoint());
                if (row >= 0) showCategoryDetail(row);
            }
        });
        JScrollPane statsScroll = UIStyle.scroll(statsTable);

        flowArea = new JTextArea();
        flowArea.setEditable(false);
        flowArea.setLineWrap(true);
        flowArea.setWrapStyleWord(true);
        flowArea.setRows(4);
        JScrollPane flowScroll = UIStyle.scroll(flowArea);

        JSplitPane overviewSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, statsScroll, flowScroll);
        overviewSplit.setResizeWeight(0.65);
        overviewSplit.setDividerSize(6);
        overviewSplit.setOneTouchExpandable(true);
        overviewSplit.setContinuousLayout(true);
        SwingUtilities.invokeLater(() -> overviewSplit.setDividerLocation(0.65));
        overviewPanel.add(overviewSplit, BorderLayout.CENTER);
        innerTabs.addTab("概览", overviewPanel);

        // ===== 技术栈标签 =====
        JPanel techPanel = new JPanel(new BorderLayout(4, 4));

        String[] techCols = {"类别", "识别结果", "状态"};
        Object[][] techData = {
            {"开发语言", "-", "未识别"},
            {"Web框架", "-", "未识别"},
            {"服务器", "-", "未识别"},
            {"操作系统", "-", "未识别"},
            {"CMS", "-", "未识别"},
            {"前端框架", "-", "未识别"},
            {"API风格", "-", "未识别"},
            {"组件", "-", "未识别"}
        };
        techTable = new JTable(techData, techCols);
        configureTable(techTable);
        techTable.getColumnModel().getColumn(2).setCellRenderer(new TechSourceCellRenderer());
        JScrollPane techScroll = UIStyle.scroll(techTable);

        techDetailArea = new JTextArea();
        techDetailArea.setEditable(false);
        techDetailArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        techDetailArea.setLineWrap(true);
        techDetailArea.setWrapStyleWord(true);
        techDetailArea.setText("选择主机并点击「开始分析」以识别技术栈。");
        JScrollPane techDetailScroll = UIStyle.scroll(techDetailArea);

        JSplitPane techSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, techScroll, techDetailScroll);
        techSplit.setResizeWeight(0.6);
        techSplit.setDividerSize(6);
        techSplit.setOneTouchExpandable(true);
        techSplit.setContinuousLayout(true);
        SwingUtilities.invokeLater(() -> techSplit.setDividerLocation(0.6));
        techPanel.add(techSplit, BorderLayout.CENTER);
        innerTabs.addTab("技术栈", techPanel);

        // ===== 风险端点标签 =====
        JPanel riskPanel = new JPanel(new BorderLayout());
        String[] riskCols = {"端点", "风险原因"};
        riskTable = new JTable(new Object[][]{}, riskCols);
        configureTable(riskTable);
        riskTable.getColumnModel().getColumn(0).setPreferredWidth(400);
        riskTable.getColumnModel().getColumn(1).setPreferredWidth(250);
        riskTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        riskPanel.add(UIStyle.scroll(riskTable), BorderLayout.CENTER);
        innerTabs.addTab("风险端点", riskPanel);

        add(innerTabs, BorderLayout.CENTER);
    }

    // ==================== 开始/暂停分析 ====================

    /**
     * 取消所有正在运行的分析（主分析 + 附加分析）。
     * 供外部调用，确保新分析启动前旧分析已停止。
     */
    public void cancelAllAnalysis()
    {
        analysing.set(false);
        if (currentWorker != null) { currentWorker.cancel(false); currentWorker = null; }
        if (activePostWorker != null) { activePostWorker.cancel(false); activePostWorker = null; }
        SwingUtilities.invokeLater(() -> startButton.setText(DASHBOARD_BTN_START));
    }

    private void toggleAnalysis()
    {
        String selected = (String) hostSelector.getSelectedItem();
        if (selected == null || selected.isEmpty())
        {
            statusLabel.setText("请先选择目标主机");
            return;
        }

        // 如果正在分析（可能是不同主机），取消旧的直接启动新的
        if (analysing.get())
        {
            cancelAllAnalysis();
        }

        // 清空该主机的旧 UI 缓存（保留 TechFingerprint 底层缓存，被动扫描器已积累的结果不应丢弃）
        techStackMap.remove(selected);
        currentSurface = null;

        analysing.set(true);
        startButton.setText(DASHBOARD_BTN_STOP);
        statusLabel.setText(DASHBOARD_STATUS_ANALYZING);

        final String hostPortKey = selected;
        final String host = extractHost(hostPortKey);

        currentWorker = new SwingWorker<String, String>()
        {
            @Override
            protected String doInBackground() throws Exception
            {
                publish("正在收集攻击面数据...");

                // 使用与"全量扫描"完全相同的引擎：AttackSurfaceMapper
                // 数据源统一：SiteMap + Proxy 历史，去重逻辑一致，含 AI 分析
                AttackSurfaceMapper mapper = new AttackSurfaceMapper(api, provider, logger);
                AttackSurface surface = mapper.map(host);

                if (!analysing.get() || isCancelled()) return "已取消";
                if (surface.totalEndpoints == 0)
                {
                    return "该主机无可用数据（SiteMap 和 Proxy 历史均为空）";
                }

                publish("攻击面收集完成: " + surface.totalEndpoints + " 个端点");

                // 用统一结果更新概览统计表 + 风险端点表 + 业务流程区
                final AttackSurface fSurface = surface;
                SwingUtilities.invokeLater(() -> updateAttackSurface(fSurface));

                // 附加分析：技术栈识别 + 关键信息提取（复用公共方法）
                runPostAnalysis(host);

                return "分析完成: " + surface.totalEndpoints + " 个端点, "
                    + surface.highRisk.size() + " 个高风险";
            }

            @Override
            protected void process(List<String> chunks)
            {
                String last = chunks.get(chunks.size() - 1);
                statusLabel.setText(last);
            }

            @Override
            protected void done()
            {
                // 如果已被更新的分析取代，直接跳过
                if (currentWorker != this) return;
                analysing.set(false);
                startButton.setText(DASHBOARD_BTN_START);
                try
                {
                    String result = get();
                    statusLabel.setText(result);
                    // 10秒后自动清除状态提示
                    Timer timer = new Timer(10000, e -> statusLabel.setText(" "));
                    timer.setRepeats(false);
                    timer.start();
                }
                catch (Exception e)
                {
                    statusLabel.setText("分析异常: " + e.getMessage());
                    Timer timer = new Timer(10000, evt -> statusLabel.setText(" "));
                    timer.setRepeats(false);
                    timer.start();
                }
            }
        };
        currentWorker.execute();
    }

    // ==================== 数据更新方法 ====================

    /**
     * 点击概览行时，在下方展示该分类的端点列表。
     * 行号对应: 0=总端点 1=高风险 2=认证 3=API 4=隐藏 5=遗漏 6=未认证 7=上传 8=数据库 9=管理面板
     */
    private void showCategoryDetail(int row)
    {
        AttackSurface surface = currentSurface;
        if (surface == null)
        {
            flowArea.setText("暂无数据，请先运行分析。");
            return;
        }

        String title;
        List<String> items;
        List<RiskEndpoint> riskItems;

        switch (row)
        {
            case 0:
                title = "全部端点";
                items = surface.allEndpoints;
                riskItems = null;
                break;
            case 1:
                title = "高风险端点";
                items = null;
                riskItems = surface.highRisk;
                break;
            case 2:
                title = "认证相关端点";
                items = surface.authEndpoints;
                riskItems = null;
                break;
            case 3:
                title = "API 接口";
                items = surface.apiEndpoints;
                riskItems = null;
                break;
            case 4:
                title = "隐藏接口";
                items = surface.hiddenEndpoints;
                riskItems = null;
                break;
            case 5:
                title = "可能遗漏的接口";
                items = surface.missingEndpoints;
                riskItems = null;
                break;
            case 6:
            {
                title = "未认证接口";
                items = null;
                riskItems = null;
                Object unauthCount = statsTable.getValueAt(6, 1);
                flowArea.setText("【未认证接口】AI估算共 " + unauthCount + " 个\n\n"
                    + "以下为未匹配认证模式的所有端点（供参考）:\n\n");
                // 用 Set 存认证端点的URL部分，做 O(1) 查找
                Set<String> authUrlPaths = new java.util.HashSet<>();
                for (String ep : surface.authEndpoints)
                {
                    String urlPart = extractUrlPart(ep);
                    if (!urlPart.isEmpty()) authUrlPaths.add(urlPart.toLowerCase());
                }
                int shown = 0;
                for (String ep : surface.allEndpoints)
                {
                    String urlPart = extractUrlPart(ep).toLowerCase();
                    if (!authUrlPaths.contains(urlPart))
                    {
                        flowArea.append("• " + ep + "\n");
                        shown++;
                    }
                }
                flowArea.append("\n（共 " + shown + " 个端点未匹配认证模式）");
                flowArea.setCaretPosition(0);
                return;
            }

            case 7:
                title = "文件上传端点";
                items = null;
                riskItems = filterByReason(surface.highRisk, "文件");
                break;
            case 8:
                title = "数据库操作";
                items = null;
                riskItems = null;
                Object dbCount = statsTable.getValueAt(8, 1);
                flowArea.setText("【数据库操作】AI估算共 " + dbCount + " 个\n\n"
                    + "该计数由AI根据端点模式分析得出，具体端点需结合业务逻辑判断。\n"
                    + "可关注包含 sql/db/database/data 等关键词的接口。");
                flowArea.setCaretPosition(0);
                return;
            case 9:
                title = "管理面板端点";
                items = null;
                riskItems = filterByReason(surface.highRisk, "管理");
                break;
            default:
                flowArea.setText("暂无数据");
                flowArea.setCaretPosition(0);
                return;
        }

        StringBuilder sb = new StringBuilder();
        sb.append("【").append(title).append("】");

        if (riskItems != null)
        {
            sb.append(" 共 ").append(riskItems.size()).append(" 个\n\n");
            for (RiskEndpoint ep : riskItems)
            {
                sb.append("• ").append(ep.url);
                if (ep.reason != null && !ep.reason.isEmpty())
                    sb.append("  [").append(ep.reason).append("]");
                sb.append("\n");
            }
        }
        else if (items != null)
        {
            sb.append(" 共 ").append(items.size()).append(" 个\n\n");
            for (String ep : items)
            {
                sb.append("• ").append(ep).append("\n");
            }
        }

        flowArea.setText(sb.toString());
        flowArea.setCaretPosition(0);
    }

    public void updateAttackSurface(AttackSurface surface)
    {
        currentSurface = surface;
        String surfaceKey = null;
        // 如果是指定主机的扫描结果，确保该主机在选择器中并选中
        if (surface.host != null && !surface.host.isEmpty())
        {
            String key = hostToKey.get(surface.host);
            if (key == null) key = surface.host;
            surfaceKey = key;
            ensureHostInSelector(key, surface.host);
            hostSelectorChanging = true;
            hostSelector.setSelectedItem(key);
            hostSelectorChanging = false;
            currentHost = key;
        }

        applySurfaceToUI(surface);

        // 缓存攻击面数据，供主机切换时恢复
        if (surfaceKey != null) surfaceMap.put(surfaceKey, surface);
    }

    public void updateTechStack(TechStack tech)
    {
        String host = tech.getHost();
        if (host == null || host.isEmpty()) return;
        String key = hostToKey.getOrDefault(host, host);
        techStackMap.put(key, tech);
        ensureHostInSelector(key, host);
        String selected = (String) hostSelector.getSelectedItem();
        if (selected == null || selected.equals(key))
        {
            hostSelectorChanging = true;
            hostSelector.setSelectedItem(key);
            hostSelectorChanging = false;
            currentHost = key;
            applyTechStackToTable(tech);
        }
    }

    private void applyTechStackToTable(TechStack tech)
    {
        setTechRow(0, tech.getLanguage());
        setTechRow(1, String.join(", ", tech.getFrameworks()));
        setTechRow(2, tech.getWebServer());
        setTechRow(3, tech.getOs());
        setTechRow(4, tech.getCms());
        setTechRow(5, tech.getFrontend());
        setTechRow(6, tech.getApiStyle());
        setTechRow(7, String.join(", ", tech.getComponents()));

        if (techDetailArea != null)
        {
            techDetailArea.setText(tech.summary());
        }
    }

    private void setTechRow(int row, String value)
    {
        boolean identified = value != null && !value.trim().isEmpty() && !value.equals("-");
        techTable.setValueAt(identified ? value : "-", row, 1);
        techTable.setValueAt(identified ? "已识别" : "未识别", row, 2);
    }

    public void updateRiskEndpoints(List<RiskEndpoint> risks)
    {
        Object[][] data = new Object[risks.size()][2];
        for (int i = 0; i < risks.size(); i++)
        {
            data[i][0] = risks.get(i).url;
            data[i][1] = risks.get(i).reason;
        }
        riskTable.setModel(new DefaultTableModel(data, new String[]{"端点", "风险原因"}));
        // setModel 会重建列模型，需重新设置列宽
        riskTable.getColumnModel().getColumn(0).setPreferredWidth(400);
        riskTable.getColumnModel().getColumn(1).setPreferredWidth(250);
    }

    public void updateFromTrafficAnalysis(List<VulnReport> results)
    {
        if (results == null || results.isEmpty()) return;

        Map<VulnReport.Severity, Integer> severityCount = new LinkedHashMap<>();

        for (VulnReport r : results)
        {
            severityCount.merge(r.getSeverity(), 1, Integer::sum);
        }

        StringBuilder flowText = new StringBuilder();
        if (flowArea.getText() != null && !flowArea.getText().isEmpty())
        {
            flowText.append(flowArea.getText()).append("\n\n");
        }
        flowText.append("--- 流量分析漏洞统计 ---\n");
        for (Map.Entry<VulnReport.Severity, Integer> entry : severityCount.entrySet())
        {
            flowText.append("• ").append(entry.getKey().label()).append(": ")
                .append(entry.getValue()).append(" 个\n");
        }
        flowText.append("• 总计: ").append(results.size()).append(" 个风险点");
        flowArea.setText(flowText.toString());
        flowArea.setCaretPosition(0);

        List<RiskEndpoint> riskEndpoints = new ArrayList<>();
        for (VulnReport r : results)
        {
            if (r.getUrl() != null)
            {
                String reason = (r.getVulnType() != null ? r.getVulnType() : "未知风险")
                    + " [" + r.getSeverity().label() + "]";
                if (r.getParameter() != null && !r.getParameter().isEmpty())
                {
                    reason += " - 参数: " + r.getParameter();
                }
                riskEndpoints.add(new RiskEndpoint(r.getUrl(), reason));
            }
        }
        if (!riskEndpoints.isEmpty())
        {
            DefaultTableModel riskModel = (DefaultTableModel) riskTable.getModel();
            for (RiskEndpoint ep : riskEndpoints)
            {
                riskModel.addRow(new Object[]{ep.url, ep.reason});
            }
        }
    }

    // ==================== 主机选择器辅助 ====================

    private void ensureHostInSelector(String hostPortKey, String host)
    {
        if (hostsInSelector.contains(hostPortKey)) return;
        hostsInSelector.add(hostPortKey);
        hostToKey.put(host, hostPortKey);
        hostSelectorChanging = true;
        hostSelector.addItem(hostPortKey);
        hostSelectorChanging = false;
    }

    /**
     * 清空当前主机的所有分析数据和缓存。
     */
    private void clearCurrentHost()
    {
        String selected = (String) hostSelector.getSelectedItem();
        if (selected == null) return;
        String host = extractHost(selected);

        // 清空内存缓存
        techStackMap.remove(selected);
        surfaceMap.remove(selected);
        currentSurface = null;
        TechFingerprint.invalidate(host);

        // 重置所有表格到默认状态
        for (int i = 0; i < statsTable.getRowCount(); i++)
        {
            statsTable.setValueAt("-", i, 1);
        }
        for (int i = 0; i < 8; i++)
        {
            techTable.setValueAt("-", i, 1);
            techTable.setValueAt("未识别", i, 2);
        }
        riskTable.setModel(new DefaultTableModel(new Object[][]{}, new String[]{"端点", "风险原因"}));
        flowArea.setText("");
        techDetailArea.setText("");
        statusLabel.setText("已清空");
    }

    private void onHostSelected()
    {
        String selected = (String) hostSelector.getSelectedItem();
        if (selected == null) return;
        currentHost = selected;
        TechStack tech = techStackMap.get(currentHost);
        applyTechStackToTable(tech != null ? tech : new TechStack(""));

        AttackSurface surface = surfaceMap.get(currentHost);
        if (surface != null)
        {
            currentSurface = surface;
            applySurfaceToUI(surface);
        }
        else
        {
            currentSurface = null;
            for (int i = 0; i < statsTable.getRowCount(); i++)
            {
                statsTable.setValueAt("-", i, 1);
            }
            updateRiskEndpoints(new ArrayList<>());
            flowArea.setText("");
        }
    }

    /**
     * 设置状态栏文字，可选延时自动清除。
     */
    public void setStatus(String text, boolean autoClear)
    {
        SwingUtilities.invokeLater(() -> {
            statusLabel.setText(text);
            if (autoClear && text != null && !text.trim().isEmpty())
            {
                Timer timer = new Timer(10000, e -> statusLabel.setText(" "));
                timer.setRepeats(false);
                timer.start();
            }
        });
    }

    /**
     * 攻击面数据更新后的附加分析（技术栈 + 关键信息提取）。
     * 供外部调用（如全量扫描完成后），在后台运行避免阻塞。
     */
    public void runPostAnalysis(final String host)
    {
        if (host == null || host.isEmpty()) return;

        // 取消上一次的附加分析
        if (activePostWorker != null) { activePostWorker.cancel(false); activePostWorker = null; }

        activePostWorker = new SwingWorker<Void, String>()
        {
            @Override
            protected Void doInBackground() throws Exception
            {
                List<ProxyHttpRequestResponse> history = api.proxy().history();
                // 从代理历史中选取多个非静态样本进行技术栈识别（增量积累）
                publish("正在识别技术栈...");
                TechStack tech = null;
                int sampleCount = 0;
                for (int i = history.size() - 1; i >= 0 && sampleCount < 15; i--)
                {
                    if (isCancelled()) break;
                    try
                    {
                        String h = history.get(i).finalRequest().httpService().host();
                        if (!host.equals(h)) continue;

                        String url = history.get(i).finalRequest().url().toLowerCase();
                        if (isStaticUrl(url)) continue;

                        HttpRequestResponse sample = (HttpRequestResponse) history.get(i);
                        tech = fingerprint.identify(sample);
                        sampleCount++;

                        // 已完整识别（语言+服务器）则提前退出
                        if (tech.isComplete()) break;
                    }
                    catch (Exception ignored) {}
                }

                if (tech != null)
                {
                    final TechStack fTech = tech;
                    SwingUtilities.invokeLater(() -> updateTechStack(fTech));
                }

                return null;
            }

            @Override
            protected void process(List<String> chunks)
            {
                String last = chunks.get(chunks.size() - 1);
                statusLabel.setText(last);
            }

            @Override
            protected void done()
            {
                // 如果已被更新的附加分析取代，直接跳过
                if (activePostWorker != this) return;
                setStatus("分析完成", true);
            }
        };
        activePostWorker.execute();
    }

    /**
     * 将 AttackSurface 数据应用到所有 UI 组件（概览表、风险端点表、业务流程区）。
     * updateAttackSurface 和 onHostSelected 共用此方法，避免重复代码。
     */
    private void applySurfaceToUI(AttackSurface surface)
    {
        // 概览表行0-5
        statsTable.setValueAt(String.valueOf(surface.totalEndpoints), 0, 1);
        statsTable.setValueAt(String.valueOf(surface.highRisk.size()), 1, 1);
        statsTable.setValueAt(String.valueOf(surface.authEndpoints.size()), 2, 1);
        statsTable.setValueAt(String.valueOf(surface.apiEndpoints.size()), 3, 1);
        statsTable.setValueAt(String.valueOf(surface.hiddenEndpoints.size()), 4, 1);
        statsTable.setValueAt(String.valueOf(surface.missingEndpoints.size()), 5, 1);
        // 行6-9: 从实际数据派生计数
        int fileUploadCount = 0, adminPanelCount = 0;
        for (RiskEndpoint ep : surface.highRisk)
        {
            if (ep.reason != null)
            {
                if (ep.reason.contains("文件")) fileUploadCount++;
                if (ep.reason.contains("管理")) adminPanelCount++;
            }
        }
        statsTable.setValueAt(String.valueOf(surface.unauthenticatedCount), 6, 1);
        statsTable.setValueAt(String.valueOf(Math.max(fileUploadCount, surface.fileUploadCount)), 7, 1);
        statsTable.setValueAt(String.valueOf(surface.databaseOpsCount), 8, 1);
        statsTable.setValueAt(String.valueOf(Math.max(adminPanelCount, surface.adminPanelCount)), 9, 1);

        // 合并所有风险分类到风险端点表
        updateRiskEndpoints(buildCombinedRisks(surface));

        // 业务流程区
        flowArea.setText(buildFlowText(surface));
        flowArea.setCaretPosition(0);
    }

    /**
     * 合并所有风险分类为统一的风险端点列表。
     */
    private static List<RiskEndpoint> buildCombinedRisks(AttackSurface surface)
    {
        List<RiskEndpoint> all = new ArrayList<>(surface.highRisk);
        for (String ep : surface.authEndpoints) all.add(new RiskEndpoint(ep, "认证相关"));
        for (String ep : surface.hiddenEndpoints) all.add(new RiskEndpoint(ep, "隐藏接口"));
        for (String ep : surface.missingEndpoints) all.add(new RiskEndpoint(ep, "可能遗漏"));
        return all;
    }

    /**
     * 构建业务流程区文本（业务流程 + 可能遗漏 + 隐藏接口）。
     */
    private static String buildFlowText(AttackSurface surface)
    {
        StringBuilder flow = new StringBuilder();
        for (String f : surface.businessFlows) flow.append("• ").append(f).append("\n");
        if (!surface.missingEndpoints.isEmpty())
        {
            flow.append("\n可能遗漏的接口:\n");
            for (String ep : surface.missingEndpoints) flow.append("• ").append(ep).append("\n");
        }
        if (!surface.hiddenEndpoints.isEmpty())
        {
            flow.append("\n隐藏接口:\n");
            for (String ep : surface.hiddenEndpoints) flow.append("• ").append(ep).append("\n");
        }
        return flow.length() > 0 ? flow.toString() : "未发现明显风险特征";
    }

    /**
     * 按风险原因关键词过滤端点列表。
     */
    private static List<RiskEndpoint> filterByReason(List<RiskEndpoint> endpoints, String reasonKeyword)
    {
        List<RiskEndpoint> result = new ArrayList<>();
        for (RiskEndpoint ep : endpoints)
        {
            if (ep.reason != null && ep.reason.contains(reasonKeyword))
            {
                result.add(ep);
            }
        }
        return result;
    }

    /**
     * 选中指定主机（供外部调用）。
     */
    public void selectHost(String host)
    {
        if (host == null || host.isEmpty()) return;
        String key = hostToKey.get(host);
        if (key == null) key = host;
        ensureHostInSelector(key, host);
        hostSelectorChanging = true;
        hostSelector.setSelectedItem(key);
        hostSelectorChanging = false;
        currentHost = key;
    }

    public void loadProxyHosts(java.util.List<String> hosts)
    {
        if (hosts == null || hosts.isEmpty()) return;
        boolean firstAdded = hostSelector.getItemCount() == 0;
        String firstKey = null;
        for (String hostPort : hosts)
        {
            if (hostPort == null || hostPort.isEmpty()) continue;
            if (hostsInSelector.contains(hostPort)) continue;
            String host = extractHost(hostPort);
            hostsInSelector.add(hostPort);
            hostToKey.put(host, hostPort);
            hostSelectorChanging = true;
            hostSelector.addItem(hostPort);
            hostSelectorChanging = false;
            if (firstKey == null) firstKey = hostPort;
        }
        if (firstKey != null && firstAdded)
        {
            hostSelectorChanging = true;
            hostSelector.setSelectedItem(firstKey);
            hostSelectorChanging = false;
            currentHost = firstKey;
            TechStack tech = techStackMap.get(firstKey);
            if (tech != null) applyTechStackToTable(tech);
        }
    }

    private static String extractHost(String hostPort)
    {
        if (hostPort == null) return "";
        if (hostPort.startsWith("["))
        {
            int bracket = hostPort.indexOf(']');
            return bracket > 0 ? hostPort.substring(1, bracket) : hostPort;
        }
        int colon = hostPort.lastIndexOf(':');
        return colon > 0 ? hostPort.substring(0, colon) : hostPort;
    }

    /**
     * 从 "METHOD url" 格式中提取URL部分。
     * AttackSurfaceMapper 存储格式为 "GET /api/..."，提取空格后的部分。
     */
    private static String extractUrlPart(String entry)
    {
        if (entry == null) return "";
        int space = entry.indexOf(' ');
        return space >= 0 ? entry.substring(space + 1) : entry;
    }

    private static boolean isStaticUrl(String url)
    {
        if (url == null) return false;
        String lower = url.toLowerCase();
        int q = lower.indexOf('?');
        String path = q >= 0 ? lower.substring(0, q) : lower;
        return path.endsWith(".css") || path.endsWith(".js")
            || path.endsWith(".png") || path.endsWith(".jpg")
            || path.endsWith(".jpeg") || path.endsWith(".gif")
            || path.endsWith(".ico") || path.endsWith(".svg")
            || path.endsWith(".woff") || path.endsWith(".woff2")
            || path.endsWith(".ttf") || path.endsWith(".eot")
            || path.endsWith(".map");
    }

    private void configureTable(JTable table)
    {
        UIStyle.table(table);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
        table.addMouseMotionListener(new java.awt.event.MouseMotionAdapter()
        {
            @Override
            public void mouseMoved(java.awt.event.MouseEvent e)
            {
                int row = table.rowAtPoint(e.getPoint());
                int col = table.columnAtPoint(e.getPoint());
                if (row >= 0 && col >= 0)
                {
                    Object value = table.getValueAt(row, col);
                    table.setToolTipText(value == null ? null : value.toString());
                }
            }
        });

        JPopupMenu menu = new JPopupMenu();
        JMenuItem copyCell = new JMenuItem("复制单元格");
        copyCell.addActionListener(e -> {
            int row = table.getSelectedRow();
            int col = table.getSelectedColumn();
            if (row < 0 || col < 0) return;
            Object value = table.getValueAt(row, col);
            java.awt.Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
                new java.awt.datatransfer.StringSelection(value == null ? "" : value.toString()), null);
        });
        menu.add(copyCell);
        table.setComponentPopupMenu(menu);
    }

    /**
     * 技术栈状态列自定义渲染器：已识别显示绿色，未识别显示灰色。
     */
    private static class TechSourceCellRenderer extends DefaultTableCellRenderer
    {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
            boolean isSelected, boolean hasFocus, int row, int column)
        {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (!isSelected)
            {
                String source = value == null ? "" : value.toString();
                if ("已识别".equals(source))
                {
                    c.setForeground(new Color(46, 125, 50));
                }
                else
                {
                    c.setForeground(Color.GRAY);
                }
            }
            return c;
        }
    }
}
