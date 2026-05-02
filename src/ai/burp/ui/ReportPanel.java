package ai.burp.ui;

import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.List;

import javax.swing.*;
import javax.swing.RowFilter;
import javax.swing.event.HyperlinkEvent;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableRowSorter;

import ai.burp.model.VulnReport;
import ai.burp.scanner.ReportGenerator;
import ai.burp.util.TextUtils;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;

import static ai.burp.ui.ChineseUI.*;

/**
 * 漏洞报告面板 - 结构化展示所有发现的漏洞。
 * <p>
 * 7列表格: 时间 | 漏洞类型 | URL | 严重性 | 参数 | 验证状态 | 操作
 * 严重性颜色编码、三重过滤(严重性+状态+搜索)、统计摘要、导出、Repeater操作。
 */
public class ReportPanel extends JPanel
{
    private MontoyaApi api;
    private Runnable onReportsChanged; // 数据变更回调

    private JTable vulnTable;
    private VulnReportTableModel tableModel;
    private TableRowSorter<VulnReportTableModel> rowSorter;
    private JEditorPane detailPane;
    private JLabel countLabel;
    private JTextField searchField;
    private JComboBox<String> severityFilter;
    private JComboBox<String> statusFilter;
    private JButton exportButton;
    private JButton copyButton;
    private JButton statsButton;
    private JButton clearButton;
    private JButton deleteButton;

    private List<VulnReport> allReports = new ArrayList<>();

    public ReportPanel()
    {
        initUI();
    }

    public void setApi(MontoyaApi api)
    {
        this.api = api;
    }

    /** 设置数据变更回调，用于通知 AuditLogger 同步删除/状态变更。 */
    public void setOnReportsChanged(Runnable callback)
    {
        this.onReportsChanged = callback;
    }

    public List<VulnReport> getCurrentReports()
    {
        return new ArrayList<>(allReports);
    }

    private void initUI()
    {
        setLayout(new BorderLayout(4, 4));
        setBorder(BorderFactory.createEmptyBorder(3, 3, 3, 3));

        // ===== 顶部工具栏 =====
        JPanel topPanel = new JPanel(new BorderLayout(6, 0));
        topPanel.setOpaque(false);

        countLabel = UIStyle.mutedLabel(String.format(REPORT_COUNT_FORMAT, 0));
        topPanel.add(countLabel, BorderLayout.WEST);

        JPanel filterPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        filterPanel.setOpaque(false);

        filterPanel.add(UIStyle.mutedLabel("严重性:"));
        severityFilter = new JComboBox<>(REPORT_SEVERITY_OPTIONS);
        severityFilter.setFont(severityFilter.getFont().deriveFont(Font.PLAIN, 12f));
        severityFilter.addActionListener(e -> applyCombinedFilter());
        filterPanel.add(severityFilter);

        filterPanel.add(Box.createHorizontalStrut(4));

        filterPanel.add(UIStyle.mutedLabel("状态:"));
        statusFilter = new JComboBox<>(REPORT_STATUS_OPTIONS);
        statusFilter.setFont(statusFilter.getFont().deriveFont(Font.PLAIN, 12f));
        statusFilter.addActionListener(e -> applyCombinedFilter());
        filterPanel.add(statusFilter);

        filterPanel.add(Box.createHorizontalStrut(4));

        filterPanel.add(UIStyle.mutedLabel("搜索:"));
        searchField = new JTextField(14);
        searchField.setToolTipText(REPORT_SEARCH_PLACEHOLDER);
        searchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener()
        {
            @Override public void insertUpdate(javax.swing.event.DocumentEvent e) { applyCombinedFilter(); }
            @Override public void removeUpdate(javax.swing.event.DocumentEvent e) { applyCombinedFilter(); }
            @Override public void changedUpdate(javax.swing.event.DocumentEvent e) { applyCombinedFilter(); }
        });
        filterPanel.add(searchField);
        topPanel.add(filterPanel, BorderLayout.CENTER);

        JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        actions.setOpaque(false);

        statsButton = new JButton("统计");
        UIStyle.compactButton(statsButton);
        statsButton.addActionListener(e -> showStats());
        actions.add(statsButton);

        deleteButton = new JButton(REPORT_BTN_DELETE);
        UIStyle.compactButton(deleteButton);
        deleteButton.addActionListener(e -> deleteSelected());
        actions.add(deleteButton);

        clearButton = new JButton(REPORT_BTN_CLEAR_ALL);
        UIStyle.compactButton(clearButton);
        clearButton.addActionListener(e -> clearAll());
        actions.add(clearButton);

        copyButton = new JButton("复制详情");
        UIStyle.compactButton(copyButton);
        copyButton.addActionListener(e -> copySelectedDetail());
        actions.add(copyButton);

        exportButton = new JButton("导出报告");
        UIStyle.compactButton(exportButton);
        exportButton.addActionListener(e -> exportReport());
        actions.add(exportButton);

        // 所有按钮悬停显示手指光标
        Cursor hand = Cursor.getPredefinedCursor(Cursor.HAND_CURSOR);
        for (Component c : actions.getComponents())
        {
            if (c instanceof AbstractButton) ((AbstractButton) c).setCursor(hand);
        }

        topPanel.add(actions, BorderLayout.EAST);
        add(topPanel, BorderLayout.NORTH);

        // ===== 中间分割: 表格 + 详情 =====
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        split.setResizeWeight(0.6);

        tableModel = new VulnReportTableModel();
        vulnTable = new JTable(tableModel);
        UIStyle.table(vulnTable);
        vulnTable.setRowHeight(28);

        // 多选支持
        vulnTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);

        rowSorter = new TableRowSorter<>(tableModel);
        vulnTable.setRowSorter(rowSorter);

        TableColumnModel colModel = vulnTable.getColumnModel();
        colModel.getColumn(0).setPreferredWidth(65);   // 时间
        colModel.getColumn(1).setPreferredWidth(130);  // 漏洞类型
        colModel.getColumn(2).setPreferredWidth(280);  // URL
        colModel.getColumn(3).setPreferredWidth(60);   // 严重性
        colModel.getColumn(4).setPreferredWidth(80);   // 参数
        colModel.getColumn(5).setPreferredWidth(70);   // 验证状态
        colModel.getColumn(6).setPreferredWidth(70);   // 操作

        // 设置严重性列渲染器（带背景色）
        colModel.getColumn(3).setCellRenderer(new SeverityCellRenderer());
        // 设置验证状态列渲染器（带颜色标签）
        colModel.getColumn(5).setCellRenderer(new StatusCellRenderer());
        // 设置操作列渲染器
        colModel.getColumn(6).setCellRenderer(new ActionCellRenderer());

        // 操作列点击 → 发送到 Repeater
        MouseAdapter actionAdapter = new MouseAdapter()
        {
            @Override
            public void mouseClicked(MouseEvent e)
            {
                int col = vulnTable.columnAtPoint(e.getPoint());
                if (col == 6)
                {
                    int row = vulnTable.rowAtPoint(e.getPoint());
                    if (row >= 0)
                    {
                        int modelRow = vulnTable.convertRowIndexToModel(row);
                        VulnReport report = tableModel.getRow(modelRow);
                        if (report != null) sendToRepeater(report);
                    }
                }
            }

            @Override
            public void mouseMoved(MouseEvent e)
            {
                int col = vulnTable.columnAtPoint(e.getPoint());
                vulnTable.setCursor(col == 6
                    ? Cursor.getPredefinedCursor(Cursor.HAND_CURSOR)
                    : Cursor.getDefaultCursor());
            }
        };
        vulnTable.addMouseListener(actionAdapter);
        vulnTable.addMouseMotionListener(actionAdapter);

        vulnTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) showSelectedDetail();
        });

        // 右键菜单 - 增强版
        JPopupMenu popup = new JPopupMenu();
        JMenuItem copyItem = new JMenuItem("复制详情");
        copyItem.addActionListener(ev -> copySelectedDetail());
        popup.add(copyItem);
        JMenuItem repeaterItem = new JMenuItem("发送到 Repeater");
        repeaterItem.addActionListener(ev -> {
            VulnReport r = getSelectedReport();
            if (r != null) sendToRepeater(r);
        });
        popup.add(repeaterItem);
        popup.addSeparator();
        JMenuItem markConfirmed = new JMenuItem(REPORT_MENU_MARK_CONFIRMED);
        markConfirmed.addActionListener(ev -> markSelected(VulnReport.VerifyStatus.CONFIRMED));
        popup.add(markConfirmed);
        JMenuItem markFalsePositive = new JMenuItem(REPORT_MENU_MARK_FALSE_POSITIVE);
        markFalsePositive.addActionListener(ev -> markSelected(VulnReport.VerifyStatus.FALSE_POSITIVE));
        popup.add(markFalsePositive);
        JMenuItem markPending = new JMenuItem(REPORT_MENU_MARK_PENDING);
        markPending.addActionListener(ev -> markSelected(VulnReport.VerifyStatus.PENDING));
        popup.add(markPending);
        popup.addSeparator();
        JMenuItem deleteItem = new JMenuItem(REPORT_MENU_DELETE);
        deleteItem.addActionListener(ev -> deleteSelected());
        popup.add(deleteItem);
        vulnTable.setComponentPopupMenu(popup);

        split.setLeftComponent(UIStyle.scroll(vulnTable));

        // 使用 JEditorPane 渲染 HTML 详情
        detailPane = new JEditorPane();
        detailPane.setEditable(false);
        detailPane.setContentType("text/html");
        detailPane.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, Boolean.TRUE);
        detailPane.setFont(new Font("Microsoft YaHei", Font.PLAIN, 13));
        detailPane.setBorder(BorderFactory.createEmptyBorder(6, 10, 6, 10));
        // 拦截超链接（可扩展为点击操作）
        detailPane.addHyperlinkListener(e -> {
            if (e.getEventType() == HyperlinkEvent.EventType.ACTIVATED) {
                // 预留：点击超链接的操作
            }
        });
        split.setRightComponent(UIStyle.scroll(detailPane));

        add(split, BorderLayout.CENTER);
    }

    // ==================== 数据刷新 ====================

    /**
     * 刷新漏洞报告数据（供 by ai 主入口调用）。
     */
    public void refreshVulnReports(List<VulnReport> reports)
    {
        this.allReports = new ArrayList<>(reports);
        tableModel.setData(reports);
        countLabel.setText(String.format(REPORT_COUNT_FORMAT, reports.size()));
        detailPane.setText("");
    }

    /**
     * 旧接口兼容 — 空实现。实际数据通过 refreshVulnReports 提供。
     */
    public void refresh(List<?> entries)
    {
        // no-op: 保留方法签名以避免编译错误，实际不使用
    }

    // ==================== 过滤 ====================

    private void applyCombinedFilter()
    {
        String selectedSeverity = (String) severityFilter.getSelectedItem();
        String selectedStatus = (String) statusFilter.getSelectedItem();
        String searchText = searchField.getText().trim();

        List<RowFilter<Object, Object>> filters = new ArrayList<>();

        if (selectedSeverity != null && !selectedSeverity.equals(REPORT_SEVERITY_FILTER_ALL))
        {
            filters.add(RowFilter.regexFilter(
                "^" + java.util.regex.Pattern.quote(selectedSeverity) + "$", 3));
        }

        if (selectedStatus != null && !selectedStatus.equals(REPORT_STATUS_FILTER_ALL))
        {
            filters.add(RowFilter.regexFilter(
                "^" + java.util.regex.Pattern.quote(selectedStatus) + "$", 5));
        }

        if (!searchText.isEmpty())
        {
            filters.add(RowFilter.regexFilter(
                "(?i)" + java.util.regex.Pattern.quote(searchText)));
        }

        if (filters.isEmpty())
        {
            rowSorter.setRowFilter(null);
        }
        else
        {
            rowSorter.setRowFilter(RowFilter.andFilter(filters));
        }
    }

    // ==================== 详情展示（HTML渲染） ====================

    private void showSelectedDetail()
    {
        VulnReport report = getSelectedReport();
        if (report == null)
        {
            detailPane.setText("");
            return;
        }
        detailPane.setText(formatReportHtml(report));
        detailPane.setCaretPosition(0);
    }

    private VulnReport getSelectedReport()
    {
        int row = vulnTable.getSelectedRow();
        if (row < 0) return null;
        return tableModel.getRow(vulnTable.convertRowIndexToModel(row));
    }

    private List<VulnReport> getSelectedReports()
    {
        int[] rows = vulnTable.getSelectedRows();
        List<VulnReport> selected = new ArrayList<>();
        for (int row : rows)
        {
            VulnReport r = tableModel.getRow(vulnTable.convertRowIndexToModel(row));
            if (r != null) selected.add(r);
        }
        return selected;
    }

    /** 纯文本格式（用于复制到剪贴板） */
    private String formatReport(VulnReport r)
    {
        StringBuilder sb = new StringBuilder();
        if (r.getTimestamp() != null) sb.append("时间: ").append(r.getTimestamp()).append("\n");
        sb.append("漏洞类型: ").append(safe(r.getVulnType())).append("\n");
        sb.append("URL: ").append(safe(r.getUrl())).append("\n");
        sb.append("方法: ").append(safe(r.getMethod())).append("\n");
        sb.append("主机: ").append(safe(r.getHost())).append("\n");
        sb.append("严重性: ").append(r.getSeverity().label()).append("\n");
        sb.append("参数: ").append(safe(r.getParameter())).append("\n");
        sb.append("置信度: ").append(String.format("%.2f", r.getConfidence())).append("\n");
        sb.append("验证状态: ").append(r.getVerifyStatus().label()).append("\n");
        sb.append("分类: ").append(safe(r.getCategory())).append("\n");
        if (r.hasTimingData())
        {
            sb.append("响应时间: ");
            if (r.getTtfbMs() > 0) sb.append("TTFB=").append(r.getTtfbMs()).append("ms");
            if (r.getTtlbMs() > 0)
            {
                if (r.getTtfbMs() > 0) sb.append(", ");
                sb.append("TTLB=").append(r.getTtlbMs()).append("ms");
            }
            sb.append("\n");
        }
        if (r.getDescription() != null) sb.append("描述: ").append(r.getDescription()).append("\n");
        if (r.getEvidence() != null) sb.append("证据: ").append(r.getEvidence()).append("\n");
        if (r.getSuggestion() != null) sb.append("建议: ").append(r.getSuggestion()).append("\n");
        if (r.getVerificationDetail() != null) sb.append("验证详情: ").append(r.getVerificationDetail()).append("\n");
        if (r.getTestPayload() != null) sb.append("测试Payload: ").append(r.getTestPayload()).append("\n");
        if (r.getOriginalRequest() != null) sb.append("\n=== 原始请求 ===\n").append(r.getOriginalRequest()).append("\n");
        if (r.getReproduceRequest() != null) sb.append("\n=== 可复现请求 ===\n").append(r.getReproduceRequest()).append("\n");
        if (r.getOriginalResponse() != null) sb.append("\n=== 原始响应 ===\n").append(r.getOriginalResponse()).append("\n");
        if (r.getTestResponse() != null) sb.append("\n=== 测试响应 ===\n").append(r.getTestResponse()).append("\n");
        if (!r.getTags().isEmpty()) sb.append("标签: ").append(String.join(", ", r.getTags())).append("\n");
        return sb.toString();
    }

    /** HTML 格式（用于详情面板简洁展示） */
    private String formatReportHtml(VulnReport r)
    {
        StringBuilder sb = new StringBuilder();
        sb.append("<html><body style='font-family:Consolas,Microsoft YaHei,monospace;font-size:12px;margin:2px 0;color:#333;'>");

        // 标题行: 漏洞类型 | 严重性 | 状态
        sb.append("<b style='font-size:14px;'>").append(esc(r.getVulnType())).append("</b>");
        sb.append("&nbsp;&nbsp;<span style='color:#888;'>[").append(r.getSeverity().label())
          .append(" | ").append(r.getVerifyStatus().label()).append("]</span><br>");

        // 基本信息
        sb.append("<hr style='border:none;border-top:1px solid #ddd;margin:4px 0;'>");
        infoLine(sb, "URL", r.getUrl());
        infoLine(sb, "Method", r.getMethod());
        infoLine(sb, "Host", r.getHost());
        infoLine(sb, "Param", r.getParameter());
        infoLine(sb, "Confidence", r.getConfidence() > 0 ? String.format("%.0f%%", r.getConfidence() * 100) : null);
        if (r.getCategory() != null) infoLine(sb, "Category", r.getCategory());
        if (r.getTimestamp() != null) infoLine(sb, "Time", r.getTimestamp());

        // 描述
        textSection(sb, "Description", r.getDescription());
        textSection(sb, "Evidence", r.getEvidence());
        textSection(sb, "Fix", r.getSuggestion());
        if (r.getVerificationDetail() != null && !r.getVerificationDetail().isEmpty())
            textSection(sb, "Detail", r.getVerificationDetail());

        // 原始请求是所有来源共同的基线证据，优先展示
        codeSection(sb, "Original Request", truncateForDisplay(r.getOriginalRequest(), 3000), "#f4f4f4");
        // 可复现请求
        codeSection(sb, "Reproduce Request", r.getReproduceRequest(), "#f4f4f4");
        // 原始响应
        codeSection(sb, "Original Response", truncateForDisplay(r.getOriginalResponse(), 3000), "#f4f4f4");
        // 测试响应（仅在与原始响应不同时显示）
        if (r.getTestResponse() != null && !r.getTestResponse().equals(r.getOriginalResponse()))
            codeSection(sb, "Test Response", truncateForDisplay(r.getTestResponse(), 3000), "#f4f4f4");

        sb.append("</body></html>");
        return sb.toString();
    }

    private void infoLine(StringBuilder sb, String label, String value)
    {
        if (value == null || value.isEmpty()) return;
        sb.append("<b style='color:#888;'>").append(label).append(":</b> ").append(esc(value)).append("<br>");
    }

    private void textSection(StringBuilder sb, String title, String content)
    {
        if (content == null || content.isEmpty()) return;
        sb.append("<br><b>").append(title).append(":</b> ").append(esc(content));
    }

    private void codeSection(StringBuilder sb, String title, String content, String bg)
    {
        if (content == null || content.isEmpty()) return;
        sb.append("<br><b>").append(title).append(":</b>");
        sb.append("<pre style='background:").append(bg).append(";padding:6px 8px;border-radius:3px;")
          .append("font-size:11px;overflow-x:auto;white-space:pre-wrap;margin-top:2px;border:1px solid #ddd;'>")
          .append(esc(content)).append("</pre>");
    }

    private String truncateForDisplay(String text, int maxLen)
    {
        if (text == null) return null;
        if (text.length() <= maxLen) return text;
        return text.substring(0, maxLen) + "\n... [" + text.length() + " chars total]";
    }

    private String esc(String s)    {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }

    private String safe(String s) { return s == null ? "" : s; }

    // ==================== 状态变更 ====================

    private void markSelected(VulnReport.VerifyStatus status)
    {
        List<VulnReport> selected = getSelectedReports();
        if (selected.isEmpty()) return;
        for (VulnReport r : selected)
        {
            r.setVerifyStatus(status);
        }
        tableModel.fireTableDataChanged();
        showSelectedDetail();
        if (onReportsChanged != null) onReportsChanged.run();
    }

    // ==================== 删除报告 ====================

    private void deleteSelected()
    {
        List<VulnReport> selected = getSelectedReports();
        if (selected.isEmpty()) return;
        int confirm = JOptionPane.showConfirmDialog(this,
            String.format(REPORT_CONFIRM_DELETE, selected.size()),
            REPORT_BTN_DELETE, JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (confirm != JOptionPane.YES_OPTION) return;

        allReports.removeAll(selected);
        tableModel.setData(allReports);
        countLabel.setText(String.format(REPORT_COUNT_FORMAT, allReports.size()));
        detailPane.setText("");
        if (onReportsChanged != null) onReportsChanged.run();
    }

    private void clearAll()
    {
        if (allReports.isEmpty()) return;
        int confirm = JOptionPane.showConfirmDialog(this,
            String.format(REPORT_CONFIRM_CLEAR, allReports.size()),
            REPORT_BTN_CLEAR_ALL, JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (confirm != JOptionPane.YES_OPTION) return;

        allReports.clear();
        tableModel.setData(allReports);
        countLabel.setText(String.format(REPORT_COUNT_FORMAT, 0));
        detailPane.setText("");
        if (onReportsChanged != null) onReportsChanged.run();
    }

    // ==================== Repeater 集成 ====================

    private void sendToRepeater(VulnReport report)
    {
        if (api == null) return;
        try
        {
            // 优先使用可复现请求（含payload的完整测试请求）
            String requestStr = report.getReproduceRequest();
            if (requestStr == null || requestStr.isEmpty())
            {
                // 其次使用原始请求
                requestStr = report.getOriginalRequest();
            }
            if (requestStr == null || requestStr.isEmpty())
            {
                String method = report.getMethod() != null ? report.getMethod() : "GET";
                String url = report.getUrl() != null ? report.getUrl() : "";
                String host = report.getHost() != null ? report.getHost() : "";
                requestStr = method + " " + url + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n";
            }

            // 解析目标服务信息，绑定 HttpService 避免弹出协议/端口选择对话框
            String url = report.getUrl() != null ? report.getUrl() : "";
            boolean secure = report.isSecure();
            String host = report.getHost() != null ? report.getHost() : "";
            int port = secure ? 443 : 80;
            // 尝试从 URL 中提取 host 和 port
            try
            {
                if (!url.isEmpty())
                {
                    java.net.URI uri = new java.net.URI(url);
                    if (uri.getHost() != null && !uri.getHost().isEmpty() && host.isEmpty())
                    {
                        host = uri.getHost();
                    }
                    if (uri.getPort() > 0) port = uri.getPort();
                    // URL scheme 也可能暗示 HTTPS（如 wss:// 或其他间接线索）
                }
            }
            catch (Exception ignored) {}
            // 尝试从 Host 头中提取端口
            if (host.contains(":"))
            {
                String[] hp = host.split(":", 2);
                host = hp[0];
                try { port = Integer.parseInt(hp[1]); } catch (Exception ignored) {}
            }
            // 尝试从请求文本中提取 Host 头
            if (host.isEmpty())
            {
                for (String line : requestStr.split("\r?\n"))
                {
                    if (line.toLowerCase().startsWith("host:"))
                    {
                        host = line.substring(5).trim();
                        break;
                    }
                    if (line.isEmpty()) break;
                }
                if (host.contains(":"))
                {
                    String[] hp = host.split(":", 2);
                    host = hp[0];
                    try { port = Integer.parseInt(hp[1]); } catch (Exception ignored) {}
                }
            }
            // 端口推断 HTTPS：如果 host 含 :443 或 port 已经被设为 443，升级为 HTTPS
            if (!secure && port == 443) secure = true;
            if (!host.isEmpty())
            {
                burp.api.montoya.http.HttpService service =
                    burp.api.montoya.http.HttpService.httpService(host, port, secure);
                HttpRequest httpRequest = HttpRequest.httpRequest(service, requestStr);
                api.repeater().sendToRepeater(httpRequest,
                    report.getVulnType() != null ? report.getVulnType() : "VulnReport");
            }
            else
            {
                // 降级：无法确定目标服务
                HttpRequest httpRequest = HttpRequest.httpRequest(requestStr);
                api.repeater().sendToRepeater(httpRequest,
                    report.getVulnType() != null ? report.getVulnType() : "VulnReport");
            }
        }
        catch (Exception ignored) {}
    }

    // ==================== 统计 ====================

    private void showStats()
    {
        if (allReports.isEmpty())
        {
            JOptionPane.showMessageDialog(this, "暂无漏洞数据可统计。", "统计", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        Map<VulnReport.Severity, Integer> sevCount = new LinkedHashMap<>();
        Map<String, Integer> typeCount = new LinkedHashMap<>();
        int confirmed = 0, pending = 0, unverified = 0, falsePositive = 0;

        for (VulnReport r : allReports)
        {
            sevCount.merge(r.getSeverity(), 1, Integer::sum);
            typeCount.merge(r.getVulnType(), 1, Integer::sum);
            switch (r.getVerifyStatus())
            {
                case CONFIRMED: confirmed++; break;
                case PENDING: pending++; break;
                case UNVERIFIED: unverified++; break;
                case FALSE_POSITIVE: falsePositive++; break;
            }
        }

        // 计算整体风险评分
        int riskScore = 0;
        for (VulnReport r : allReports)
        {
            riskScore += r.getSeverity().level() * (r.getVerifyStatus() == VulnReport.VerifyStatus.CONFIRMED ? 2 : 1);
        }
        String riskLevel;
        if (riskScore >= 30) { riskLevel = "极高风险"; }
        else if (riskScore >= 15) { riskLevel = "高风险"; }
        else if (riskScore >= 8) { riskLevel = "中风险"; }
        else if (riskScore >= 3) { riskLevel = "低风险"; }
        else { riskLevel = "信息级"; }

        // 构建 HTML 统计报告
        StringBuilder sb = new StringBuilder();
        sb.append("<html><body style='font-family:Consolas,Microsoft YaHei,monospace;font-size:12px;margin:2px 0;color:#333;'>");

        // 风险评分
        sb.append("<b>风险评分:</b> ").append(riskScore).append(" (").append(riskLevel).append(")<br>");
        sb.append("<hr style='border:none;border-top:1px solid #ddd;margin:4px 0;'>");

        // 概览
        sb.append("<b>总漏洞数:</b> ").append(allReports.size()).append("<br>");
        sb.append("<b>已确认:</b> ").append(confirmed).append("<br>");
        sb.append("<b>待验证:</b> ").append(pending).append("<br>");
        sb.append("<b>无法验证:</b> ").append(unverified).append("<br>");
        sb.append("<b>误报:</b> ").append(falsePositive).append("<br>");

        sb.append("<hr style='border:none;border-top:1px solid #ddd;margin:4px 0;'>");

        // 严重性分布
        sb.append("<b>严重性分布:</b><br>");
        for (Map.Entry<VulnReport.Severity, Integer> e : sevCount.entrySet())
        {
            sb.append("&nbsp;&nbsp;").append(e.getKey().label()).append(": ").append(e.getValue()).append("<br>");
        }

        // 漏洞类型分布
        sb.append("<br><b>漏洞类型分布:</b><br>");
        typeCount.entrySet().stream()
            .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
            .forEach(e -> sb.append("&nbsp;&nbsp;").append(e.getKey()).append(": ").append(e.getValue()).append("<br>"));

        sb.append("</body></html>");
        detailPane.setText(sb.toString());
        detailPane.setCaretPosition(0);
    }

    // ==================== 复制 ====================

    private void copySelectedDetail()
    {
        VulnReport report = getSelectedReport();
        if (report == null) return;
        java.awt.Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
            new java.awt.datatransfer.StringSelection(formatReport(report)), null);
    }

    // ==================== 导出 ====================

    private void exportReport()
    {
        // 收集当前筛选条件下可见的报告
        List<VulnReport> visibleReports = new ArrayList<>();
        for (int viewRow = 0; viewRow < vulnTable.getRowCount(); viewRow++)
        {
            int modelRow = vulnTable.convertRowIndexToModel(viewRow);
            VulnReport r = tableModel.getRow(modelRow);
            if (r != null) visibleReports.add(r);
        }

        if (visibleReports.isEmpty())
        {
            JOptionPane.showMessageDialog(this, "暂无漏洞数据可导出。", "导出", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        // 格式选择：HTML 企业报告 / Markdown 报告
        String[] options = {"HTML 报告", "Markdown 报告"};
        int choice = JOptionPane.showOptionDialog(this,
            "导出当前筛选的 " + visibleReports.size() + " 条漏洞报告\n选择导出格式:",
            "导出漏洞报告",
            JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE,
            null, options, options[0]);

        if (choice < 0) return; // 用户取消

        boolean isMarkdown = (choice == 1);
        String defaultName = isMarkdown ? "AI漏洞报告.md" : "AI漏洞报告.html";

        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File(defaultName));
        chooser.setDialogTitle("导出漏洞报告");
        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION)
        {
            try
            {
                String content = isMarkdown
                    ? ReportGenerator.generateVulnReportMarkdown("所有目标", visibleReports)
                    : ReportGenerator.generateVulnReportHtmlEnterprise("所有目标", visibleReports);
                ReportGenerator.exportToFile(chooser.getSelectedFile().getAbsolutePath(), content);
                JOptionPane.showMessageDialog(this,
                    "报告已导出: " + chooser.getSelectedFile().getAbsolutePath(),
                    "导出成功", JOptionPane.INFORMATION_MESSAGE);
            }
            catch (Exception e)
            {
                JOptionPane.showMessageDialog(this,
                    "导出失败: " + e.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    // ==================== 严重性颜色渲染（带背景色） ====================

    private static class SeverityCellRenderer extends DefaultTableCellRenderer
    {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
            boolean isSelected, boolean hasFocus, int row, int column)
        {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            setHorizontalAlignment(SwingConstants.CENTER);
            if (!isSelected && value instanceof String)
            {
                String text = (String) value;
                Color fg, bg;
                if (text.contains("严重")) { fg = Color.WHITE; bg = new Color(0xb7, 0x1c, 0x1c); }
                else if (text.contains("高")) { fg = Color.WHITE; bg = new Color(0xd3, 0x2f, 0x2f); }
                else if (text.contains("中")) { fg = Color.WHITE; bg = new Color(0xe6, 0x51, 0x00); }
                else if (text.contains("低")) { fg = Color.WHITE; bg = new Color(0x19, 0x76, 0xd2); }
                else { fg = new Color(0x61, 0x61, 0x61); bg = new Color(0xee, 0xee, 0xee); }
                c.setForeground(fg);
                c.setBackground(bg);
            }
            else if (isSelected)
            {
                c.setForeground(Color.WHITE);
                c.setBackground(table.getSelectionBackground());
            }
            return c;
        }
    }

    // ==================== 验证状态渲染器 ====================

    private static class StatusCellRenderer extends DefaultTableCellRenderer
    {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
            boolean isSelected, boolean hasFocus, int row, int column)
        {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            setHorizontalAlignment(SwingConstants.CENTER);
            if (!isSelected && value instanceof String)
            {
                String text = (String) value;
                if (text.contains("已确认")) { c.setForeground(new Color(0x2e, 0x7d, 0x32)); }
                else if (text.contains("误报")) { c.setForeground(new Color(0x99, 0x99, 0x99)); }
                else if (text.contains("无法")) { c.setForeground(new Color(0xf5, 0x7c, 0x00)); }
                else { c.setForeground(new Color(0xe6, 0x51, 0x00)); } // 待验证
            }
            else if (isSelected)
            {
                c.setForeground(Color.WHITE);
            }
            return c;
        }
    }

    // ==================== 操作列渲染器 ====================

    private static class ActionCellRenderer extends DefaultTableCellRenderer
    {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
            boolean isSelected, boolean hasFocus, int row, int column)
        {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            setHorizontalAlignment(SwingConstants.CENTER);
            if (!isSelected)
            {
                setForeground(new Color(0x15, 0x65, 0xc0));
            }
            else
            {
                setForeground(Color.WHITE);
            }
            return c;
        }
    }

    // ==================== 表格模型 ====================

    private static class VulnReportTableModel extends AbstractTableModel
    {
        private final String[] cols = {
            REPORT_COL_TIME, REPORT_COL_VULN_TYPE, COL_URL,
            REPORT_COL_SEVERITY, REPORT_COL_PARAMETER,
            REPORT_COL_STATUS, REPORT_COL_ACTION
        };
        private List<VulnReport> data = new ArrayList<>();

        public void setData(List<VulnReport> reports)
        {
            data = reports;
            fireTableDataChanged();
        }

        public VulnReport getRow(int row)
        {
            return row >= 0 && row < data.size() ? data.get(row) : null;
        }

        public List<VulnReport> getData() { return data; }

        @Override public int getRowCount() { return data.size(); }
        @Override public int getColumnCount() { return cols.length; }
        @Override public String getColumnName(int col) { return cols[col]; }

        @Override
        public Object getValueAt(int row, int col)
        {
            VulnReport r = data.get(row);
            switch (col)
            {
                case 0: return r.getTimestamp() != null ? r.getTimestamp() : "";
                case 1: return r.getVulnType();
                case 2: return TextUtils.truncate(r.getUrl(), 50);
                case 3: return r.getSeverity().label();
                case 4: return r.getParameter() != null ? r.getParameter() : "";
                case 5: return r.getVerifyStatus().label();
                case 6: return BTN_TO_REPEATER;
                default: return "";
            }
        }
    }
}
