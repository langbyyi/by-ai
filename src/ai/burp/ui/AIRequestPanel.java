package ai.burp.ui;

import java.awt.*;
import java.awt.event.*;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import java.net.URI;

import static ai.burp.ui.ChineseUI.*;

/**
 * AI 请求标签页 — 展示 AI 发送的所有 HTTP 请求/响应历史。
 * 使用 Burp 原生 HttpRequestEditor / HttpResponseEditor 展示，
 * 支持语法高亮、Hex视图、自动格式化。
 */
public class AIRequestPanel extends JPanel
{
    private final MontoyaApi api;
    private final List<RequestEntry> entries = new ArrayList<>();
    private final RequestTableModel tableModel;
    private final Set<String> dedupeKeys = new HashSet<>();
    private JTable requestTable;
    private HttpRequestEditor requestEditor;
    private HttpResponseEditor responseEditor;
    private JLabel countLabel;

    /**
     * Thread-safe time formatting. SimpleDateFormat is not thread-safe,
     * but all callers (getValueAt, formatEntry) run on the EDT, so a
     * local instance per call is used for correctness.
     */
    private static String formatTime(Date date)
    {
        return new SimpleDateFormat("HH:mm:ss").format(date);
    }

    private static String formatDuration(long ms)
    {
        if (ms < 1000) return ms + "ms";
        return String.format("%.1fs", ms / 1000.0);
    }

    public AIRequestPanel(MontoyaApi api)
    {
        this.api = api;
        tableModel = new RequestTableModel(entries);
        initUI();
    }

    private void initUI()
    {
        setLayout(new BorderLayout(4, 4));
        setBorder(new EmptyBorder(3, 3, 3, 3));

        // ===== 顶部工具栏 =====
        JPanel toolbar = UIStyle.toolbar();

        JButton clearButton = new JButton(BTN_CLEAR);
        UIStyle.compactButton(clearButton);
        clearButton.setToolTipText("清空所有请求记录");
        clearButton.addActionListener(e -> clearAll());
        toolbar.add(clearButton);

        JButton copyReqButton = new JButton("复制请求");
        UIStyle.compactButton(copyReqButton);
        copyReqButton.addActionListener(e -> copySelectedRequestText());
        toolbar.add(copyReqButton);

        JButton copyRespButton = new JButton("复制响应");
        UIStyle.compactButton(copyRespButton);
        copyRespButton.addActionListener(e -> copySelectedResponseText());
        toolbar.add(copyRespButton);

        JButton toRepeaterBtn = new JButton(BTN_TO_REPEATER);
        UIStyle.compactButton(toRepeaterBtn);
        toRepeaterBtn.setToolTipText("发送到 Repeater 进行手动重放");
        toRepeaterBtn.addActionListener(e -> sendSelectedToRepeater());
        toolbar.add(toRepeaterBtn);

        toolbar.add(Box.createHorizontalStrut(10));
        countLabel = UIStyle.mutedLabel("共 0 条请求");
        toolbar.add(countLabel);

        add(toolbar, BorderLayout.NORTH);

        // ===== 中间：请求历史表格 =====
        requestTable = new JTable(tableModel);
        UIStyle.table(requestTable);
        requestTable.setFont(requestTable.getFont().deriveFont(Font.PLAIN, 12f));
        requestTable.getColumnModel().getColumn(0).setPreferredWidth(40);    // #
        requestTable.getColumnModel().getColumn(1).setPreferredWidth(70);    // 方法
        requestTable.getColumnModel().getColumn(2).setPreferredWidth(200);   // Host
        requestTable.getColumnModel().getColumn(3).setPreferredWidth(60);    // 端口
        requestTable.getColumnModel().getColumn(4).setPreferredWidth(55);    // 协议
        requestTable.getColumnModel().getColumn(5).setPreferredWidth(280);   // 路径
        requestTable.getColumnModel().getColumn(6).setPreferredWidth(65);    // 状态
        requestTable.getColumnModel().getColumn(7).setPreferredWidth(80);    // 请求大小
        requestTable.getColumnModel().getColumn(8).setPreferredWidth(80);    // 响应大小
        requestTable.getColumnModel().getColumn(9).setPreferredWidth(90);    // MIME
        requestTable.getColumnModel().getColumn(10).setPreferredWidth(75);   // 耗时
        requestTable.getColumnModel().getColumn(11).setPreferredWidth(75);   // 时间
        installRenderers();

        requestTable.getSelectionModel().setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        requestTable.getSelectionModel().addListSelectionListener(new ListSelectionListener()
        {
            @Override
            public void valueChanged(ListSelectionEvent e)
            {
                if (!e.getValueIsAdjusting()) showSelectedDetail();
            }
        });

        // 右键菜单
        JPopupMenu popup = new JPopupMenu();
        JMenuItem copyItem = new JMenuItem("复制详情");
        copyItem.addActionListener(e -> {
            RequestEntry entry = getSelectedEntry();
            if (entry != null) copyToClipboard(formatEntry(entry));
        });
        popup.add(copyItem);

        JMenuItem repeaterItem = new JMenuItem("发送到 Repeater");
        repeaterItem.addActionListener(e -> sendSelectedToRepeater());
        popup.add(repeaterItem);

        requestTable.setComponentPopupMenu(popup);

        JScrollPane tableScroll = UIStyle.scroll(requestTable);

        // ===== 下方：Request / Response 原生编辑器左右分栏 =====
        requestEditor = api.userInterface().createHttpRequestEditor();
        responseEditor = api.userInterface().createHttpResponseEditor();

        JSplitPane detailSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
            requestEditor.uiComponent(), responseEditor.uiComponent());
        detailSplit.setResizeWeight(0.5);
        detailSplit.setDividerSize(4);

        // ===== 整体上下分栏 =====
        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, detailSplit);
        mainSplit.setResizeWeight(0.45);
        mainSplit.setDividerSize(4);

        add(mainSplit, BorderLayout.CENTER);
    }

    // ==================== 数据操作 ====================

    /**
     * 添加一条请求/响应记录。
     */
    public synchronized void addEntry(String requestText, String responseText,
        String host, String method, int statusCode, long durationMs)
    {
        HostPort target = normalizeTarget(host, requestText);
        String key = buildDedupeKey(requestText, responseText, host, method, statusCode);
        if (dedupeKeys.contains(key))
        {
            return;
        }
        dedupeKeys.add(key);

        RequestEntry entry = new RequestEntry(
            entries.size() + 1,
            method != null ? method : extractMethod(requestText),
            statusCode,
            target.host,
            target.port,
            extractScheme(target.port, requestText),
            extractUrlPath(requestText),
            byteLength(requestText),
            byteLength(responseText),
            extractMime(responseText),
            new Date(),
            durationMs,
            requestText,
            responseText != null ? responseText : ""
        );
        entries.add(entry);
        int newRow = entries.size() - 1;
        tableModel.fireTableRowsInserted(newRow, newRow);
        countLabel.setText("共 " + entries.size() + " 条请求");

        // 自动选中并滚动到新增行
        SwingUtilities.invokeLater(() -> {
            int viewRow = requestTable.convertRowIndexToView(newRow);
            requestTable.setRowSelectionInterval(viewRow, viewRow);
            requestTable.scrollRectToVisible(requestTable.getCellRect(viewRow, 0, true));
        });
    }

    /**
     * 清空所有记录。
     */
    public synchronized void clearAll()
    {
        entries.clear();
        dedupeKeys.clear();
        tableModel.fireTableDataChanged();
        // 清空编辑器内容
        try
        {
            requestEditor.setRequest(HttpRequest.httpRequest(""));
            responseEditor.setResponse(HttpResponse.httpResponse(""));
        }
        catch (Exception ignored) {}
        countLabel.setText("共 0 条请求");
    }

    // ==================== 内部方法 ====================

    private void showSelectedDetail()
    {
        RequestEntry entry = getSelectedEntry();
        if (entry == null) return;

        try
        {
            requestEditor.setRequest(HttpRequest.httpRequest(entry.requestText));
        }
        catch (Exception e)
        {
            // 解析失败时用空请求
            try { requestEditor.setRequest(HttpRequest.httpRequest("")); } catch (Exception ignored) {}
        }

        if (entry.responseText != null && !entry.responseText.isEmpty())
        {
            try
            {
                responseEditor.setResponse(HttpResponse.httpResponse(entry.responseText));
            }
            catch (Exception e)
            {
                try { responseEditor.setResponse(HttpResponse.httpResponse("")); } catch (Exception ignored) {}
            }
        }
        else
        {
            try { responseEditor.setResponse(HttpResponse.httpResponse("")); } catch (Exception ignored) {}
        }
    }

    /**
     * 将当前选中的请求发送到 Repeater。
     */
    private void sendSelectedToRepeater()
    {
        RequestEntry entry = getSelectedEntry();
        if (entry == null || api == null) return;

        try
        {
            boolean secure = "https".equalsIgnoreCase(entry.scheme);
            burp.api.montoya.http.HttpService service =
                burp.api.montoya.http.HttpService.httpService(entry.host, entry.port, secure);
            HttpRequest request = HttpRequest.httpRequest(service, entry.requestText);
            api.repeater().sendToRepeater(request,
                "AI #" + entry.id + " " + entry.method + " " + entry.path);
        }
        catch (Exception e)
        {
            // 降级：尝试从请求文本中提取 Host 头构造 HttpService
            try
            {
                String hostFromReq = extractHostHeader(entry.requestText);
                if (hostFromReq != null && !hostFromReq.isEmpty())
                {
                    String h = hostFromReq;
                    int p = entry.port;
                    if (h.contains(":"))
                    {
                        String[] hp = h.split(":", 2);
                        h = hp[0];
                        try { p = Integer.parseInt(hp[1]); } catch (Exception ignored2) {}
                    }
                    boolean sec = "https".equalsIgnoreCase(entry.scheme) || p == 443 || p == 8443;
                    burp.api.montoya.http.HttpService svc =
                        burp.api.montoya.http.HttpService.httpService(h, p, sec);
                    HttpRequest request = HttpRequest.httpRequest(svc, entry.requestText);
                    api.repeater().sendToRepeater(request,
                        "AI #" + entry.id + " " + entry.method + " " + entry.path);
                }
                else
                {
                    HttpRequest request = HttpRequest.httpRequest(entry.requestText);
                    api.repeater().sendToRepeater(request,
                        "AI #" + entry.id + " " + entry.method + " " + entry.path);
                }
            }
            catch (Exception ignored) {}
        }
    }

    private RequestEntry getSelectedEntry()
    {
        int viewRow = requestTable.getSelectedRow();
        if (viewRow < 0) return null;
        int modelRow = requestTable.convertRowIndexToModel(viewRow);
        if (modelRow < 0 || modelRow >= entries.size()) return null;
        return entries.get(modelRow);
    }

    private static String extractUrlPath(String requestText)
    {
        if (requestText == null) return "/";
        String firstLine = requestText.split("\r?\n", 2)[0];
        String[] parts = firstLine.split("\\s+");
        return parts.length >= 2 ? parts[1] : "/";
    }

    private static String extractMethod(String requestText)
    {
        if (requestText == null) return "GET";
        String firstLine = requestText.split("\r?\n", 2)[0];
        String[] parts = firstLine.split("\\s+");
        return parts.length >= 1 ? parts[0] : "GET";
    }

    private void copyToClipboard(String text)
    {
        if (text == null || text.trim().isEmpty()) return;
        java.awt.datatransfer.StringSelection sel = new java.awt.datatransfer.StringSelection(text);
        java.awt.Toolkit.getDefaultToolkit().getSystemClipboard().setContents(sel, null);
    }

    private void copySelectedRequestText()
    {
        RequestEntry entry = getSelectedEntry();
        if (entry != null)
        {
            copyToClipboard(entry.requestText);
            return;
        }
        try
        {
            if (requestEditor.getRequest() != null)
            {
                copyToClipboard(requestEditor.getRequest().toString());
            }
        }
        catch (Exception ignored) {}
    }

    private void copySelectedResponseText()
    {
        RequestEntry entry = getSelectedEntry();
        if (entry != null)
        {
            copyToClipboard(entry.responseText);
            return;
        }
        try
        {
            if (responseEditor.getResponse() != null)
            {
                copyToClipboard(responseEditor.getResponse().toString());
            }
        }
        catch (Exception ignored) {}
    }

    private String formatEntry(RequestEntry entry)
    {
        if (entry == null) return "";
        StringBuilder sb = new StringBuilder();
        sb.append("=== Request #").append(entry.id).append(" ===\n");
        sb.append("Time: ").append(formatTime(entry.timestamp)).append("\n");
        sb.append("Duration: ").append(formatDuration(entry.durationMs)).append("\n");
        sb.append("Method: ").append(entry.method).append("\n");
        sb.append("Status: ").append(entry.statusCode).append("\n");
        sb.append("Target: ").append(entry.host).append(":").append(entry.port)
            .append(" (").append(entry.scheme).append(")").append("\n\n");
        sb.append("--- Request ---\n").append(entry.requestText).append("\n\n");
        sb.append("--- Response ---\n").append(entry.responseText);
        return sb.toString();
    }

    private String buildDedupeKey(String requestText, String responseText,
        String host, String method, int statusCode)
    {
        String req = requestText == null ? "" : requestText.trim();
        String resp = responseText == null ? "" : responseText.trim();
        String h = host == null ? "" : host.trim();
        String m = method == null ? "" : method.trim();
        return m + "|" + h + "|" + statusCode + "|" + req + "|" + resp;
    }

    private static int extractPort(String host)
    {
        if (host == null || host.isEmpty()) return 80;
        int colon = host.lastIndexOf(':');
        if (colon > 0 && host.indexOf(':') == colon)
        {
            try { return Integer.parseInt(host.substring(colon + 1)); } catch (Exception ignored) {}
        }
        return 80;
    }

    private static String extractScheme(int port, String requestText)
    {
        String firstLine = requestText == null ? "" : requestText.split("\r?\n", 2)[0].toLowerCase();
        if (firstLine.contains(" https://")) return "https";
        if (firstLine.contains(" http://")) return "http";
        return (port == 443 || port == 8443) ? "https" : "http";
    }

    private HostPort normalizeTarget(String host, String requestText)
    {
        String fromRequest = extractHostHeader(requestText);
        String candidate = (fromRequest != null && !fromRequest.isEmpty()) ? fromRequest : host;
        if (candidate == null || candidate.trim().isEmpty())
        {
            return new HostPort("unknown", 80);
        }
        String raw = candidate.trim();

        // 输入可能是完整URL（来自 scanner/audit）
        if (raw.startsWith("http://") || raw.startsWith("https://"))
        {
            try
            {
                URI uri = URI.create(raw);
                String h = uri.getHost();
                int p = uri.getPort();
                if (h != null && !h.isEmpty())
                {
                    if (p <= 0) p = "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
                    return new HostPort(h, p);
                }
            }
            catch (Exception ignored) {}
        }

        int p = extractPort(raw);
        String h = raw;
        int colon = raw.lastIndexOf(':');
        if (colon > 0 && raw.indexOf(':') == colon)
        {
            h = raw.substring(0, colon);
        }
        return new HostPort(h, p);
    }

    private String extractHostHeader(String requestText)
    {
        if (requestText == null || requestText.isEmpty()) return "";
        String[] lines = requestText.split("\r?\n");
        for (String line : lines)
        {
            if (line.toLowerCase().startsWith("host:"))
            {
                return line.substring(5).trim();
            }
            if (line.isEmpty()) break;
        }
        return "";
    }

    private static int byteLength(String text)
    {
        if (text == null || text.isEmpty()) return 0;
        return text.getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
    }

    private static String extractMime(String responseText)
    {
        if (responseText == null || responseText.isEmpty()) return "-";
        String[] lines = responseText.split("\r?\n");
        for (String line : lines)
        {
            if (line.toLowerCase().startsWith("content-type:"))
            {
                String v = line.substring(line.indexOf(':') + 1).trim();
                int semi = v.indexOf(';');
                return semi > 0 ? v.substring(0, semi).trim() : v;
            }
            if (line.isEmpty()) break;
        }
        return "-";
    }

    private void installRenderers()
    {
        DefaultTableCellRenderer methodRenderer = new DefaultTableCellRenderer()
        {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value,
                boolean isSelected, boolean hasFocus, int row, int column)
            {
                Component c = super.getTableCellRendererComponent(
                    table, value, isSelected, hasFocus, row, column);
                if (!isSelected)
                {
                    String m = value == null ? "" : value.toString();
                    if ("GET".equals(m)) c.setForeground(new Color(25, 118, 210));
                    else if ("POST".equals(m)) c.setForeground(new Color(46, 125, 50));
                    else if ("DELETE".equals(m) || "PUT".equals(m) || "PATCH".equals(m))
                        c.setForeground(new Color(198, 40, 40));
                    else c.setForeground(new Color(66, 66, 66));
                }
                return c;
            }
        };
        requestTable.getColumnModel().getColumn(1).setCellRenderer(methodRenderer);

        DefaultTableCellRenderer statusRenderer = new DefaultTableCellRenderer()
        {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value,
                boolean isSelected, boolean hasFocus, int row, int column)
            {
                Component c = super.getTableCellRendererComponent(
                    table, value, isSelected, hasFocus, row, column);
                if (!isSelected)
                {
                    int code = 0;
                    try { code = Integer.parseInt(String.valueOf(value)); } catch (Exception ignored) {}
                    if (code >= 500) c.setForeground(new Color(183, 28, 28));
                    else if (code >= 400) c.setForeground(new Color(239, 108, 0));
                    else if (code >= 300) c.setForeground(new Color(123, 31, 162));
                    else if (code >= 200) c.setForeground(new Color(46, 125, 50));
                    else c.setForeground(new Color(66, 66, 66));
                }
                return c;
            }
        };
        requestTable.getColumnModel().getColumn(6).setCellRenderer(statusRenderer);
    }

    // ==================== 数据条目 ====================

    private static class RequestEntry
    {
        final int id;
        final String method;
        final int statusCode;
        final String host;
        final int port;
        final String scheme;
        final String path;
        final int requestBytes;
        final int responseBytes;
        final String mimeType;
        final Date timestamp;
        final long durationMs;
        final String requestText;
        final String responseText;

        RequestEntry(int id, String method, int statusCode, String host, int port, String scheme,
            String path, int requestBytes, int responseBytes, String mimeType,
            Date timestamp, long durationMs, String requestText, String responseText)
        {
            this.id = id;
            this.method = method;
            this.statusCode = statusCode;
            this.host = host;
            this.port = port;
            this.scheme = scheme;
            this.path = path;
            this.requestBytes = requestBytes;
            this.responseBytes = responseBytes;
            this.mimeType = mimeType;
            this.timestamp = timestamp;
            this.durationMs = durationMs;
            this.requestText = requestText;
            this.responseText = responseText;
        }
    }

    private static class HostPort
    {
        final String host;
        final int port;

        HostPort(String host, int port)
        {
            this.host = host;
            this.port = port;
        }
    }

    // ==================== 表格模型 ====================

    private static class RequestTableModel extends AbstractTableModel
    {
        private static final String[] COLUMNS = {
            "#", "方法", "Host", "端口", "协议", "路径", "状态",
            "请求字节", "响应字节", "MIME", "耗时", "时间"
        };
        private final List<RequestEntry> data;

        RequestTableModel(List<RequestEntry> data)
        {
            this.data = data;
        }

        @Override
        public int getRowCount()
        {
            return data.size();
        }

        @Override
        public int getColumnCount()
        {
            return COLUMNS.length;
        }

        @Override
        public String getColumnName(int col)
        {
            return COLUMNS[col];
        }

        @Override
        public Object getValueAt(int row, int col)
        {
            if (row < 0 || row >= data.size()) return "";
            RequestEntry e = data.get(row);
            switch (col)
            {
                case 0: return e.id;
                case 1: return e.method;
                case 2: return e.host;
                case 3: return e.port;
                case 4: return e.scheme;
                case 5: return e.path;
                case 6: return e.statusCode;
                case 7: return e.requestBytes;
                case 8: return e.responseBytes;
                case 9: return e.mimeType;
                case 10: return formatDuration(e.durationMs);
                case 11: return formatTime(e.timestamp);
                default: return "";
            }
        }
    }
}
