package ai.burp.ui;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.HyperlinkEvent;
import java.awt.*;
import java.awt.event.*;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.List;

import ai.burp.config.ExtensionConfig;
import ai.burp.model.ChatMessage;
import ai.burp.provider.OpenAIStreamingProvider;
import ai.burp.provider.StreamingAIProvider;
import ai.burp.util.AiResponseParser;
import ai.burp.util.MarkdownRenderer;
import ai.burp.util.TextUtils;
import ai.burp.util.VulnFindingPolicy;
import static ai.burp.ui.ChineseUI.*;

/**
 * AI Chat panel - main UI for interacting with the AI.
 */
public class AIChatPanel extends JPanel
{
    private enum BurpTarget
    {
        REPEATER,
        INTRUDER
    }

    private static class ParsedHttpRequest
    {
        final String requestText;
        final String host;
        final int port;
        final boolean secure;

        ParsedHttpRequest(String requestText, String host, int port, boolean secure)
        {
            this.requestText = requestText;
            this.host = host;
            this.port = port;
            this.secure = secure;
        }
    }

    private final StreamingAIProvider provider;
    private final ExtensionConfig config;
    private final burp.api.montoya.MontoyaApi api;
    private final List<ChatPanelListener> listeners = new ArrayList<>();
    private static final long REFRESH_INTERVAL_MS = 80; // 最少80ms刷新一次
    private static final int MAX_MESSAGE_LOG_CHARS = 500_000; // ~500KB limit
    private static final String[] SPINNER_FRAMES = {"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"};
    private static final int SPINNER_INTERVAL_MS = 150;

    private JTextPane chatDisplay;
    private JTextArea inputArea;
    private JButton sendButton;
    private JButton stopButton;
    private JButton clearButton;
    private JButton settingsButton;
    private JLabel statusLabel;
    private JScrollPane chatScrollPane;

    // 最近一次发送的请求/响应（用于弹窗查看）

    private static final int MAX_RETRIES = 3;
    private HttpRequestCallback httpRequestCallback;
    private TabSwitchCallback tabSwitchCallback;
    private Runnable openSettingsCallback;
    private ai.burp.scanner.AuditLogger auditLogger;
    private Runnable vulnReportCallback;

    // 后台并行处理：每个 session 独立的 SwingWorker
    private final Map<String, SwingWorker<String, Void>> backgroundWorkers = Collections.synchronizedMap(new LinkedHashMap<>());

    // 发送并分析 - 安全限制
    private static final int MAX_REQUESTS_PER_SESSION = 50;
    private final List<ChatSession> sessions = new ArrayList<>();
    private int currentSessionIndex = -1;
    private JComboBox<ChatSession> sessionComboBox;
    private int sessionCounter = 0;
    private boolean sessionSwitching = false;
    private volatile SessionRuntime activeRuntime = null;

    /**
     * 每个会话的运行时状态。
     * 持有独立的 provider、流式缓冲区、队列等，
     * 使多个会话可以并行执行 AI 请求。
     */
    private class SessionRuntime
    {
        final String sessionId;
        final List<ChatMessage> conversationHistory = new ArrayList<>();
        final StringBuilder messageLog = new StringBuilder();
        final Map<String, String> codeBlockCopies = new LinkedHashMap<>();
        final StringBuilder streamingBuffer = new StringBuilder();
        final java.util.LinkedList<String> promptQueue = new java.util.LinkedList<>();
        final Set<String> reportedVulnKeys = new java.util.LinkedHashSet<>();
        final Set<Integer> pausedHttpTasks = Collections.synchronizedSet(new HashSet<>());

        volatile boolean isProcessing = false;
        volatile boolean isSendingHttp = false;
        volatile long aiGeneration = 0;
        int aiRetryCount = 0;
        long lastRefreshTime = 0;
        volatile int activeHttpTaskId = 0;
        int requestCountInSession = 0;
        volatile String lastRequestText;
        volatile String lastResponseText;
        volatile String lastRequestHost;
        volatile boolean lastRequestSecure;

        final StreamingAIProvider provider;
        volatile SwingWorker<?, ?> activeWorker = null;
        javax.swing.Timer spinnerTimer;
        int spinnerFrame = 0;

        SessionRuntime(String sessionId)
        {
            this.sessionId = sessionId;
            this.provider = new OpenAIStreamingProvider(config, api);
        }

        boolean isActive()
        {
            return this == activeRuntime;
        }
    }

    /**
     * 会话快照 — 保存/恢复对话状态。
     */
    private static class ChatSession
    {
        final String id;
        String title;
        final List<ChatMessage> history;
        final String messageLogHtml;
        final Map<String, String> codeBlocks;
        final int requestCount;
        final String lastReqText;
        final String lastRespText;
        final String lastReqHost;
        final boolean lastReqSecure;
        final Date createdAt;
        SessionRuntime runtime;

        ChatSession(String id, String title, List<ChatMessage> history,
            String messageLogHtml, Map<String, String> codeBlocks,
            int requestCount, String lastReqText, String lastRespText, String lastReqHost,
            boolean lastReqSecure)
        {
            this.id = id;
            this.title = title;
            this.history = new ArrayList<>(history);
            this.messageLogHtml = messageLogHtml;
            this.codeBlocks = new LinkedHashMap<>(codeBlocks);
            this.requestCount = requestCount;
            this.lastReqText = lastReqText;
            this.lastRespText = lastRespText;
            this.lastReqHost = lastReqHost;
            this.lastReqSecure = lastReqSecure;
            this.createdAt = new Date();
        }

        @Override
        public String toString()
        {
            return title;
        }
    }

    public AIChatPanel(StreamingAIProvider provider, ExtensionConfig config, burp.api.montoya.MontoyaApi api,
        ai.burp.scanner.AuditLogger auditLogger)
    {
        this.provider = provider;
        this.config = config;
        this.api = api;
        this.auditLogger = auditLogger;
        initUI();
        initFirstSession();
    }

    private void initUI()
    {
        setLayout(new BorderLayout(4, 4));
        setBorder(new EmptyBorder(3, 3, 3, 3));

        // ===== Top toolbar =====
        JPanel toolbar = UIStyle.toolbar();
        settingsButton = new JButton(BTN_SETTINGS);
        UIStyle.compactButton(settingsButton);
        settingsButton.setToolTipText("配置 AI API 设置");
        settingsButton.addActionListener(e -> openSettings());
        toolbar.add(settingsButton);

        // 新建会话按钮
        JButton newSessionButton = new JButton("新建");
        UIStyle.compactButton(newSessionButton);
        newSessionButton.setToolTipText("新建对话会话");
        newSessionButton.addActionListener(e -> newSession());
        toolbar.add(newSessionButton);

        JButton deleteSessionButton = new JButton("删除");
        UIStyle.compactButton(deleteSessionButton);
        deleteSessionButton.setToolTipText("删除当前会话");
        deleteSessionButton.addActionListener(e -> deleteCurrentSession());
        toolbar.add(deleteSessionButton);

        clearButton = new JButton(BTN_CLEAR);
        UIStyle.compactButton(clearButton);
        clearButton.setToolTipText("清空当前会话");
        clearButton.addActionListener(e -> clearConversation());
        toolbar.add(clearButton);

        JButton viewDetailButton = new JButton(BTN_DETAIL);
        UIStyle.compactButton(viewDetailButton);
        viewDetailButton.setToolTipText("查看最近一次请求/响应详情");
        viewDetailButton.addActionListener(e -> showLastHttpDetail());
        toolbar.add(viewDetailButton);

        toolbar.add(Box.createHorizontalStrut(6));

        // 会话下拉框
        sessionComboBox = new JComboBox<>();
        sessionComboBox.setFont(sessionComboBox.getFont().deriveFont(Font.PLAIN, 12f));
        sessionComboBox.setMaximumSize(new Dimension(200, 28));
        sessionComboBox.setPreferredSize(new Dimension(180, 28));
        sessionComboBox.addActionListener(e -> {
            if (sessionSwitching) return;
            if (e.getActionCommand().equals("comboBoxChanged")) {
                int idx = sessionComboBox.getSelectedIndex();
                if (idx >= 0 && idx != currentSessionIndex) switchToSession(idx);
            }
        });
        toolbar.add(sessionComboBox);

        toolbar.add(Box.createHorizontalStrut(6));

        statusLabel = UIStyle.mutedLabel(getStatusText());
        toolbar.add(statusLabel);

        add(toolbar, BorderLayout.NORTH);

        // ===== Chat display =====
        chatDisplay = new JTextPane();
        chatDisplay.setEditable(false);
        chatDisplay.setContentType("text/html");
        chatDisplay.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, Boolean.TRUE);
        chatDisplay.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 13));
        chatDisplay.addHyperlinkListener(e ->
        {
            if (e.getEventType() == HyperlinkEvent.EventType.ACTIVATED)
            {
                handleChatLink(e.getDescription());
            }
        });

        chatScrollPane = new JScrollPane(chatDisplay);
        chatScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        chatScrollPane.setPreferredSize(new Dimension(600, 400));



        // ===== 右键菜单 =====
        JPopupMenu popupMenu = new JPopupMenu();

        JMenu copyMenu = new JMenu("复制");

        JMenuItem copyItem = new JMenuItem("复制选中");
        copyItem.addActionListener(e -> copySelectedText());
        copyMenu.add(copyItem);

        JMenuItem copyCodeItem = new JMenuItem("复制代码块");
        copyCodeItem.addActionListener(e -> copyCodeBlockAtCursor());
        copyMenu.add(copyCodeItem);

        JMenuItem copyLastMessageItem = new JMenuItem("复制最后一条 AI 回复(Markdown)");
        copyLastMessageItem.addActionListener(e -> copyLastAssistantMessage());
        copyMenu.add(copyLastMessageItem);

        JMenuItem copyConversationItem = new JMenuItem("复制完整对话(Markdown)");
        copyConversationItem.addActionListener(e -> copyConversationAsMarkdown());
        copyMenu.add(copyConversationItem);

        popupMenu.add(copyMenu);

        popupMenu.addSeparator();

        JMenu sendMenu = new JMenu("发送到 Burp");

        JMenuItem sendToRepeaterItem = new JMenuItem("发送到 Repeater");
        sendToRepeaterItem.addActionListener(e -> sendSelectionToBurpTool(BurpTarget.REPEATER));
        sendMenu.add(sendToRepeaterItem);

        JMenuItem sendToIntruderItem = new JMenuItem("发送到 Intruder");
        sendToIntruderItem.addActionListener(e -> sendSelectionToBurpTool(BurpTarget.INTRUDER));
        sendMenu.add(sendToIntruderItem);

        JMenuItem sendAnalyzeItem = new JMenuItem(MENU_SEND_ANALYZE);
        sendAnalyzeItem.addActionListener(e -> {
            String text = getSelectedOrNearestCodeBlock();
            if (text != null) executeSendAndAnalyze(text);
        });
        sendMenu.add(sendAnalyzeItem);

        popupMenu.add(sendMenu);

        chatDisplay.setComponentPopupMenu(popupMenu);

        // ===== Input area =====
        JPanel inputPanel = new JPanel(new BorderLayout(4, 4));

        inputArea = new JTextArea(3, 40);
        inputArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
        inputArea.setLineWrap(true);
        inputArea.setWrapStyleWord(true);
        inputArea.addKeyListener(new KeyAdapter()
        {
            @Override
            public void keyPressed(KeyEvent e)
            {
                if (e.getKeyCode() == KeyEvent.VK_ENTER && !e.isShiftDown())
                {
                    e.consume();
                    sendMessage();
                }
            }
        });

        JScrollPane inputScroll = new JScrollPane(inputArea);
        inputScroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        inputPanel.add(inputScroll, BorderLayout.CENTER);

        JPanel buttonPanel = new JPanel();
        buttonPanel.setLayout(new BoxLayout(buttonPanel, BoxLayout.Y_AXIS));

        sendButton = new JButton(BTN_SEND);
        UIStyle.primaryButton(sendButton);
        sendButton.setToolTipText("发送消息 (Enter)");
        sendButton.addActionListener(e -> sendMessage());
        buttonPanel.add(sendButton);

        stopButton = new JButton(BTN_STOP);
        UIStyle.compactButton(stopButton);
        stopButton.setToolTipText("停止当前任务");
        stopButton.setVisible(false);
        stopButton.addActionListener(e ->
        {
            pauseCurrentWork("已暂停当前任务");
        });
        buttonPanel.add(stopButton);

        inputPanel.add(buttonPanel, BorderLayout.EAST);

        // 使用 JSplitPane 让聊天区和输入区可拖拽调整大小
        JSplitPane chatSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, chatScrollPane, inputPanel);
        chatSplit.setResizeWeight(0.85);
        chatSplit.setDividerSize(6);
        chatSplit.setOneTouchExpandable(true);
        chatSplit.setContinuousLayout(true);
        add(chatSplit, BorderLayout.CENTER);

        // ===== Welcome message =====
        if (!config.isConfigured())
        {
            appendSystemMessage(MSG_NOT_CONFIGURED, activeRuntime);
        }
    }

    private void sendMessage()
    {
        if (activeRuntime.isSendingHttp)
        {
            pauseCurrentHttpTask("检测到新对话，已暂停上一个请求任务");
        }

        String text = inputArea.getText().trim();
        if (text.isEmpty()) return;

        if (!activeRuntime.provider.isConfigured())
        {
            appendErrorMessage(MSG_API_NOT_CONFIGURED, activeRuntime);
            return;
        }

        // 正在处理时，将用户输入的消息入队
        if (activeRuntime.isProcessing)
        {
            inputArea.setText("");
            sendPrompt(text);
            return;
        }

        inputArea.setText("");
        appendUserMessage(text, activeRuntime);

        final String userText = text;
        synchronized (activeRuntime.conversationHistory)
        {
            ensureCapabilityInstruction(activeRuntime);
            activeRuntime.conversationHistory.add(ChatMessage.user(userText));
        }

        // 首条用户消息后更新会话标题
        updateCurrentSessionTitle();

        activeRuntime.isProcessing = true;
        updateSendState(activeRuntime);

        executeAiRequest(activeRuntime);
    }

    /**
     * Send a pre-built prompt (from context menu) to the AI.
     */
    public void sendPrompt(String prompt, SessionRuntime rt)
    {
        if (!rt.provider.isConfigured())
        {
            appendErrorMessage(MSG_API_NOT_CONFIGURED, rt);
            return;
        }

        // 正在处理时入队，等完成后自动发送
        if (rt.isProcessing)
        {
            synchronized (rt.promptQueue)
            {
                rt.promptQueue.add(prompt);
                int size = rt.promptQueue.size();
                appendSystemMessage(String.format(STATUS_QUEUED, size), rt);
            }
            updateSendState(rt);
            return;
        }

        appendUserMessage(prompt, rt);
        synchronized (rt.conversationHistory)
        {
            ensureCapabilityInstruction(rt);
            rt.conversationHistory.add(ChatMessage.user(prompt));
        }

        rt.isProcessing = true;
        rt.aiRetryCount = 0;
        updateSendState(rt);

        executeAiRequest(rt);
    }

    public void sendPrompt(String prompt)
    {
        sendPrompt(prompt, activeRuntime);
    }

    private void continueWithToolResult(String prompt, SessionRuntime rt)
    {
        if (rt.isProcessing) return;
        if (!rt.provider.isConfigured())
        {
            appendErrorMessage(MSG_API_NOT_CONFIGURED, rt);
            return;
        }

        synchronized (rt.conversationHistory)
        {
            rt.conversationHistory.add(ChatMessage.user(prompt));
        }

        rt.isProcessing = true;
        rt.aiRetryCount = 0;
        updateSendState(rt);

        executeAiRequest(rt);
    }

    private void continueWithToolResult(String prompt)
    {
        continueWithToolResult(prompt, activeRuntime);
    }

    private void clearConversation()
    {
        int choice = JOptionPane.showConfirmDialog(this,
            "确认清空当前会话的所有消息？",
            "确认清空", JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE);
        if (choice != JOptionPane.YES_OPTION) return;

        if (activeRuntime.isSendingHttp)
        {
            pauseCurrentHttpTask("清空会话前，已暂停当前请求任务");
        }

        // 停止正在进行的 AI 流式回复
        if (activeRuntime.isProcessing)
        {
            activeRuntime.aiGeneration++;
            activeRuntime.provider.stopStreaming();
            activeRuntime.isProcessing = false;
        }

        synchronized (activeRuntime.promptQueue)
        {
            activeRuntime.promptQueue.clear();
        }
        synchronized (activeRuntime.conversationHistory)
        {
            activeRuntime.conversationHistory.clear();
        }
        activeRuntime.codeBlockCopies.clear();
        activeRuntime.messageLog.setLength(0);
        activeRuntime.requestCountInSession = 0;
        activeRuntime.lastRequestText = null;
        activeRuntime.lastResponseText = null;
        activeRuntime.lastRequestHost = null;
        activeRuntime.lastRequestSecure = false;
        chatDisplay.setText("");
        updateSendState(activeRuntime);
    }

    // ==================== Session Management ====================

    /**
     * 新建会话 — 保存当前会话，创建并切换到新会话。
     */
    private void newSession()
    {
        // 每个 SessionRuntime 有独立 provider，新建会话不中断旧会话的 HTTP 请求
        stopThinkingSpinner(activeRuntime);

        // 保存当前会话
        if (currentSessionIndex >= 0 && currentSessionIndex < sessions.size())
        {
            sessions.set(currentSessionIndex, snapshotCurrentSession());
        }

        // 创建新会话（带独立 SessionRuntime）
        sessionCounter++;
        String title = "会话 " + formatTimeShort(new Date());
        ChatSession newSess = new ChatSession(
            "sess-" + sessionCounter, title,
            Collections.emptyList(), "", Collections.emptyMap(),
            0, null, null, null, false);
        newSess.runtime = new SessionRuntime(newSess.id);
        sessions.add(newSess);

        activeRuntime = newSess.runtime;
        currentSessionIndex = sessions.size() - 1;

        // 更新下拉框（不触发 listener）
        refreshSessionComboBox();

        chatDisplay.setText("");
        updateSendState(activeRuntime);
    }

    /**
     * 切换到指定会话。
     */
    private void switchToSession(int targetIndex)
    {
        if (targetIndex == currentSessionIndex) return;
        if (targetIndex < 0 || targetIndex >= sessions.size()) return;

        // 每个 SessionRuntime 有独立 provider，切换会话不中断旧会话的 HTTP 请求
        // 只停止旧会话的 UI 动画
        stopThinkingSpinner(activeRuntime);

        // 保存当前会话
        if (currentSessionIndex >= 0 && currentSessionIndex < sessions.size())
        {
            sessions.set(currentSessionIndex, snapshotCurrentSession());
        }

        // 恢复目标会话
        ChatSession target = sessions.get(targetIndex);
        restoreFromSnapshot(target);
        currentSessionIndex = targetIndex;
    }

    /**
     * 快照当前会话状态。
     * 有独立 runtime 的 session 直接返回（runtime 即持久状态）；
     * 无 runtime 的 session（如后台 host session）拷贝数据到快照。
     */
    private ChatSession snapshotCurrentSession()
    {
        ChatSession existing = (currentSessionIndex >= 0 && currentSessionIndex < sessions.size())
            ? sessions.get(currentSessionIndex) : null;
        String existingId = existing != null ? existing.id : "sess-" + (currentSessionIndex + 1);
        String existingTitle = existing != null ? existing.title : "新对话";

        // 更新 title（host session 保留主机名标题）
        String title = (existingId != null && existingId.startsWith("host-"))
            ? existingTitle
            : (hasUserMessage(activeRuntime.conversationHistory)
                ? generateSessionTitle(activeRuntime.conversationHistory)
                : existingTitle);

        // 有独立 runtime 的 session：只更新 title，直接返回现有对象
        if (existing != null && existing.runtime != null)
        {
            existing.title = title;
            return existing;
        }

        // 无独立 runtime 的 session：拷贝数据到快照
        synchronized (activeRuntime.conversationHistory)
        {
            return new ChatSession(
                existingId,
                title,
                new ArrayList<>(activeRuntime.conversationHistory),
                activeRuntime.messageLog.toString(),
                new LinkedHashMap<>(activeRuntime.codeBlockCopies),
                activeRuntime.requestCountInSession,
                activeRuntime.lastRequestText, activeRuntime.lastResponseText, activeRuntime.lastRequestHost,
                activeRuntime.lastRequestSecure);
        }
    }

    /**
     * 从快照恢复会话状态。
     * 有独立 runtime 的 session：切换 activeRuntime 指针，刷新显示（runtime 有最新数据）。
     * 无 runtime 的 session：创建新 runtime，从快照加载数据，确保 session 间隔离。
     */
    private void restoreFromSnapshot(ChatSession session)
    {
        if (session.runtime != null)
        {
            // 有独立 runtime：直接切换，不覆盖 runtime 中的实时数据
            activeRuntime = session.runtime;
        }
        else
        {
            // 无独立 runtime 的 session：创建新 runtime，从快照加载数据
            // 不复用其他 session 的 runtime，确保 session 间完全隔离
            SessionRuntime newRt = new SessionRuntime(session.id);
            synchronized (newRt.conversationHistory)
            {
                newRt.conversationHistory.addAll(session.history);
            }
            newRt.messageLog.append(session.messageLogHtml);
            newRt.codeBlockCopies.putAll(session.codeBlocks);
            newRt.requestCountInSession = session.requestCount;
            newRt.lastRequestText = session.lastReqText;
            newRt.lastResponseText = session.lastRespText;
            newRt.lastRequestHost = session.lastReqHost;
            newRt.lastRequestSecure = session.lastReqSecure;
            session.runtime = newRt;
            activeRuntime = newRt;
        }

        refreshDisplay(activeRuntime);
        updateSendState(activeRuntime);

        // 恢复目标 session 的状态栏
        if (activeRuntime.isSendingHttp)
        {
            statusLabel.setText("正在发送 HTTP 请求...");
        }
        else
        {
            statusLabel.setText(getStatusText());
        }

        // 如果切换回来的 session 正在 AI 处理中，恢复流式显示或思考动画
        if (activeRuntime.isProcessing)
        {
            if (activeRuntime.streamingBuffer.length() > 0)
            {
                // 流式阶段：直接显示已接收的流式内容
                activeRuntime.lastRefreshTime = 0;
                refreshStreamingDisplay(activeRuntime);
            }
            else
            {
                // 思考阶段：显示 spinner
                startThinkingSpinner(activeRuntime);
            }
        }
    }

    /**
     * 根据第一条用户消息自动生成会话标题。
     */
    private String generateSessionTitle(List<ChatMessage> history)
    {
        for (ChatMessage msg : history)
        {
            if (msg.role() == ChatMessage.Role.USER)
            {
                String text = msg.content().replace("\n", " ").trim();
                return text.length() > 20 ? text.substring(0, 20) + "..." : text;
            }
        }
        return "新对话";
    }

    private boolean hasUserMessage(List<ChatMessage> history)
    {
        for (ChatMessage msg : history)
        {
            if (msg.role() == ChatMessage.Role.USER)
            {
                return true;
            }
        }
        return false;
    }

    /**
     * 刷新会话下拉框（不触发 listener）。
     */
    private void refreshSessionComboBox()
    {
        sessionSwitching = true;
        try
        {
            sessionComboBox.removeAllItems();
            for (ChatSession s : sessions)
            {
                sessionComboBox.addItem(s);
            }
            if (currentSessionIndex >= 0 && currentSessionIndex < sessions.size())
            {
                sessionComboBox.setSelectedIndex(currentSessionIndex);
            }
        }
        finally
        {
            sessionSwitching = false;
        }
    }

    /**
     * 更新当前会话标题（在首条用户消息后调用）。
     */
    private void updateCurrentSessionTitle()
    {
        if (currentSessionIndex < 0 || currentSessionIndex >= sessions.size()) return;
        // host session 保留主机名标题，不自动重命名
        String sid = sessions.get(currentSessionIndex).id;
        if (sid != null && sid.startsWith("host-")) return;
        synchronized (activeRuntime.conversationHistory)
        {
            if (!hasUserMessage(activeRuntime.conversationHistory))
            {
                return;
            }
        }
        String newTitle;
        synchronized (activeRuntime.conversationHistory)
        {
            newTitle = generateSessionTitle(activeRuntime.conversationHistory);
        }
        sessions.get(currentSessionIndex).title = newTitle;
        // 更新下拉框显示（使用 refreshSessionComboBox 避免触发 listener）
        refreshSessionComboBox();
    }

    /**
     * 初始化第一个会话。
     */
    private void initFirstSession()
    {
        sessionCounter++;
        String title = "会话 " + formatTimeShort(new Date());
        ChatSession first = new ChatSession(
            "sess-1", title,
            Collections.emptyList(), "", Collections.emptyMap(),
            0, null, null, null, false);
        first.runtime = new SessionRuntime(first.id);
        sessions.add(first);
        currentSessionIndex = 0;
        activeRuntime = first.runtime;
        refreshSessionComboBox();
    }

    private void deleteCurrentSession()
    {
        if (activeRuntime.isSendingHttp)
        {
            pauseCurrentHttpTask("删除会话前，已暂停当前请求任务");
        }
        if (activeRuntime.isProcessing)
        {
            activeRuntime.aiGeneration++;
            activeRuntime.provider.stopStreaming();
            activeRuntime.isProcessing = false;
            activeRuntime.streamingBuffer.setLength(0);
            synchronized (activeRuntime.promptQueue)
            {
                activeRuntime.promptQueue.clear();
            }
            updateSendState(activeRuntime);
        }
        if (currentSessionIndex < 0 || currentSessionIndex >= sessions.size())
        {
            return;
        }

        int choice = JOptionPane.showConfirmDialog(this,
            "确认删除当前会话？",
            "删除会话", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (choice != JOptionPane.YES_OPTION)
        {
            return;
        }

        sessions.remove(currentSessionIndex);
        if (sessions.isEmpty())
        {
            synchronized (activeRuntime.conversationHistory) { activeRuntime.conversationHistory.clear(); }
            activeRuntime.codeBlockCopies.clear();
            activeRuntime.messageLog.setLength(0);
            activeRuntime.requestCountInSession = 0;
            activeRuntime.lastRequestText = null;
            activeRuntime.lastResponseText = null;
            activeRuntime.lastRequestHost = null;
        activeRuntime.lastRequestSecure = false;
            currentSessionIndex = -1;
            initFirstSession();
            restoreFromSnapshot(sessions.get(currentSessionIndex));
            return;
        }

        currentSessionIndex = Math.max(0, Math.min(currentSessionIndex, sessions.size() - 1));
        refreshSessionComboBox();
        restoreFromSnapshot(sessions.get(currentSessionIndex));
    }

    private void openSettings()
    {
        if (openSettingsCallback != null)
        {
            openSettingsCallback.run();
            return;
        }

        // Fallback: 弹窗模式（当未设置回调时）
        SettingsDialog dialog = new SettingsDialog(
            (Frame) SwingUtilities.getWindowAncestor(this), config);
        dialog.setVisible(true);

        if (dialog.isSaved())
        {
            config.save();
            statusLabel.setText(getStatusText());
            appendSystemMessage(String.format(MSG_SETTINGS_SAVED, config.getApiUrl()), activeRuntime);
            fireSettingsChanged();
        }
    }

    // ==================== Message Display ====================

    private void appendUserMessage(String text, SessionRuntime rt)
    {
        appendMessageCard("You", "#1565c0", "#edf7ff",
            MarkdownRenderer.render(text, code -> registerCodeBlockCopy(code, rt)), rt);
        refreshDisplay(rt);
    }

    private void appendAssistantMessage(String text, SessionRuntime rt)
    {
        appendMessageCard("AI", "#2e7d32", "#f7fbf3",
            MarkdownRenderer.render(text, code -> registerCodeBlockCopy(code, rt)), rt);
        refreshDisplay(rt);
    }

    private void appendSystemMessage(String text, SessionRuntime rt)
    {
        rt.messageLog.append(renderSystemMessageHtml(text));
        trimMessageLogIfNeeded(rt);
        refreshDisplay(rt);
    }

    private String renderSystemMessageHtml(String text)
    {
        return "<table border='0' width='100%' cellpadding='4' cellspacing='0' bgcolor='#f6f7f8'>"
            + "<tr><td><font face='sans-serif' size='-1' color='#6b7280'>"
            + TextUtils.escapeHtmlWithBr(text) + "</font></td></tr></table>";
    }

    private void appendErrorMessage(String text, SessionRuntime rt)
    {
        rt.messageLog.append("<table border='0' width='100%' cellpadding='8' cellspacing='0' bgcolor='#ffebee'>"
            + "<tr><td><font face='sans-serif' color='#c62828'><b>Error:</b> "
            + TextUtils.escapeHtmlWithBr(text) + "</font></td></tr></table><br>");
        trimMessageLogIfNeeded(rt);
        refreshDisplay(rt);
    }

    private void appendErrorWithRetry(String text, SessionRuntime rt)
    {
        rt.messageLog.append("<table border='0' width='100%' cellpadding='8' cellspacing='0' bgcolor='#ffebee'>"
            + "<tr><td><font face='sans-serif' color='#c62828'><b>Error:</b> "
            + TextUtils.escapeHtmlWithBr(text)
            + "</font><br><br><a href='retry-ai' style='color:#1565c0;text-decoration:none;'>"
            + "<span style='background:#e3f2fd;padding:4px 12px;border-radius:3px;font-size:12px;'>"
            + "🔄 重新发送</span></a></td></tr></table><br>");
        trimMessageLogIfNeeded(rt);
        refreshDisplay(rt);
    }

    private void appendMessageCard(String role, String roleColor, String bgColor, String bodyHtml, SessionRuntime rt)
    {
        rt.messageLog.append("<table border='0' width='100%' cellpadding='0' cellspacing='0' bgcolor='")
            .append(bgColor).append("'><tr><td>");
        rt.messageLog.append("<table border='0' width='100%' cellpadding='6' cellspacing='0'><tr><td>");
        rt.messageLog.append("<font face='sans-serif' size='-1' color='").append(roleColor)
            .append("'><b>").append(role).append("</b></font><br>");
        rt.messageLog.append(bodyHtml);
        rt.messageLog.append("</td></tr></table></td></tr></table><br>");
        trimMessageLogIfNeeded(rt);
    }

    /**
     * 用 setText 整体刷新显示，比 insertHTML 更可靠地渲染 Markdown 生成的 HTML。
     */
    private void refreshDisplay(SessionRuntime rt)
    {
        if (!rt.isActive()) return;
        SwingUtilities.invokeLater(() ->
        {
            chatDisplay.setText("<html><body style='font-family:sans-serif;font-size:13px;padding:4px;background:#ffffff;'>"
                + rt.messageLog.toString() + "</body></html>");
            chatScrollPane.getVerticalScrollBar().setValue(
                chatScrollPane.getVerticalScrollBar().getMaximum());
        });
    }

    /**
     * 流式更新：节流，避免每个 token 都重建 HTML。
     * 最少间隔 REFRESH_INTERVAL_MS 毫秒才刷新一次界面。
     */
    private void refreshStreamingDisplay(SessionRuntime rt)
    {
        if (!rt.isActive()) return;
        long now = System.currentTimeMillis();
        if (now - rt.lastRefreshTime < REFRESH_INTERVAL_MS) return;
        rt.lastRefreshTime = now;

        String streamingHtml = "<table border='0' width='100%' cellpadding='6' cellspacing='0' bgcolor='#f7fbf3'>"
            + "<tr><td>"
            + "<font face='sans-serif' size='-1' color='#2e7d32'><b>AI</b></font>"
            + "<br>"
            + MarkdownRenderer.render(rt.streamingBuffer.toString())
            + "<font color='#999999'>▌</font></td></tr></table>";

        SwingUtilities.invokeLater(() ->
        {
            chatDisplay.setText("<html><body style='font-family:sans-serif;font-size:13px;padding:4px;background:#ffffff;'>"
                + rt.messageLog.toString() + streamingHtml + "</body></html>");
            chatScrollPane.getVerticalScrollBar().setValue(
                chatScrollPane.getVerticalScrollBar().getMaximum());
        });
    }

    private void startThinkingSpinner(SessionRuntime rt)
    {
        stopThinkingSpinner(rt);
        rt.spinnerFrame = 0;
        rt.spinnerTimer = new javax.swing.Timer(SPINNER_INTERVAL_MS, e -> {
            if (!rt.isActive()) { stopThinkingSpinner(rt); return; }
            rt.spinnerFrame = (rt.spinnerFrame + 1) % SPINNER_FRAMES.length;
            String spinnerHtml = "<table border='0' width='100%' cellpadding='6' cellspacing='0' bgcolor='#f7fbf3'>"
                + "<tr><td>"
                + "<font face='sans-serif' size='-1' color='#2e7d32'><b>AI</b></font><br>"
                + "<font color='#999999'>" + SPINNER_FRAMES[rt.spinnerFrame] + " 正在思考...</font>"
                + "</td></tr></table>";
            SwingUtilities.invokeLater(() -> {
                chatDisplay.setText("<html><body style='font-family:sans-serif;font-size:13px;padding:4px;background:#ffffff;'>"
                    + rt.messageLog.toString() + spinnerHtml + "</body></html>");
                chatScrollPane.getVerticalScrollBar().setValue(
                    chatScrollPane.getVerticalScrollBar().getMaximum());
            });
        });
        rt.spinnerTimer.start();
    }

    private void stopThinkingSpinner(SessionRuntime rt)
    {
        if (rt.spinnerTimer != null)
        {
            rt.spinnerTimer.stop();
            rt.spinnerTimer = null;
        }
    }

    private String registerCodeBlockCopy(String code, SessionRuntime rt)
    {
        String id = String.valueOf(rt.codeBlockCopies.size());
        rt.codeBlockCopies.put(id, code == null ? "" : code);
        return id;
    }

    private void handleChatLink(String href)
    {
        if (href == null) return;
        if (href.startsWith("copy-code-"))
        {
            String code = activeRuntime.codeBlockCopies.get(href.substring("copy-code-".length()));
            if (code != null)
            {
                copyToClipboard(code);
                statusLabel.setText("已复制代码块");
            }
        }
        else if (href.startsWith("repeater-code-"))
        {
            sendCodeBlockToBurpTool(href.substring("repeater-code-".length()), BurpTarget.REPEATER);
        }
        else if (href.startsWith("intruder-code-"))
        {
            sendCodeBlockToBurpTool(href.substring("intruder-code-".length()), BurpTarget.INTRUDER);
        }
        else if (href.startsWith("send-analyze-code-"))
        {
            String code = activeRuntime.codeBlockCopies.get(href.substring("send-analyze-code-".length()));
            if (code != null) executeSendAndAnalyze(code);
        }
        else if (href.equals("retry-ai"))
        {
            retryLastAiRequest();
        }
    }

    private void retryLastAiRequest()
    {
        SessionRuntime rt = activeRuntime;
        if (rt == null || rt.isProcessing || rt.isSendingHttp) return;

        // 移除 messageLog 末尾的错误卡片（bgColor='#ffebee' 的 table）
        String log = rt.messageLog.toString();
        int errIdx = log.lastIndexOf("bgcolor='#ffebee'");
        if (errIdx > 0)
        {
            // 找到包含这个错误卡片的 <table ... <br> 整块
            int tableStart = log.lastIndexOf("<table ", errIdx);
            int tableEnd = log.indexOf("<br>", errIdx);
            if (tableStart >= 0 && tableEnd >= 0)
            {
                rt.messageLog.setLength(0);
                rt.messageLog.append(log.substring(0, tableStart));
                // tableEnd + 4 = skip "<br>"
                if (tableEnd + 4 < log.length())
                {
                    rt.messageLog.append(log.substring(tableEnd + 4));
                }
            }
        }

        rt.aiRetryCount = 0;
        rt.isProcessing = true;
        appendSystemMessage("正在重新请求...", rt);
        updateSendState(rt);
        executeAiRequest(rt);
    }

    private String getStatusText()
    {
        if (config.isConfigured())
        {
            return "模型: " + config.getModel();
        }
        return STATUS_NOT_CONFIGURED;
    }

    /**
     * Thread-safe time formatting for session titles.
     * Creates a new SimpleDateFormat per call to avoid thread-safety issues.
     */
    private static String formatTimeShort(Date date)
    {
        return new SimpleDateFormat("HH:mm").format(date);
    }

    private void updateSendState(SessionRuntime rt)
    {
        int queueSize;
        synchronized (rt.promptQueue)
        {
            queueSize = rt.promptQueue.size();
        }
        if (!rt.isActive()) return; // 后台 session 不更新 UI 控件
        sendButton.setEnabled(true);  // 始终可点，AI处理中点击会入队
        inputArea.setEnabled(true);   // 始终可输入，允许准备下一条消息
        stopButton.setEnabled(rt.isProcessing || rt.isSendingHttp || queueSize > 0);
        stopButton.setVisible(rt.isProcessing || rt.isSendingHttp || queueSize > 0);

        if (rt.isProcessing)
        {
            String text = STATUS_THINKING;
            if (queueSize > 0) text += " (+" + queueSize + " 排队)";
            sendButton.setText(text);
        }
        else
        {
            sendButton.setText(BTN_SEND);
        }
    }

    // ==================== Listener support ====================

    public interface ChatPanelListener extends EventListener
    {
        void settingsChanged();
    }

    /**
     * HTTP 请求发送后的回调接口，用于通知 AIRequestPanel。
     */
    public interface HttpRequestCallback extends EventListener
    {
        void onRequestSent(String requestText, String responseText, String host, String method, int statusCode, long durationMs);
    }

    /**
     * 标签页切换回调，用于跳转到 AI 请求标签页。
     */
    public interface TabSwitchCallback extends EventListener
    {
        void switchToAiRequest();
    }

    public void addListener(ChatPanelListener listener)
    {
        listeners.add(listener);
    }

    public void setHttpRequestCallback(HttpRequestCallback callback)
    {
        this.httpRequestCallback = callback;
    }

    public void setTabSwitchCallback(TabSwitchCallback callback)
    {
        this.tabSwitchCallback = callback;
    }

    public void setOpenSettingsCallback(Runnable callback)
    {
        this.openSettingsCallback = callback;
    }

    /**
     * 设置漏洞报告写入后的回调（用于刷新 ReportPanel）。
     */
    public void setVulnReportCallback(Runnable callback)
    {
        this.vulnReportCallback = callback;
    }

    private void fireSettingsChanged()
    {
        for (ChatPanelListener l : listeners)
        {
            l.settingsChanged();
        }
    }

    // ==================== Streaming Helpers ====================

    /**
     * 裁剪 messageLog，防止无限增长。
     * 超过 MAX_MESSAGE_LOG_CHARS 时截断前 30%，保留最近 70% 的内容。
     */
    private void trimMessageLogIfNeeded(SessionRuntime rt)
    {
        if (rt.messageLog.length() > MAX_MESSAGE_LOG_CHARS)
        {
            int keepStart = (int) (rt.messageLog.length() * 0.7);
            // 找到第一个 '<' 标签起始位置，避免截断在标签中间
            String tail = rt.messageLog.substring(keepStart);
            int tagStart = tail.indexOf('<');
            if (tagStart > 0)
            {
                keepStart += tagStart;
            }
            String kept = rt.messageLog.substring(keepStart);
            rt.messageLog.setLength(0);
            rt.messageLog.append(kept);
        }
    }

    /**
     * 统一的 AI 流式请求执行器。
     * sendMessage / sendPrompt / continueWithToolResult 共用此方法。
     */
    private void executeAiRequest(SessionRuntime rt)
    {
        final long myGeneration = rt.aiGeneration;
        SwingWorker<Void, String> worker = new SwingWorker<>()
        {
            @Override
            protected Void doInBackground() throws Exception
            {
                final List<ChatMessage> historyCopy;
                synchronized (rt.conversationHistory)
                {
                    historyCopy = new ArrayList<>(rt.conversationHistory);
                }
                rt.streamingBuffer.setLength(0);
                rt.provider.chatStream(historyCopy, new StreamingAIProvider.StreamCallback()
                {
                    @Override public void onToken(String token) { publish(token); }
                    @Override public void onComplete(String fullResponse) { publish(""); }
                    @Override public void onError(Exception e) { publish("ERROR:" + e.getMessage()); }
                });
                return null;
            }

            @Override
            protected void process(List<String> chunks)
            {
                if (myGeneration != rt.aiGeneration) return;
                processStreamingChunks(chunks, rt);
            }

            @Override
            protected void done()
            {
                stopThinkingSpinner(rt);
                try
                {
                    get();
                }
                catch (Exception e)
                {
                    if (myGeneration != rt.aiGeneration) return;
                    String msg = e.getMessage();
                    if (e.getCause() != null) msg = e.getCause().getMessage();
                    // 先保留已接收的部分内容
                    finishStreaming(false, rt);
                    appendErrorWithRetry("AI 请求异常: " + msg, rt);
                    if (api != null) api.logging().logToError("[Chat] executeAiRequest failed: " + msg);
                }
            }
        };
        worker.execute();
        startThinkingSpinner(rt);
    }

    private void processStreamingChunks(List<String> chunks, SessionRuntime rt)
    {
        stopThinkingSpinner(rt);
        boolean hasComplete = false;
        for (String token : chunks)
        {
            if (token.isEmpty())
            {
                hasComplete = true;
            }
            else if (token.startsWith("ERROR:"))
            {
                String errMsg = token.substring(6);
                if (rt.aiRetryCount < MAX_RETRIES)
                {
                    rt.aiRetryCount++;
                    appendSystemMessage("请求失败，第 " + rt.aiRetryCount + "/" + MAX_RETRIES + " 次重试...", rt);
                    rt.streamingBuffer.setLength(0);
                    rt.isProcessing = false;
                    updateSendState(rt);
                    // 重新执行（不重置 aiRetryCount）
                    SwingUtilities.invokeLater(() -> {
                        rt.isProcessing = true;
                        updateSendState(rt);
                        executeAiRequest(rt);
                    });
                }
                else
                {
                    appendErrorWithRetry("重试 " + MAX_RETRIES + " 次后仍然失败: " + errMsg, rt);
                    finishStreaming(false, rt);
                }
                return;
            }
            else
            {
                rt.streamingBuffer.append(token);
            }
        }
        if (hasComplete)
        {
            rt.lastRefreshTime = 0;
            finishStreaming(true, rt);
        }
        else
        {
            refreshStreamingDisplay(rt);
        }
    }

    private void finishStreaming(boolean success, SessionRuntime rt)
    {
        stopThinkingSpinner(rt);
        String completedResponse = rt.streamingBuffer.toString();
        if (api != null) api.logging().logToOutput("[Chat] finishStreaming(" + success + "), responseLen=" + completedResponse.length());
        // 即使失败（超时/断连），也保留已接收的部分内容
        if (completedResponse.length() > 0)
        {
            synchronized (rt.conversationHistory)
            {
                rt.conversationHistory.add(ChatMessage.assistant(completedResponse));
            }
            appendAssistantMessage(completedResponse, rt);
            if (!success)
            {
                appendSystemMessage("(响应被中断，以上为已接收的部分内容)", rt);
            }
        }
        rt.streamingBuffer.setLength(0);
        rt.isProcessing = false;
        updateSendState(rt);

        if (success)
        {
            // 优先处理当前响应中的漏洞报告和 HTTP 代码块（属于当前对话流）
            maybeExtractVulnReport(completedResponse, rt);
            maybeExecuteAutonomousRequest(completedResponse, rt);
        }

        // 只有在未触发自主 HTTP 请求时才处理队列
        // （自主请求完成后会再次调用 finishStreaming，那时再处理队列）
        if (!rt.isSendingHttp)
        {
            processNextInQueue(rt);
        }
    }

    /**
     * 处理队列中的下一条消息。
     * 在 finishStreaming 和 stopCurrentAndContinue 后调用。
     */
    private void processNextInQueue(SessionRuntime rt)
    {
        String next;
        synchronized (rt.promptQueue)
        {
            next = rt.promptQueue.poll();
        }
        if (next == null) return;

        appendUserMessage(next, rt);
        synchronized (rt.conversationHistory)
        {
            // 如果上一条是 user 消息（说明上一轮 AI 回复被中断），
            // 插入中断标记，防止 AI 把上一个问题和新问题混在一起回答
            if (!rt.conversationHistory.isEmpty()
                && rt.conversationHistory.get(rt.conversationHistory.size() - 1).role() == ChatMessage.Role.USER)
            {
                rt.conversationHistory.add(ChatMessage.assistant("[回复已中断]"));
            }
            ensureCapabilityInstruction(rt);
            rt.conversationHistory.add(ChatMessage.user(next));
        }

        rt.isProcessing = true;
        rt.aiRetryCount = 0;
        updateSendState(rt);
        executeAiRequest(rt);
    }

    // ==================== 右键菜单操作 ====================

    /**
     * 复制当前选中的渲染文本。
     */
    private void copySelectedText()
    {
        String selected = chatDisplay.getSelectedText();
        if (selected == null || selected.trim().isEmpty()) return;
        copyToClipboard(selected);
    }

    /**
     * 复制光标所在代码块的完整内容。
     */
    private void copyCodeBlockAtCursor()
    {
        String selected = chatDisplay.getSelectedText();
        if (selected != null && !selected.isEmpty())
        {
            // 有选中文字就复制选中
            copyToClipboard(selected);
            return;
        }

        // 无选中文字，尝试提取光标处的完整文档文本
        // 从 streamingBuffer 或 conversationHistory 中找最近的代码块
        String fullText = activeRuntime.streamingBuffer.length() > 0 ? activeRuntime.streamingBuffer.toString() : getLastAssistantText();
        if (fullText == null) return;

        // 提取 ```...``` 代码块
        int cursorHint = -1;
        if (selected != null) cursorHint = fullText.indexOf(selected);

        String codeBlock = findCodeBlockNear(fullText, cursorHint);
        if (codeBlock != null)
        {
            copyToClipboard(codeBlock);
        }
    }

    /**
     * 复制最后一条 AI 回复的 Markdown 原文。
     */
    private void copyLastAssistantMessage()
    {
        String text = getLastAssistantText();
        if (text == null || text.trim().isEmpty()) return;
        copyToClipboard(text);
    }

    /**
     * 复制完整对话的 Markdown 原文。
     */
    private void copyConversationAsMarkdown()
    {
        String text = getConversationMarkdown();
        if (text.trim().isEmpty()) return;
        copyToClipboard(text);
    }

    /**
     * 将选中的文本或最近代码块发送到指定 Burp 工具。
     */
    private void sendSelectionToBurpTool(BurpTarget target)
    {
        if (api == null) return;

        String text = getSelectedOrNearestCodeBlock();
        if (text == null || text.trim().isEmpty()) return;

        sendRawRequestToBurpTool(text, target);
    }

    /**
     * 将指定代码块中的 HTTP 请求发送到 Burp 工具。
     */
    private void sendCodeBlockToBurpTool(String codeBlockId, BurpTarget target)
    {
        if (api == null) return;

        String text = activeRuntime.codeBlockCopies.get(codeBlockId);
        if (text == null || text.trim().isEmpty()) return;

        sendRawRequestToBurpTool(text, target);
    }

    /**
     * 只发送真实 HTTP 请求，不再把普通文本包装成临时请求。
     */
    private void sendRawRequestToBurpTool(String text, BurpTarget target)
    {
        try
        {
            ParsedHttpRequest parsed = parseAsHttpRequest(text, activeRuntime.lastRequestSecure);
            burp.api.montoya.http.message.requests.HttpRequest request = createHttpRequestForBurp(parsed);
            if (target == BurpTarget.REPEATER)
            {
                api.repeater().sendToRepeater(request, "AI Chat");
            }
            else if (target == BurpTarget.INTRUDER)
            {
                api.intruder().sendToIntruder(request, "AI Chat");
            }
            statusLabel.setText(target == BurpTarget.REPEATER ? "已发送到 Repeater" : "已发送到 Intruder");
        }
        catch (Exception e)
        {
            appendErrorMessage("只能重放 HTTP 请求代码块: " + e.getMessage(), activeRuntime);
        }
    }

    /**
     * 获取选中文本；无选中时取最近一条 AI 回复中的第一个代码块。
     */
    private String getSelectedOrNearestCodeBlock()
    {
        String text = chatDisplay.getSelectedText();
        if (text != null && !text.trim().isEmpty()) return text;

        String fullText = activeRuntime.streamingBuffer.length() > 0 ? activeRuntime.streamingBuffer.toString() : getLastAssistantText();
        if (fullText == null) return null;
        return findCodeBlockNear(fullText, -1);
    }

    /**
     * 将对话历史导出为 Markdown。
     */
    private String getConversationMarkdown()
    {
        StringBuilder markdown = new StringBuilder();
        synchronized (activeRuntime.conversationHistory)
        {
            for (ChatMessage msg : activeRuntime.conversationHistory)
            {
                if (msg.role() == ChatMessage.Role.USER)
                {
                    markdown.append("## You\n\n");
                }
                else if (msg.role() == ChatMessage.Role.ASSISTANT)
                {
                    markdown.append("## AI\n\n");
                }
                else
                {
                    markdown.append("## System\n\n");
                }
                markdown.append(msg.content()).append("\n\n");
            }
        }
        if (activeRuntime.streamingBuffer.length() > 0)
        {
            markdown.append("## AI\n\n").append(activeRuntime.streamingBuffer).append("\n\n");
        }
        return markdown.toString();
    }

    /**
     * 获取最后一条 AI 消息的原始文本。
     */
    private String getLastAssistantText()
    {
        synchronized (activeRuntime.conversationHistory)
        {
            for (int i = activeRuntime.conversationHistory.size() - 1; i >= 0; i--)
            {
                ChatMessage msg = activeRuntime.conversationHistory.get(i);
                if (msg.role() == ChatMessage.Role.ASSISTANT)
                {
                    return msg.content();
                }
            }
        }
        return null;
    }

    /**
     * 从文本中找到包含指定位置或最近的代码块，返回代码块内容。
     */
    private String findCodeBlockNear(String text, int hintPos)
    {
        int searchStart = hintPos >= 0 ? Math.max(0, hintPos - 500) : 0;
        // 先从 hintPos 附近找，找不到就从头找
        for (int attempt = 0; attempt < 2; attempt++)
        {
            int i = (attempt == 0) ? searchStart : 0;
            while (i < text.length())
            {
                int openIdx = text.indexOf("```", i);
                if (openIdx < 0) break;

                // 跳过语言标记行（```python 等）
                int contentStart = text.indexOf('\n', openIdx);
                if (contentStart < 0) break;
                contentStart++;

                int closeIdx = text.indexOf("```", contentStart);
                if (closeIdx < 0) break;

                String code = text.substring(contentStart, closeIdx).trim();
                // 如果 hintPos 在这个代码块范围内，或者第一次找到
                if (hintPos < 0 || (hintPos >= openIdx && hintPos <= closeIdx + 3))
                {
                    return code;
                }
                i = closeIdx + 3;
            }
            if (attempt == 0) continue;
            break;
        }
        // 没找到代码块，返回整个文本
        return text.length() > 500 ? text.substring(0, 500) : text;
    }

    /**
     * 将文本解析为 HTTP 请求，保留 body 原始内容，只规范化换行。
     */
    private ParsedHttpRequest parseAsHttpRequest(String text)
    {
        return parseAsHttpRequest(text, false);
    }

    /**
     * 将文本解析为 HTTP 请求。
     * @param hintSecure 外部上下文提示：原始请求是否为 HTTPS（来自 Burp 的 httpService.secure()）
     */
    private ParsedHttpRequest parseAsHttpRequest(String text, boolean hintSecure)
    {
        if (text == null || text.trim().isEmpty())
        {
            throw new IllegalArgumentException("请求为空");
        }

        String normalized = stripOuterBlankLines(normalizeHttpNewlines(text));
        int firstLineEnd = normalized.indexOf("\r\n");
        String firstLine = firstLineEnd >= 0 ? normalized.substring(0, firstLineEnd) : normalized;
        if (!firstLine.matches("^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\\s+.+\\s+HTTP/\\d\\.\\d$"))
        {
            throw new IllegalArgumentException("首行不是 HTTP 请求行");
        }

        String hostHeader = extractHostFromNormalizedRequest(normalized);
        int methodEnd = firstLine.indexOf(' ');
        int httpPos = firstLine.lastIndexOf(" HTTP/");
        String requestTarget = httpPos > methodEnd ? firstLine.substring(methodEnd + 1, httpPos) : firstLine.split("\\s+")[1];
        String host = hostHeader;
        // HTTPS 判定：1) 绝对URL中的 https:// 2) CONNECT 方法 3) 外部上下文 hint 4) 端口443
        boolean secure = requestTarget.startsWith("https://") || firstLine.startsWith("CONNECT ");
        if (requestTarget.startsWith("http://") || requestTarget.startsWith("https://"))
        {
            String urlHost = extractHostFromAbsoluteUrl(requestTarget);
            if (urlHost != null && !urlHost.isEmpty())
            {
                host = urlHost;
            }
        }
        if (host == null || host.isEmpty())
        {
            throw new IllegalArgumentException("缺少 Host 头，无法确定目标服务");
        }

        // 请求行没有 https 标识时，使用外部上下文 hint（来自原始 Burp 请求）
        if (!secure && hintSecure)
        {
            secure = true;
        }
        HostPort hostPort = parseHostPort(host, secure ? 443 : 80);
        String prepared = prepareHttpRequestForBurp(normalized);
        return new ParsedHttpRequest(prepared, hostPort.host, hostPort.port, secure);
    }

    /**
     * 创建 Burp 可接收的 HTTP 请求，显式绑定 HttpService，避免只靠 Host 推断服务。
     */
    private burp.api.montoya.http.message.requests.HttpRequest createHttpRequestForBurp(String text)
    {
        ParsedHttpRequest parsed = parseAsHttpRequest(text);
        return createHttpRequestForBurp(parsed);
    }

    private burp.api.montoya.http.message.requests.HttpRequest createHttpRequestForBurp(ParsedHttpRequest parsed)
    {
        burp.api.montoya.http.HttpService service =
            burp.api.montoya.http.HttpService.httpService(parsed.host, parsed.port, parsed.secure);
        return burp.api.montoya.http.message.requests.HttpRequest.httpRequest(service, parsed.requestText);
    }

    /**
     * 发送到 Burp 前只修正 Content-Length；含非 ASCII body 时为常见文本类型补 charset，避免显示乱码。
     */
    private String prepareHttpRequestForBurp(String requestText)
    {
        String normalized = normalizeHttpNewlines(requestText);

        // URI 中可能含空格（AI 生成的 SQL 注入等），需编码为 %20
        int firstSpace = normalized.indexOf(' ');
        if (firstSpace >= 0)
        {
            int firstCrlf = normalized.indexOf("\r\n");
            if (firstCrlf > firstSpace)
            {
                String requestLine = normalized.substring(0, firstCrlf);
                int httpPos = requestLine.lastIndexOf(" HTTP/");
                if (httpPos > firstSpace)
                {
                    int methodEnd = requestLine.indexOf(' ');
                    String method = requestLine.substring(0, methodEnd);
                    String uri = requestLine.substring(methodEnd + 1, httpPos);
                    String version = requestLine.substring(httpPos + 1);
                    String encodedUri = uri.replace(" ", "%20");
                    normalized = method + " " + encodedUri + " " + version + normalized.substring(firstCrlf);
                }
            }
        }

        int headerEnd = normalized.indexOf("\r\n\r\n");
        // 如果找不到头部/正文分隔符，说明 AI 生成的请求缺少结尾空行，补上 \r\n\r\n
        if (headerEnd < 0)
        {
            normalized = normalized.endsWith("\r\n") ? normalized + "\r\n" : normalized + "\r\n\r\n";
            headerEnd = normalized.indexOf("\r\n\r\n");
            if (headerEnd < 0) return normalized;
        }

        String headerPart = normalized.substring(0, headerEnd);
        String body = normalized.substring(headerEnd + 4);
        int bodyLength = body.getBytes(StandardCharsets.UTF_8).length;

        StringBuilder rebuiltHeaders = new StringBuilder();
        String[] lines = headerPart.split("\r\n", -1);
        boolean sawContentLength = false;
        for (int i = 0; i < lines.length; i++)
        {
            String line = lines[i];
            String lower = line.toLowerCase(Locale.ROOT);
            if (lower.startsWith("content-length:"))
            {
                line = "Content-Length: " + bodyLength;
                sawContentLength = true;
            }
            else if (containsNonAscii(body) && lower.startsWith("content-type:")
                && shouldAppendUtf8Charset(lower))
            {
                line = line + "; charset=utf-8";
            }

            if (i > 0) rebuiltHeaders.append("\r\n");
            rebuiltHeaders.append(line);
        }

        if (!sawContentLength && bodyLength > 0)
        {
            rebuiltHeaders.append("\r\nContent-Length: ").append(bodyLength);
        }

        return rebuiltHeaders.append("\r\n\r\n").append(body).toString();
    }

    private boolean containsNonAscii(String text)
    {
        if (text == null) return false;
        for (int i = 0; i < text.length(); i++)
        {
            if (text.charAt(i) > 0x7F) return true;
        }
        return false;
    }

    private boolean shouldAppendUtf8Charset(String contentTypeHeaderLower)
    {
        if (contentTypeHeaderLower.contains("charset=")) return false;
        return contentTypeHeaderLower.contains("json")
            || contentTypeHeaderLower.contains("text/")
            || contentTypeHeaderLower.contains("xml")
            || contentTypeHeaderLower.contains("x-www-form-urlencoded");
    }

    private String stripOuterBlankLines(String text)
    {
        if (text == null) return "";
        int start = 0;
        int end = text.length();
        while (start < end && (text.charAt(start) == '\r' || text.charAt(start) == '\n')) start++;
        while (end > start && (text.charAt(end - 1) == '\r' || text.charAt(end - 1) == '\n')) end--;
        return text.substring(start, end);
    }

    private String extractHostFromNormalizedRequest(String httpRequest)
    {
        for (String line : httpRequest.split("\r\n"))
        {
            if (line.toLowerCase(Locale.ROOT).startsWith("host:"))
            {
                return line.substring(5).trim();
            }
        }
        return null;
    }

    private String extractHostFromAbsoluteUrl(String requestTarget)
    {
        try
        {
            java.net.URI uri = java.net.URI.create(requestTarget);
            if (uri.getHost() == null) return null;
            int port = uri.getPort();
            return port > 0 ? uri.getHost() + ":" + port : uri.getHost();
        }
        catch (Exception e)
        {
            return null;
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

    private HostPort parseHostPort(String hostHeader, int defaultPort)
    {
        String host = hostHeader == null ? "" : hostHeader.trim();
        int port = defaultPort;
        if (host.startsWith("["))
        {
            int close = host.indexOf(']');
            if (close >= 0)
            {
                String after = host.substring(close + 1);
                if (after.startsWith(":")) port = parsePort(after.substring(1), defaultPort);
                host = host.substring(1, close);
            }
        }
        else
        {
            int colon = host.lastIndexOf(':');
            if (colon > 0 && host.indexOf(':') == colon)
            {
                port = parsePort(host.substring(colon + 1), defaultPort);
                host = host.substring(0, colon);
            }
        }
        return new HostPort(host, port);
    }

    private int parsePort(String value, int defaultPort)
    {
        try
        {
            int port = Integer.parseInt(value);
            return port > 0 && port <= 65535 ? port : defaultPort;
        }
        catch (Exception e)
        {
            return defaultPort;
        }
    }

    /**
     * 将 HTTP 请求换行规范化为 CRLF，避免重复替换产生 \r\r\n。
     */
    private String normalizeHttpNewlines(String text)
    {
        return text.replace("\r\n", "\n")
                   .replace('\r', '\n')
                   .replace("\n", "\r\n")
                   .replaceAll("(\r\n){3,}", "\r\n\r\n");
    }

    // ==================== 发送并分析 ====================

    /**
     * 发送 HTTP 请求并将响应反馈给 AI 分析。
     */
    private void executeSendAndAnalyze(String rawRequestText)
    {
        executeSendAndAnalyze(rawRequestText, true, false, activeRuntime);
    }

    private void executeSendAndAnalyze(String rawRequestText, boolean requireConfirmation, boolean continueAutonomously)
    {
        executeSendAndAnalyze(rawRequestText, requireConfirmation, continueAutonomously, activeRuntime);
    }

    private void executeSendAndAnalyze(String rawRequestText, boolean requireConfirmation, boolean continueAutonomously, SessionRuntime rt)
    {
        if (api == null) { api.logging().logToOutput("[Chat] executeSendAndAnalyze: api=null, abort"); return; }
        if (!rt.provider.isConfigured())
        {
            appendErrorMessage(MSG_API_NOT_CONFIGURED, rt);
            api.logging().logToOutput("[Chat] executeSendAndAnalyze: provider not configured, abort");
            return;
        }
        if (rt.isProcessing)
        {
            appendErrorMessage("AI 正在处理中，请点击停止按钮中断后再发送请求", rt);
            api.logging().logToOutput("[Chat] executeSendAndAnalyze: isProcessing=true, abort");
            return;
        }
        if (rt.isSendingHttp)
        {
            appendErrorMessage("已有 HTTP 请求正在发送，请等待完成", rt);
            api.logging().logToOutput("[Chat] executeSendAndAnalyze: isSendingHttp=true, abort");
            return;
        }
        if (rt.requestCountInSession >= MAX_REQUESTS_PER_SESSION)
        {
            appendErrorMessage("已达到本次会话最大请求数限制(" + MAX_REQUESTS_PER_SESSION + ")", rt);
            if (continueAutonomously) stopAutonomousMode("已达到发送次数限制，停止自主模式。");
            api.logging().logToOutput("[Chat] executeSendAndAnalyze: max requests reached, abort");
            return;
        }
        if (TextUtils.isDestructivePayload(rawRequestText))
        {
            appendErrorMessage("请求包含破坏性操作(DROP/DELETE/TRUNCATE等)，已拒绝发送", rt);
            if (continueAutonomously) stopAutonomousMode("检测到危险请求，停止自主模式。");
            api.logging().logToOutput("[Chat] executeSendAndAnalyze: destructive payload, abort");
            return;
        }

        ParsedHttpRequest parsedRequest;
        try
        {
            parsedRequest = parseAsHttpRequest(rawRequestText, rt.lastRequestSecure);
        }
        catch (IllegalArgumentException e)
        {
            appendErrorMessage("不是有效的 HTTP 请求: " + e.getMessage(), rt);
            if (continueAutonomously) stopAutonomousMode("AI 生成的请求无效，停止自主模式。");
            return;
        }

        // 提取 Host 用于确认对话框
        String host = parsedRequest.host + ":" + parsedRequest.port;
        String preview = rawRequestText.length() > 500
            ? rawRequestText.substring(0, 500) + "\n..." : rawRequestText;
        if (requireConfirmation)
        {
            int choice = JOptionPane.showConfirmDialog(this,
                "确认发送以下 HTTP 请求到 " + host + "？\n\n" + preview,
                "确认发送请求",
                JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            if (choice != JOptionPane.YES_OPTION) return;
        }

        // 构建请求
        burp.api.montoya.http.message.requests.HttpRequest request = createHttpRequestForBurp(parsedRequest);

        appendSystemMessage("正在发送请求到 " + host + " ...", rt);
        api.logging().logToOutput("[Chat] executeSendAndAnalyze: starting SwingWorker, sending to " + host + ", autonomous=" + continueAutonomously);
        rt.isSendingHttp = true;
        int taskId = ++rt.activeHttpTaskId;
        if (rt.isActive()) statusLabel.setText("正在发送 HTTP 请求...");
        updateSendState(rt);

        SwingWorker<String, Void> sendWorker = new SwingWorker<>()
        {
            long durationMs = 0;

            @Override
            protected String doInBackground() throws Exception
            {
                long start = System.currentTimeMillis();
                api.logging().logToOutput("[Chat] HTTP sending: "
                    + parsedRequest.host + ":" + parsedRequest.port + " secure=" + parsedRequest.secure);
                burp.api.montoya.http.message.HttpRequestResponse result = api.http().sendRequest(request);
                durationMs = System.currentTimeMillis() - start;
                // 如果第一次发送没有收到响应，重试一次（可能 Burp HTTP 引擎暂时异常）
                if (!result.hasResponse())
                {
                    api.logging().logToOutput("[Chat] HTTP no response, retrying once... (" + durationMs + "ms)");
                    try { Thread.sleep(200); } catch (InterruptedException ignored) {}
                    long retryStart = System.currentTimeMillis();
                    result = api.http().sendRequest(request);
                    durationMs = System.currentTimeMillis() - retryStart;
                }
                api.logging().logToOutput("[Chat] HTTP response: hasResponse=" + result.hasResponse()
                    + " duration=" + durationMs + "ms");
                if (result.hasResponse())
                {
                    return TextUtils.toStringUtf8(result.response());
                }
                return null;
            }

            @Override
            protected void done()
            {
                api.logging().logToOutput("[Chat] sendWorker.done() called, taskId=" + taskId + ", activeTaskId=" + rt.activeHttpTaskId);
                try
                {
                    if (rt.pausedHttpTasks.remove(taskId))
                    {
                        // 只有当前没有更新的 HTTP 任务在执行时才清除标志，
                        // 避免误清后续任务的 isSendingHttp 标志
                        if (rt.activeHttpTaskId == taskId)
                        {
                            rt.isSendingHttp = false;
                        }
                        if (rt.isActive()) statusLabel.setText(getStatusText());
                        updateSendState(rt);
                        api.logging().logToOutput("[Chat] sendWorker.done(): task was paused, returning (isSendingHttp=" + rt.isSendingHttp + ")");
                        return;
                    }

                    String response = get();
                    api.logging().logToOutput("[Chat] sendWorker.done(): got response, len=" + (response != null ? response.length() : "null") + ", autonomous=" + continueAutonomously);
                    rt.requestCountInSession++;
                    if (response != null)
                    {
                        // 存储最近请求/响应用于弹窗查看
                        rt.lastRequestText = parsedRequest.requestText;
                        rt.lastResponseText = response;
                        rt.lastRequestHost = parsedRequest.host + ":" + parsedRequest.port;
                        rt.lastRequestSecure = parsedRequest.secure;

                        // 通知 AIRequestPanel
                        if (httpRequestCallback != null)
                        {
                            int statusCode = extractStatusCode(response);
                            httpRequestCallback.onRequestSent(
                                parsedRequest.requestText, response,
                                parsedRequest.host + ":" + parsedRequest.port,
                                extractMethodFromRequest(parsedRequest.requestText),
                                statusCode, durationMs);
                        }

                        String analysisPrompt = "我发送了以下 HTTP 请求并收到了响应，"
                            + "响应耗时 " + formatDuration(durationMs) + "。"
                            + "请分析响应内容，识别安全相关信息（状态码、头部、敏感信息泄露、错误信息等）。"
                            + "特别注意：如果这是一个时间盲注测试，请根据响应耗时判断是否存在漏洞。\n\n"
                            + "---请求---\n```http\n" + TextUtils.truncateWithSuffix(parsedRequest.requestText, 3000, "\n... [已截断]") + "\n```\n\n"
                            + "---响应---\n```http\n" + TextUtils.truncateWithSuffix(response, 4000, "\n... [已截断]") + "\n```";
                        if (continueAutonomously)
                        {
                            continueWithToolResult(buildAutonomousToolResultPrompt(parsedRequest.requestText, response, durationMs), rt);
                        }
                        else
                        {
                            sendPrompt(analysisPrompt, rt);
                        }
                    }
                    else
                    {
                        appendErrorMessage("请求已发送但未收到响应", rt);
                        if (rt.isActive()) statusLabel.setText(getStatusText());
                        if (continueAutonomously)
                        {
                            String noRespPrompt = "我发送了你构造的 HTTP 请求，但目标没有返回响应（可能超时或连接被重置）。\n\n"
                                + "请分析可能的原因，如果可能请生成修正后的请求（放在 ```http 代码块中），"
                                + "或者继续用其他方式分析。";
                            continueWithToolResult(noRespPrompt, rt);
                        }
                    }
                }
                catch (Exception e)
                {
                    String msg = e.getMessage();
                    if (e.getCause() != null) msg = e.getCause().getMessage();
                    appendErrorMessage("请求发送失败: " + msg, rt);
                    if (rt.isActive()) statusLabel.setText(getStatusText());
                    if (continueAutonomously)
                    {
                        // 将错误信息反馈给 AI，让它决定下一步而不是直接中断
                        String errorPrompt = "我尝试发送了你构造的 HTTP 请求，但请求失败了。"
                            + "错误信息: " + msg + "\n\n"
                            + "请分析失败原因，如果可能请生成修正后的请求（放在 ```http 代码块中），"
                            + "或者继续用其他方式分析。";
                        continueWithToolResult(errorPrompt, rt);
                    }
                }
                finally
                {
                    // 只有自己的 taskId 仍然是活跃任务时才清除标志
                    // 防止旧任务误清新任务的 isSendingHttp
                    if (rt.activeHttpTaskId == taskId)
                    {
                        rt.isSendingHttp = false;
                    }
                    if (rt.isActive()) statusLabel.setText(getStatusText());
                    updateSendState(rt);
                }
            }
        };
        sendWorker.execute();
    }

    private void pauseCurrentWork(String reason)
    {
        pauseCurrentHttpTask(reason);
        stopThinkingSpinner(activeRuntime);
        if (activeRuntime.isProcessing)
        {
            activeRuntime.provider.stopStreaming();

            // 检查队列：有排队消息则继续下一个，否则完全停止
            boolean hasMore;
            synchronized (activeRuntime.promptQueue)
            {
                hasMore = !activeRuntime.promptQueue.isEmpty();
            }
            if (hasMore)
            {
                appendSystemMessage(MSG_STOPPED_CONTINUE, activeRuntime);
            }
            else
            {
                appendSystemMessage(MSG_QUEUE_EMPTY, activeRuntime);
            }

            // finishStreaming 内部会调 processNextInQueue
            finishStreaming(false, activeRuntime);
        }
        else
        {
            // AI 空闲但队列中有消息 → 清空队列
            synchronized (activeRuntime.promptQueue)
            {
                int size = activeRuntime.promptQueue.size();
                if (size > 0)
                {
                    activeRuntime.promptQueue.clear();
                    appendSystemMessage("已清空 " + size + " 个排队任务", activeRuntime);
                    updateSendState(activeRuntime);
                }
            }
        }
    }

    private void pauseCurrentHttpTask(String reason)
    {
        if (!activeRuntime.isSendingHttp) return;
        activeRuntime.pausedHttpTasks.add(activeRuntime.activeHttpTaskId);
        activeRuntime.isSendingHttp = false;
        statusLabel.setText(getStatusText());
        updateSendState(activeRuntime);
        if (reason != null && !reason.isEmpty())
        {
            appendSystemMessage(reason, activeRuntime);
        }
    }

    private int extractStatusCode(String response)
    {
        if (response == null) return 0;
        try
        {
            String firstLine = response.split("\r?\n", 2)[0];
            String[] parts = firstLine.split("\\s+", 3);
            if (parts.length >= 2) return Integer.parseInt(parts[1]);
        }
        catch (Exception ignored) {}
        return 0;
    }

    private String formatDuration(long ms)
    {
        if (ms < 1000) return ms + "ms";
        if (ms < 60_000) return String.format("%.1fs", ms / 1000.0);
        return String.format("%.1fmin", ms / 60_000.0);
    }

    private String extractMethodFromRequest(String request)
    {
        if (request == null) return "GET";
        try
        {
            String firstLine = request.split("\r?\n", 2)[0];
            return firstLine.split("\\s+", 2)[0];
        }
        catch (Exception e) { return "GET"; }
    }

    /**
     * 确保对话中已注入工具能力指令（仅注入一次）。
     */
    private void ensureCapabilityInstruction(SessionRuntime rt)
    {
        for (ChatMessage msg : rt.conversationHistory)
        {
            if (msg.role() == ChatMessage.Role.SYSTEM && msg.content().contains("工具能力"))
            {
                return;
            }
        }
        rt.conversationHistory.add(ChatMessage.system(buildAutonomousSystemInstruction()));
    }

    private String buildAutonomousSystemInstruction()
    {
        return "你具备以下工具能力，可自主决定是否使用：\n"
            + "1. 发送 HTTP 请求：当你需要验证漏洞时，输出一个 ```http 代码块，"
            + "首行必须是 METHOD path HTTP/1.1，并包含 Host 头。一次只生成一个请求，"
            + "收到响应后会自动反馈给你。如果还需继续验证，再输出下一个请求；"
            + "否则给出最终结论。\n"
            + "2. 写入漏洞报告：仅当漏洞同时满足以下三个条件时才输出 ```vuln 代码块："
            + "可复现（你能成功重放并得到一致结果）、"
            + "可利用（存在明确的利用路径而非理论可能）、"
            + "有实际危害（能造成数据泄露、权限提升、业务破坏等真实影响）。"
            + "缺少任何一个条件都不要报告，在分析中说明即可。"
            + "单个请求最多只写入1个最有价值、证据最强、最接近根因的漏洞。"
            + "不要同时写“信息泄露”“配置不当”“安全头缺失”“版本暴露”等低价值泛化项。"
            + "如果同一请求既能归类为根因型漏洞(SQL注入/越权/未授权/RCE/SSRF/XSS等)又能归类为衍生现象(信息泄露/配置不当)，只保留根因型漏洞。"
            + "只有在响应中直接出现凭证/token/密钥/敏感文件/堆栈等高价值内容时，才允许写入信息泄露类漏洞。"
            + "报告格式为 JSON: {\"vulnType\":\"漏洞类型(如SQL注入/XSS/SSRF/越权等)\",\"severity\":\"高/中/低/严重\","
            + "\"confidence\":0.0-1.0,\"parameter\":\"参数\",\"evidence\":\"证据\","
            + "\"description\":\"详情\",\"suggestion\":\"修复建议\"}\n"
            + "不要生成破坏性请求(DROP/DELETE/TRUNCATE/rm -rf)。"
            + "不要解释工具调用机制，不要要求用户手动操作。";
    }

    private void maybeExecuteAutonomousRequest(String assistantText, SessionRuntime rt)
    {
        String request = extractFirstHttpRequestBlock(assistantText);
        if (request == null)
        {
            if (api != null) api.logging().logToOutput("[Chat] maybeExecuteAutonomousRequest: no HTTP block found, response preview: "
                + (assistantText != null && assistantText.length() > 200 ? assistantText.substring(0, 200) + "..." : assistantText));
            return;
        }

        if (api != null) api.logging().logToOutput("[Chat] maybeExecuteAutonomousRequest: found HTTP block (" + request.length() + " chars), calling executeSendAndAnalyze");
        appendSystemMessage("AI 自主发送请求", rt);
        executeSendAndAnalyze(request, false, true, rt);
    }

    private String extractFirstHttpRequestBlock(String markdown)
    {
        if (markdown == null || markdown.isEmpty()) return null;
        int pos = 0;
        while (pos < markdown.length())
        {
            int open = markdown.indexOf("```", pos);
            if (open < 0) return extractRawHttpRequest(markdown);
            int lineEnd = markdown.indexOf('\n', open + 3);
            if (lineEnd < 0) return extractRawHttpRequest(markdown);
            int close = markdown.indexOf("```", lineEnd + 1);
            if (close < 0) return extractRawHttpRequest(markdown);

            String lang = markdown.substring(open + 3, lineEnd).trim().toLowerCase(Locale.ROOT);
            String code = markdown.substring(lineEnd + 1, close);
            if (lang.isEmpty() || lang.contains("http"))
            {
                try
                {
                    parseAsHttpRequest(code);
                    return code;
                }
                catch (Exception e)
                {
                    if (api != null) api.logging().logToOutput("[Chat] extractFirstHttpRequestBlock: code block lang='" + lang + "' failed to parse as HTTP: " + e.getMessage());
                }
            }
            pos = close + 3;
        }
        return extractRawHttpRequest(markdown);
    }

    private String extractRawHttpRequest(String text)
    {
        String normalized = normalizeHttpNewlines(text);
        String[] methods = {"GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS ", "TRACE ", "CONNECT "};
        int start = -1;
        for (String method : methods)
        {
            int idx = normalized.indexOf(method);
            if (idx >= 0 && (start < 0 || idx < start)) start = idx;
        }
        if (start < 0) return null;

        String candidate = normalized.substring(start).trim();
        try
        {
            parseAsHttpRequest(candidate);
            return candidate;
        }
        catch (Exception e)
        {
            return null;
        }
    }

    private String buildAutonomousToolResultPrompt(String requestText, String responseText, long durationMs)
    {
        return "工具执行结果：HTTP 请求已发送并收到响应，响应耗时 " + formatDuration(durationMs) + "。\n\n"
            + buildHttpExchangeSummary(requestText, responseText, durationMs)
            + "\n\n请基于以上结果继续安全验证：\n"
            + "1. 判断当前响应是否支持或否定用户关注的漏洞假设。\n"
            + "2. 明确列出证据，包括状态码、关键响应头、响应体中的关键片段或差异。"
            + "如果是时间盲注测试，请根据响应耗时判断是否存在漏洞。\n"
            + "3. 如果还需要下一步验证，只输出一个新的完整 HTTP 请求代码块，不要输出多个候选。\n"
            + "4. 如果已经足够，请输出最终结论、风险等级、置信度、复现要点和修复建议。\n\n"
            + "已发送请求:\n```http\n" + TextUtils.truncateWithSuffix(requestText, 5000, "\n... [已截断]") + "\n```\n\n"
            + "收到响应:\n```http\n" + TextUtils.truncateWithSuffix(responseText, 7000, "\n... [已截断]") + "\n```";
    }

    private String buildHttpExchangeSummary(String requestText, String responseText, long durationMs)
    {
        String requestLine = firstLine(normalizeHttpNewlines(requestText));
        String normalizedResponse = normalizeHttpNewlines(responseText);
        String statusLine = firstLine(normalizedResponse);
        String headers = headerPart(normalizedResponse);
        String body = bodyPart(normalizedResponse);

        StringBuilder summary = new StringBuilder();
        summary.append("结构化摘要 (响应耗时: ").append(formatDuration(durationMs)).append("):\n");
        summary.append("- 请求行: ").append(requestLine).append("\n");
        summary.append("- 响应状态: ").append(statusLine.isEmpty() ? "(无状态行)" : statusLine).append("\n");
        summary.append("- Content-Type: ").append(headerValue(headers, "content-type")).append("\n");
        summary.append("- Content-Length: ").append(headerValue(headers, "content-length")).append("\n");
        summary.append("- Server: ").append(headerValue(headers, "server")).append("\n");
        summary.append("- Set-Cookie: ").append(headerValue(headers, "set-cookie")).append("\n");
        summary.append("- Location: ").append(headerValue(headers, "location")).append("\n");
        summary.append("- 响应体长度(字符): ").append(body.length()).append("\n");
        summary.append("- 响应体预览:\n");
        summary.append(TextUtils.truncateWithSuffix(compactBodyPreview(body), 1500, "\n... [已截断]"));
        return summary.toString();
    }

    private String firstLine(String text)
    {
        if (text == null || text.isEmpty()) return "";
        int idx = text.indexOf("\r\n");
        return idx >= 0 ? text.substring(0, idx) : text;
    }

    private String headerPart(String httpMessage)
    {
        if (httpMessage == null) return "";
        int idx = httpMessage.indexOf("\r\n\r\n");
        return idx >= 0 ? httpMessage.substring(0, idx) : httpMessage;
    }

    private String bodyPart(String httpMessage)
    {
        if (httpMessage == null) return "";
        int idx = httpMessage.indexOf("\r\n\r\n");
        return idx >= 0 ? httpMessage.substring(idx + 4) : "";
    }

    private String headerValue(String headers, String headerName)
    {
        if (headers == null || headers.isEmpty()) return "(无)";
        String prefix = headerName.toLowerCase(Locale.ROOT) + ":";
        StringBuilder values = new StringBuilder();
        for (String line : headers.split("\r\n"))
        {
            if (line.toLowerCase(Locale.ROOT).startsWith(prefix))
            {
                if (values.length() > 0) values.append(" | ");
                values.append(line.substring(line.indexOf(':') + 1).trim());
            }
        }
        return values.length() == 0 ? "(无)" : values.toString();
    }

    private String compactBodyPreview(String body)
    {
        if (body == null || body.isEmpty()) return "(空)";
        return body.replace('\t', ' ')
                   .replaceAll("[ ]{2,}", " ")
                   .replaceAll("(\\r\\n){3,}", "\r\n\r\n")
                   .trim();
    }

    private void stopAutonomousMode(String reason)
    {
        if (reason != null && !reason.isEmpty())
        {
            appendSystemMessage(reason, activeRuntime);
        }
    }

    /**
     * 后台 session 专用：从 AI 响应中提取 vuln 代码块，直接写入 AuditLogger。
     * 不使用 maybeExtractVulnReport（它写主 UI 的 messageLog）。
     */
    private void extractVulnReportForBackground(String assistantText, String host, SessionRuntime rt)
    {
        if (assistantText == null || auditLogger == null) return;
        java.util.List<ai.burp.model.VulnReport> candidates = new java.util.ArrayList<>();
        int pos = 0;
        while (pos < assistantText.length())
        {
            int open = assistantText.indexOf("```", pos);
            if (open < 0) break;
            int lineEnd = assistantText.indexOf('\n', open + 3);
            if (lineEnd < 0) break;
            int close = assistantText.indexOf("```", lineEnd + 1);
            if (close < 0) break;
            String lang = assistantText.substring(open + 3, lineEnd).trim().toLowerCase(Locale.ROOT);
            if (lang.equals("vuln"))
            {
                String json = assistantText.substring(lineEnd + 1, close).trim();
                try
                {
                    Map<String, Object> m = AiResponseParser.parseFirstObject(json);
                    if (m != null && !m.isEmpty())
                    {
                        ai.burp.model.VulnReport vr = buildVulnReportFromMap(m, host, host, rt);
                        if (vr != null && VulnFindingPolicy.shouldKeep(vr))
                        {
                            candidates.add(vr);
                        }
                    }
                }
                catch (Exception ignored) {}
            }
            pos = close + 3;
        }

        java.util.List<ai.burp.model.VulnReport> selected = VulnFindingPolicy.keepTopOnePerRequest(candidates);
        for (ai.burp.model.VulnReport report : selected)
        {
            auditLogger.logVulnReport(report);
            if (vulnReportCallback != null)
            {
                SwingUtilities.invokeLater(vulnReportCallback);
            }
        }
    }

    /**
     * 从 AI 响应中提取 ```vuln 代码块并写入漏洞报告。
     * AI 确认漏洞后自主输出此格式，系统自动归档到 ReportPanel。
     */
    private void maybeExtractVulnReport(String assistantText, SessionRuntime rt)
    {
        if (assistantText == null || auditLogger == null) return;

        // 查找所有 ```vuln 代码块
        java.util.List<ai.burp.model.VulnReport> candidates = new java.util.ArrayList<>();
        int pos = 0;
        while (pos < assistantText.length())
        {
            int open = assistantText.indexOf("```", pos);
            if (open < 0) break;
            int lineEnd = assistantText.indexOf('\n', open + 3);
            if (lineEnd < 0) break;
            int close = assistantText.indexOf("```", lineEnd + 1);
            if (close < 0) break;

            String lang = assistantText.substring(open + 3, lineEnd).trim().toLowerCase(Locale.ROOT);
            if (lang.equals("vuln"))
            {
                String json = assistantText.substring(lineEnd + 1, close).trim();
                ai.burp.model.VulnReport report = parseVulnReport(json, rt.lastRequestHost, rt);
                if (report != null)
                {
                    candidates.add(report);
                }
            }
            pos = close + 3;
        }

        java.util.List<ai.burp.model.VulnReport> selected = VulnFindingPolicy.keepTopOnePerRequest(candidates);
        for (ai.burp.model.VulnReport report : selected)
        {
            writeVulnReport(report, rt);
        }
    }

    /**
     * 解析 JSON 并写入 VulnReport 到 AuditLogger。
     */
    private void writeVulnReport(String json, SessionRuntime rt)
    {
        try
        {
            ai.burp.model.VulnReport report = parseVulnReport(json, rt.lastRequestHost, rt);
            if (report == null)
            {
                return;
            }
            writeVulnReport(report, rt);
        }
        catch (Exception e)
        {
            appendSystemMessage("漏洞报告解析失败: " + e.getMessage(), rt);
            if (api != null) api.logging().logToError("[AI] Vuln report parse error: " + e.getMessage());
        }
    }

    private ai.burp.model.VulnReport parseVulnReport(String json, String fallbackHost, SessionRuntime rt)
    {
        try
        {
            Map<String, Object> m = AiResponseParser.parseFirstObject(json);
            if (m == null || m.isEmpty()) return null;
            ai.burp.model.VulnReport report = buildVulnReportFromMap(m, null, fallbackHost, rt);
            if (report == null) return null;
            if (!VulnFindingPolicy.shouldKeep(report))
            {
                appendSystemMessage("已忽略低价值或证据不足的漏洞项: " + report.getVulnType(), rt);
                return null;
            }
            return report;
        }
        catch (Exception e)
        {
            throw e;
        }
    }

    private ai.burp.model.VulnReport buildVulnReportFromMap(Map<String, Object> m, String preferredHost, String fallbackHost, SessionRuntime rt)
    {
        if (m == null || m.isEmpty()) return null;
        // 兼容新旧字段名: vulnType(标准) / name(旧版)
        String vulnType = AiResponseParser.getString(m, "vulnType");
        if (vulnType.isEmpty()) vulnType = AiResponseParser.getString(m, "name");
        if (vulnType.isEmpty()) return null;

        ai.burp.model.VulnReport vr = new ai.burp.model.VulnReport();
        vr.setVulnType(vulnType);
        vr.setSeverity(ai.burp.model.VulnReport.Severity.fromString(
            AiResponseParser.getString(m, "severity")));
        vr.setParameter(AiResponseParser.getString(m, "parameter"));
        vr.setEvidence(AiResponseParser.getString(m, "evidence"));
        // 兼容新旧字段名: description(标准) / detail(旧版)
        String desc = AiResponseParser.getString(m, "description");
        if (desc.isEmpty()) desc = AiResponseParser.getString(m, "detail");
        vr.setDescription(desc);
        // 兼容新旧字段名: suggestion(标准) / remediation(旧版)
        String sugg = AiResponseParser.getString(m, "suggestion");
        if (sugg.isEmpty()) sugg = AiResponseParser.getString(m, "remediation");
        vr.setSuggestion(sugg);
        vr.setConfidence(AiResponseParser.getDouble(m, "confidence", 0.5));
        vr.setVerifyStatus(ai.burp.model.VulnReport.VerifyStatus.CONFIRMED);
        vr.setCategory("AI验证");
        if (preferredHost != null && !preferredHost.isEmpty())
        {
            vr.setHost(preferredHost);
        }
        applyJsonEvidenceFields(vr, m);
        applyLastExchangeFallback(vr, fallbackHost, rt);
        return vr;
    }

    private void writeVulnReport(ai.burp.model.VulnReport vr, SessionRuntime rt)
    {
        try
        {
            // 去重：同类型+同参数的报告只保留最新的一条
            String dedupKey = vr.getVulnType() + "|" + vr.getParameter();
            if (rt.reportedVulnKeys.contains(dedupKey))
            {
                if (api != null) api.logging().logToOutput("[Chat] writeVulnReport: duplicate skipped: " + dedupKey);
                return;
            }
            rt.reportedVulnKeys.add(dedupKey);

            auditLogger.logVulnReport(vr);
            appendSystemMessage("已写入漏洞报告: [" + vr.getSeverity().label() + "] " + vr.getVulnType(), rt);

            // 通知 ReportPanel 刷新（已在 EDT 上，直接调用）
            if (vulnReportCallback != null)
            {
                vulnReportCallback.run();
            }
        }
        catch (Exception e)
        {
            appendSystemMessage("漏洞报告写入失败: " + e.getMessage(), rt);
            if (api != null) api.logging().logToError("[AI] Vuln report parse error: " + e.getMessage());
        }
    }

    private void applyJsonEvidenceFields(ai.burp.model.VulnReport vr, Map<String, Object> m)
    {
        String originalRequest = AiResponseParser.getString(m, "originalRequest");
        String reproduceRequest = AiResponseParser.getString(m, "reproduceRequest");
        String verifyRequest = AiResponseParser.getString(m, "verifyRequest");
        String originalResponse = AiResponseParser.getString(m, "originalResponse");
        String testResponse = AiResponseParser.getString(m, "testResponse");
        String verificationDetail = AiResponseParser.getString(m, "verificationDetail");
        String method = AiResponseParser.getString(m, "method");
        String url = AiResponseParser.getString(m, "url");
        String host = AiResponseParser.getString(m, "host");

        if (!method.isEmpty()) vr.setMethod(method);
        if (!url.isEmpty()) vr.setUrl(url);
        if (!host.isEmpty()) vr.setHost(host);
        if (!originalRequest.isEmpty()) vr.setOriginalRequest(originalRequest);
        if (!reproduceRequest.isEmpty()) vr.setReproduceRequest(reproduceRequest);
        else if (!verifyRequest.isEmpty()) vr.setReproduceRequest(verifyRequest);
        if (!originalResponse.isEmpty()) vr.setOriginalResponse(originalResponse);
        if (!testResponse.isEmpty()) vr.setTestResponse(testResponse);
        if (!verificationDetail.isEmpty()) vr.setVerificationDetail(verificationDetail);
    }

    private void applyLastExchangeFallback(ai.burp.model.VulnReport vr, String fallbackHost, SessionRuntime rt)
    {
        if (rt != null)
        {
            if ((vr.getOriginalRequest() == null || vr.getOriginalRequest().isEmpty()) && rt.lastRequestText != null)
            {
                vr.setOriginalRequest(rt.lastRequestText);
            }
            if ((vr.getOriginalResponse() == null || vr.getOriginalResponse().isEmpty()) && rt.lastResponseText != null)
            {
                vr.setOriginalResponse(rt.lastResponseText);
            }
        }
        if ((vr.getHost() == null || vr.getHost().isEmpty()))
        {
            vr.setHost(rt != null && rt.lastRequestHost != null ? rt.lastRequestHost : fallbackHost);
        }

        if (vr.getOriginalRequest() != null && !vr.getOriginalRequest().isEmpty())
        {
            try
            {
                String firstLine = vr.getOriginalRequest().split("\r?\n", 2)[0];
                String[] parts = firstLine.split("\\s+");
                if ((vr.getMethod() == null || vr.getMethod().isEmpty()) && parts.length >= 1)
                {
                    vr.setMethod(parts[0]);
                }
                if ((vr.getUrl() == null || vr.getUrl().isEmpty()) && parts.length >= 2)
                {
                    String path = parts[1];
                    // HTTPS 判定：URL/路径前缀 + Host端口443 + 会话上下文(rt.lastRequestSecure)
                    boolean https = path.startsWith("https://")
                        || vr.getOriginalRequest().contains("https://");
                    if (!https)
                    {
                        String hostHeader = extractHostFromNormalizedRequest(
                            normalizeHttpNewlines(vr.getOriginalRequest()));
                        if (hostHeader != null && hostHeader.endsWith(":443")) https = true;
                    }
                    if (!https && rt != null && rt.lastRequestSecure) https = true;
                    String scheme = https ? "https" : "http";
                    String host = vr.getHost() != null ? vr.getHost() : "unknown";
                    // host 可能是 "host:port" 格式，URL 中去掉端口避免重复
                    vr.setUrl(path.startsWith("http://") || path.startsWith("https://")
                        ? path : scheme + "://" + host + path);
                    vr.setSecure(https);
                }
            }
            catch (Exception ignored) {}
        }
    }

    // ==================== HTTP Viewer ====================

    /**
     * 弹窗显示最近一次请求/响应详情。
     */
    private void showLastHttpDetail()
    {
        String req = activeRuntime.lastRequestText;
        String resp = activeRuntime.lastResponseText;

        if (req == null && resp == null)
        {
            appendSystemMessage("暂无已发送的请求记录", activeRuntime);
            return;
        }

        JDialog dialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(this),
            "请求/响应详情" + (activeRuntime.lastRequestHost != null ? " - " + activeRuntime.lastRequestHost : ""), false);
        dialog.setLayout(new BorderLayout(4, 4));

        // 工具栏
        JPanel dlgToolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        JButton copyReqBtn = new JButton("复制请求");
        UIStyle.compactButton(copyReqBtn);
        dlgToolbar.add(copyReqBtn);

        JButton copyRespBtn = new JButton("复制响应");
        UIStyle.compactButton(copyRespBtn);
        dlgToolbar.add(copyRespBtn);

        JButton viewAllBtn = new JButton("查看全部请求");
        UIStyle.compactButton(viewAllBtn);
        viewAllBtn.setToolTipText("跳转到 AI 请求标签页查看所有历史");
        dlgToolbar.add(viewAllBtn);

        dialog.add(dlgToolbar, BorderLayout.NORTH);

        // Request / Response 左右分栏
        JTextArea reqArea = new JTextArea(req != null ? req : "(无)");
        UIStyle.textArea(reqArea);
        reqArea.setLineWrap(false);
        reqArea.setTabSize(4);
        reqArea.setEditable(false);

        JTextArea respArea = new JTextArea(resp != null ? resp : "(无响应)");
        UIStyle.textArea(respArea);
        respArea.setLineWrap(false);
        respArea.setTabSize(4);
        respArea.setEditable(false);

        // Request 面板
        JPanel reqPanel = new JPanel(new BorderLayout(2, 2));
        JLabel reqTitle = new JLabel("  Request");
        reqTitle.setFont(reqTitle.getFont().deriveFont(Font.BOLD, 12f));
        reqPanel.add(reqTitle, BorderLayout.NORTH);
        reqPanel.add(UIStyle.scroll(reqArea), BorderLayout.CENTER);

        // Response 面板
        JPanel respPanel = new JPanel(new BorderLayout(2, 2));
        JLabel respTitle = new JLabel("  Response");
        respTitle.setFont(respTitle.getFont().deriveFont(Font.BOLD, 12f));
        respPanel.add(respTitle, BorderLayout.NORTH);
        respPanel.add(UIStyle.scroll(respArea), BorderLayout.CENTER);

        JSplitPane detailSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, reqPanel, respPanel);
        detailSplit.setResizeWeight(0.5);
        detailSplit.setDividerSize(4);

        dialog.add(detailSplit, BorderLayout.CENTER);

        // 按钮事件
        copyReqBtn.addActionListener(e -> copyToClipboard(reqArea.getText()));
        copyRespBtn.addActionListener(e -> copyToClipboard(respArea.getText()));
        viewAllBtn.addActionListener(e -> {
            dialog.dispose();
            if (tabSwitchCallback != null) tabSwitchCallback.switchToAiRequest();
        });

        dialog.setSize(900, 500);
        dialog.setLocationRelativeTo(this);
        dialog.setVisible(true);
    }

    /**
     * 复制文本到系统剪贴板。
     */
    private void copyToClipboard(String text)
    {
        java.awt.datatransfer.StringSelection selection = new java.awt.datatransfer.StringSelection(text);
        java.awt.Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, null);
    }

    // ==================== 从流量分析创建会话 ====================

    /**
     * 从流量分析结果创建新会话，注入分析摘要作为上下文。
     * 用户可以在新会话中继续追问、验证漏洞、深入分析。
     */
    public void createSessionFromAnalysis(String title, String analysisContext)
    {
        // 每个 SessionRuntime 有独立 provider，新建分析会话不中断旧会话
        if (activeRuntime.isProcessing)
        {
            stopThinkingSpinner(activeRuntime);
        }

        // 保存当前会话
        if (currentSessionIndex >= 0 && currentSessionIndex < sessions.size())
        {
            sessions.set(currentSessionIndex, snapshotCurrentSession());
        }

        // 创建新会话（带独立 runtime，不清除旧 session 数据）
        sessionCounter++;
        ChatSession newSess = new ChatSession(
            "sess-" + sessionCounter, title,
            Collections.emptyList(), "", Collections.emptyMap(),
            0, null, null, null, false);
        newSess.runtime = new SessionRuntime(newSess.id);
        sessions.add(newSess);

        activeRuntime = newSess.runtime;
        currentSessionIndex = sessions.size() - 1;

        // 更新下拉框
        refreshSessionComboBox();

        chatDisplay.setText("");

        // 注入系统上下文
        String systemMsg = "你是专业的 Web 安全审计助手。以下是刚才流量分析的发现，用户可以基于这些结果继续对话："
            + "追问某个漏洞的细节、让 AI 构造验证请求、分析攻击链、生成修复建议等。\n\n"
            + analysisContext;

        synchronized (activeRuntime.conversationHistory)
        {
            activeRuntime.conversationHistory.add(ChatMessage.system(systemMsg));
        }

        appendSystemMessage("已加载流量分析结果到当前会话。你可以继续追问、验证漏洞或进行更深入的分析。", activeRuntime);
        appendSystemMessage("提示：你可以让 AI 构造 HTTP 请求验证漏洞，或使用「发送并分析」功能自动发送验证请求。", activeRuntime);

        // 自动跳转到此会话
    }

    public String createBackgroundAnalysisSession(String title, String analysisContext)
    {
        String sessionId = "sess-" + (++sessionCounter);
        String systemMsg = "你是专业的 Web 安全审计助手。以下是当前批次的流量分析上下文。"
            + "该批次已提交给 AI 分析，结果会继续追加到本会话。\n\n"
            + analysisContext;

        List<ChatMessage> history = new ArrayList<>();
        history.add(ChatMessage.system(systemMsg));

        StringBuilder html = new StringBuilder();
        html.append(renderSystemMessageHtml("已创建批次分析会话，等待 AI 返回结果。"));
        html.append(renderSystemMessageHtml("该会话会持续追加本批次的分析发现和后续验证线索。"));
        html.append(renderSystemMessageHtml(systemMsg));

        ChatSession session = new ChatSession(
            sessionId, title, history, html.toString(), Collections.emptyMap(),
            0, null, null, null, false);
        sessions.add(session);
        refreshSessionComboBox();
        return sessionId;
    }

    /**
     * 按 host 找到或创建对应 session，发送 prompt。
     * - 同一 session（当前活跃）→ 使用主队列排队
     * - 不同 session → 后台并行执行，互不阻塞
     */
    public void sendPromptForHost(String host, String prompt)
    {
        sendPromptForHost(host, prompt, null, null, null, false);
    }

    /**
     * 按 host 找到或创建对应 session，发送 prompt（带 HTTP 上下文）。
     * 上下文数据会设置到目标 session 的 runtime，避免跨 session 串写。
     */
    private void sendPromptForHost(String host, String prompt,
                                    String reqText, String respText, String reqHost,
                                    boolean secure)
    {
        if (host == null || host.isEmpty())
        {
            // 无 host 时设置到 activeRuntime（当前会话）
            if (reqText != null)
            {
                activeRuntime.lastRequestText = reqText;
                activeRuntime.lastResponseText = respText;
                activeRuntime.lastRequestHost = reqHost;
                activeRuntime.lastRequestSecure = secure;
            }
            sendPrompt(prompt);
            return;
        }

        // 找到已有的 host session
        int hostSessionIdx = -1;
        for (int i = 0; i < sessions.size(); i++)
        {
            if (sessions.get(i).id.startsWith("host-") && sessions.get(i).title.equals(host))
            {
                hostSessionIdx = i;
                break;
            }
        }

        // 没有则创建或复用空 session
        if (hostSessionIdx < 0)
        {
            // 检查当前活跃 session 是否为空（无用户对话），是则直接接管
            if (currentSessionIndex >= 0 && currentSessionIndex < sessions.size()
                && !hasUserMessage(sessions.get(currentSessionIndex).history)
                && !sessions.get(currentSessionIndex).id.startsWith("host-"))
            {
                // 复用空 session：改 id 和 title 为 host
                ChatSession empty = sessions.get(currentSessionIndex);
                sessionCounter++;
                ChatSession reused = new ChatSession(
                    "host-" + sessionCounter, host,
                    empty.history, empty.messageLogHtml, empty.codeBlocks,
                    empty.requestCount, empty.lastReqText, empty.lastRespText, empty.lastReqHost,
                    empty.lastReqSecure);
                reused.runtime = empty.runtime; // 保留已有的 runtime 引用
                sessions.set(currentSessionIndex, reused);
                hostSessionIdx = currentSessionIndex;
                // 同步 conversationHistory 的 id 引用（如果有必要）
                refreshSessionComboBox();
            }
            else
            {
                sessionCounter++;
                String sessionId = "host-" + sessionCounter;
                ChatSession newSess = new ChatSession(
                    sessionId, host,
                    Collections.emptyList(), "", Collections.emptyMap(),
                    0, null, null, null, false);
                sessions.add(newSess);
                hostSessionIdx = sessions.size() - 1;
                refreshSessionComboBox();
            }
        }

        // 确定目标 session 的 runtime，将 HTTP 上下文设置到正确的 runtime 上
        ChatSession targetSession = sessions.get(hostSessionIdx);
        SessionRuntime targetRt;
        if (hostSessionIdx == currentSessionIndex)
        {
            targetRt = activeRuntime;
        }
        else
        {
            // 后台 session 可能还没有 runtime，先确保创建
            if (targetSession.runtime == null)
            {
                targetSession.runtime = new SessionRuntime(targetSession.id);
                synchronized (targetSession.runtime.conversationHistory)
                {
                    targetSession.runtime.conversationHistory.addAll(targetSession.history);
                }
                targetSession.runtime.messageLog.append(targetSession.messageLogHtml);
                targetSession.runtime.codeBlockCopies.putAll(targetSession.codeBlocks);
                targetSession.runtime.requestCountInSession = targetSession.requestCount;
            }
            targetRt = targetSession.runtime;
        }

        // 将上下文设置到目标 session 的 runtime（而非 activeRuntime）
        if (reqText != null)
        {
            targetRt.lastRequestText = reqText;
            targetRt.lastResponseText = respText;
            targetRt.lastRequestHost = reqHost;
            targetRt.lastRequestSecure = secure;
        }

        // 如果是当前活跃 session → 切换后用主队列排队（同一 session 串行）
        if (hostSessionIdx == currentSessionIndex)
        {
            injectHostContextSummary(host, activeRuntime);
            sendPrompt(prompt);
            return;
        }

        // 不同 session → 后台并行执行
        processSessionInBackground(hostSessionIdx, prompt, host);
    }

    /**
     * 带HTTP上下文的发送方法。右键菜单调用时使用，确保 lastRequestText/lastResponseText
     * 在 AI 分析生成漏洞报告前就已设置，使报告中的可复现请求不为空。
     * 注意：上下文数据会被设置到目标session的runtime，而非当前活跃session，
     * 避免并发多session时请求/响应数据跨session串写。
     */
    public void sendPromptForHostWithContext(String host, String prompt,
                                              String reqText, String respText, String reqHost,
                                              boolean secure)
    {
        sendPromptForHost(host, prompt, reqText, respText, reqHost, secure);
    }

    /**
     * 后台并行处理 session 的 AI 请求。
     * 使用 session 独立 runtime + 流式 executeAiRequest，与主 UI 完全一致。
     */
    private void processSessionInBackground(int sessionIdx, String prompt, String host)
    {
        ChatSession session = sessions.get(sessionIdx);
        String sessionId = session.id;

        // 确保 session 有独立 runtime
        if (session.runtime == null)
        {
            session.runtime = new SessionRuntime(sessionId);
            // 从快照加载已有数据到 runtime
            synchronized (session.runtime.conversationHistory)
            {
                session.runtime.conversationHistory.addAll(session.history);
            }
            session.runtime.messageLog.append(session.messageLogHtml);
            session.runtime.codeBlockCopies.putAll(session.codeBlocks);
            session.runtime.requestCountInSession = session.requestCount;
        }
        SessionRuntime rt = session.runtime;

        // 如果该 session 已在处理中，入队等待（不丢弃）
        if (rt.isProcessing || rt.isSendingHttp)
        {
            synchronized (rt.promptQueue)
            {
                rt.promptQueue.add(prompt);
                int size = rt.promptQueue.size();
                appendSystemMessage(host + " 正在分析中，第 " + size + " 个请求已排队", activeRuntime);
            }
            return;
        }

        // 注入能力指令和上下文摘要
        synchronized (rt.conversationHistory)
        {
            ensureCapabilityInstruction(rt);

            // 注入 host 上下文摘要
            if (host != null && !host.isEmpty())
            {
                int userMsgCount = 0;
                int vulnCount = 0;
                for (ChatMessage msg : rt.conversationHistory)
                {
                    if (msg.role() == ChatMessage.Role.USER) userMsgCount++;
                    if (msg.role() == ChatMessage.Role.SYSTEM && msg.content().contains("已写入漏洞报告")) vulnCount++;
                }
                if (userMsgCount > 0)
                {
                    String summary = "[上下文提示] 当前会话已对 " + host + " 进行过 " + userMsgCount + " 次分析";
                    if (vulnCount > 0) summary += "，已确认 " + vulnCount + " 个漏洞";
                    summary += "。请参考之前的分析结论，避免重复报告相同问题。";
                    rt.conversationHistory.add(ChatMessage.system(summary));
                }
            }

            rt.conversationHistory.add(ChatMessage.user(prompt));
        }

        // 更新 messageLog 显示用户消息
        appendUserMessage(prompt, rt);

        // 开始流式处理
        rt.isProcessing = true;
        rt.aiRetryCount = 0;
        updateSendState(rt);
        executeAiRequest(rt);

        // 自动切换到目标 session 显示（如果当前没有正在进行的 AI 处理）
        if (!activeRuntime.isProcessing && !activeRuntime.isSendingHttp)
        {
            if (currentSessionIndex >= 0 && currentSessionIndex < sessions.size())
            {
                sessions.set(currentSessionIndex, snapshotCurrentSession());
            }
            currentSessionIndex = sessionIdx;
            restoreFromSnapshot(sessions.get(sessionIdx));
            refreshSessionComboBox();
        }
        else
        {
            // 当前正在处理中，仅更新 combo box 让用户看到新 session
            refreshSessionComboBox();
        }
    }

    /**
     * 为 host session 注入历史分析摘要，让 AI 了解之前的发现。
     * 仅在有历史消息时注入，避免每次都重复。
     */
    private void injectHostContextSummary(String host, SessionRuntime rt)
    {
        synchronized (rt.conversationHistory)
        {
            int userMsgCount = 0;
            int vulnCount = 0;
            for (ChatMessage msg : rt.conversationHistory)
            {
                if (msg.role() == ChatMessage.Role.USER) userMsgCount++;
                if (msg.role() == ChatMessage.Role.SYSTEM
                    && msg.content().contains("已写入漏洞报告")) vulnCount++;
            }

            // 有历史分析时注入摘要
            if (userMsgCount > 0)
            {
                String summary = "[上下文提示] 当前会话已对 " + host + " 进行过 "
                    + userMsgCount + " 次分析";
                if (vulnCount > 0)
                {
                    summary += "，已确认 " + vulnCount + " 个漏洞";
                }
                summary += "。请参考之前的分析结论，避免重复报告相同问题。";
                rt.conversationHistory.add(ChatMessage.system(summary));
                appendSystemMessage(summary, rt);
            }
        }
    }

    /**
     * 激活指定 ID 的会话（切换到该会话）。
     */
    public void activateSession(String sessionId)
    {
        for (int i = 0; i < sessions.size(); i++)
        {
            if (sessions.get(i).id.equals(sessionId))
            {
                switchToSession(i);
                return;
            }
        }
    }

    /**
     * 为已存在的 session 在后台发送 AI 请求。
     * 用于流量分析等场景：创建独立 provider，不干扰主 UI 队列和其他 session。
     */
    public void sendBackgroundPromptForSession(String sessionId, String prompt)
    {
        if (sessionId == null || sessionId.isEmpty()) return;

        int idx = -1;
        for (int i = 0; i < sessions.size(); i++)
        {
            if (sessions.get(i).id.equals(sessionId)) { idx = i; break; }
        }
        if (idx < 0) return;

        // 复用 processSessionInBackground 的后台逻辑
        // 不需要 host 参数（非 host session），传空
        processSessionInBackground(idx, prompt, "");
    }

    public void appendAnalysisUpdateToSession(String sessionId, String updateText)
    {
        if (sessionId == null || sessionId.isEmpty())
        {
            return;
        }

        int targetIndex = -1;
        for (int i = 0; i < sessions.size(); i++)
        {
            if (sessions.get(i).id.equals(sessionId))
            {
                targetIndex = i;
                break;
            }
        }
        if (targetIndex < 0)
        {
            return;
        }

        ChatSession existing = sessions.get(targetIndex);
        if (targetIndex == currentSessionIndex)
        {
            synchronized (activeRuntime.conversationHistory)
            {
                activeRuntime.conversationHistory.add(ChatMessage.system(updateText));
            }
            activeRuntime.messageLog.append(renderSystemMessageHtml(updateText));
            trimMessageLogIfNeeded(activeRuntime);
            ChatSession updated = snapshotCurrentSession();
            updated.title = existing.title;
            sessions.set(targetIndex, updated);
            refreshDisplay(activeRuntime);
        }
        else
        {
            // 非当前 session：写入 runtime（如果有）或快照
            if (existing.runtime != null)
            {
                SessionRuntime rt = existing.runtime;
                synchronized (rt.conversationHistory)
                {
                    rt.conversationHistory.add(ChatMessage.system(updateText));
                }
                rt.messageLog.append(renderSystemMessageHtml(updateText));
                trimMessageLogIfNeeded(rt);
            }
            else
            {
                List<ChatMessage> history = new ArrayList<>(existing.history);
                history.add(ChatMessage.system(updateText));

                String updatedHtml = existing.messageLogHtml + renderSystemMessageHtml(updateText);
                ChatSession updated = new ChatSession(
                    existing.id, existing.title, history, updatedHtml, existing.codeBlocks,
                    existing.requestCount, existing.lastReqText, existing.lastRespText, existing.lastReqHost,
                    existing.lastReqSecure);
                sessions.set(targetIndex, updated);
            }
        }
        refreshSessionComboBox();
    }

    /**
     * Called when the extension is being unloaded.
     * Cancels any in-progress requests and clears state.
     */
    public void cleanup()
    {
        activeRuntime.isProcessing = false;
        activeRuntime.isSendingHttp = false;
        activeRuntime.requestCountInSession = 0;
        // 取消所有后台并行任务
        synchronized (backgroundWorkers)
        {
            for (SwingWorker<String, Void> w : backgroundWorkers.values())
            {
                w.cancel(true);
            }
            backgroundWorkers.clear();
        }
        synchronized (activeRuntime.conversationHistory)
        {
            activeRuntime.conversationHistory.clear();
        }
        sessions.clear();
        currentSessionIndex = -1;
    }
}
