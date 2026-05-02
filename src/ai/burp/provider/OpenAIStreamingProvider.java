package ai.burp.provider;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;

import ai.burp.config.ExtensionConfig;
import ai.burp.model.ChatMessage;
import ai.burp.scanner.FullVulnDatabase;
import ai.burp.util.SimpleJson;
import burp.api.montoya.MontoyaApi;

/**
 * OpenAI兼容API的流式实现。
 * 支持SSE (Server-Sent Events) 流式输出。
 */
public class OpenAIStreamingProvider implements StreamingAIProvider
{
    private final ExtensionConfig config;
    private final MontoyaApi api;
    private final AtomicBoolean streamingStopped = new AtomicBoolean(false);
    private volatile HttpURLConnection activeConnection = null;
    private volatile InputStream activeInputStream = null;

    public OpenAIStreamingProvider(ExtensionConfig config, MontoyaApi api)
    {
        this.config = config;
        this.api = api;
    }

    // ==================== 同步方法（兼容） ====================

    @Override
    public String chat(List<ChatMessage> messages) throws AIProviderException
    {
        if (!isConfigured())
        {
            throw new AIProviderException("API 未配置。请在设置中配置 API 地址和密钥。");
        }

        final StringBuilder result = new StringBuilder();
        final CountDownLatch latch = new CountDownLatch(1);
        final AIProviderException[] error = {null};

        chatStream(messages, new StreamCallback()
        {
            @Override
            public void onToken(String token)
            {
                result.append(token);
            }

            @Override
            public void onComplete(String fullResponse)
            {
                latch.countDown();
            }

            @Override
            public void onError(Exception e)
            {
                error[0] = e instanceof AIProviderException
                    ? (AIProviderException) e
                    : new AIProviderException(e.getMessage(), e);
                latch.countDown();
            }
        });

        try
        {
            latch.await();
        }
        catch (InterruptedException e)
        {
            Thread.currentThread().interrupt();
            throw new AIProviderException("请求被中断", e);
        }

        if (error[0] != null)
        {
            throw error[0];
        }

        return result.toString();
    }

    // ==================== 流式方法 ====================

    @Override
    public void chatStream(List<ChatMessage> messages, StreamCallback callback) throws AIProviderException
    {
        if (!isConfigured())
        {
            throw new AIProviderException("API 未配置。请在设置中配置 API 地址和密钥。");
        }

        streamingStopped.set(false);

        // 构建请求体
        boolean stream = config.isStreamingEnabled();
        List<Map<String, String>> builtMessages = buildMessages(messages);

        // 动态 max_tokens：估算输入 token，留至少 4096 给输出
        int inputTokens = 0;
        for (Map<String, String> m : builtMessages)
        {
            inputTokens += estimateTokens(m.get("content")) + 4;
        }
        // 128k 模型预算，减去输入，输出至少 2048 最多 16384
        int maxTokens = Math.max(2048, Math.min(16384, 128000 - inputTokens - 500));
        if (maxTokens > 16384) maxTokens = 16384;

        Map<String, Object> requestBody = new LinkedHashMap<>();
        requestBody.put("model", config.getModel());
        requestBody.put("messages", builtMessages);
        requestBody.put("stream", stream);
        requestBody.put("max_tokens", maxTokens);

        String jsonBody = SimpleJson.toJson(requestBody);

        HttpURLConnection conn = null;
        InputStream myInputStream = null;
        try
        {
            String chatUrl = buildChatUrl(config.getApiUrl());
            if (api != null) api.logging().logToOutput("[AI] Request URL: " + chatUrl);
            URL url = URI.create(chatUrl).toURL();

            // 代理处理
            if (config.isProxyEnabled())
            {
                String proxyHost = System.getProperty("http.proxyHost");
                String proxyPort = System.getProperty("http.proxyPort");
                if (proxyHost != null && proxyPort != null)
                {
                    Proxy proxy = new Proxy(Proxy.Type.HTTP,
                        new InetSocketAddress(proxyHost, Integer.parseInt(proxyPort)));
                    conn = (HttpURLConnection) url.openConnection(proxy);
                }
            }

            if (conn == null)
            {
                conn = (HttpURLConnection) url.openConnection();
            }

            activeConnection = conn;
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("Accept", stream ? "text/event-stream" : "application/json");

            // 认证
            String apiKey = config.getApiKey();
            if (apiKey != null && !apiKey.trim().isEmpty())
            {
                String urlStr = config.getApiUrl();
                if (urlStr.contains("openai.azure.com"))
                {
                    conn.setRequestProperty("api-key", apiKey);
                }
                else
                {
                    conn.setRequestProperty("Authorization", "Bearer " + apiKey);
                }
            }

            conn.setDoOutput(true);
            conn.setConnectTimeout(30000);
            conn.setReadTimeout(600000);  // 10分钟，覆盖模型长思考时间

            // 发送请求体
            try (OutputStream os = conn.getOutputStream())
            {
                os.write(jsonBody.getBytes(StandardCharsets.UTF_8));
            }

            int statusCode = conn.getResponseCode();
            if (statusCode >= 400)
            {
                String errorMsg = readErrorStream(conn);
                try
                {
                    Map<String, Object> errorResp = SimpleJson.parseObject(errorMsg);
                    Map<String, Object> err = SimpleJson.getMap(errorResp, "error");
                    if (err != null)
                    {
                        String msg = SimpleJson.getString(err, "message");
                        if (msg != null) errorMsg = msg;
                    }
                }
                catch (Exception ignored) {}
                throw new AIProviderException("API 请求失败 (HTTP " + statusCode + "): " + errorMsg, statusCode);
            }

            if (!stream)
            {
                String responseBody = readStream(conn.getInputStream());
                String content = parseNonStreamingResponse(responseBody);
                if (!content.isEmpty())
                {
                    callback.onToken(content);
                }
                callback.onComplete(content);
                return;
            }

            // 读取SSE流
            StringBuilder fullResponse = new StringBuilder();
            boolean receivedDone = false;
            InputStream is = conn.getInputStream();
            activeInputStream = is;
            myInputStream = is;
            BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8));
            try
            {
                String line;
                while ((line = reader.readLine()) != null)
                {
                    if (streamingStopped.get())
                    {
                        callback.onComplete(fullResponse.toString());
                        return;
                    }

                    if (line.startsWith("data: "))
                    {
                        String data = line.substring(6).trim();
                        if ("[DONE]".equals(data))
                        {
                            receivedDone = true;
                            callback.onComplete(fullResponse.toString());
                            return;
                        }

                        try
                        {
                            Map<String, Object> chunk = SimpleJson.parseObject(data);
                            List<Object> choices = SimpleJson.getList(chunk, "choices");
                            if (choices != null && !choices.isEmpty())
                            {
                                @SuppressWarnings("unchecked")
                                Map<String, Object> firstChoice = (Map<String, Object>) choices.get(0);
                                @SuppressWarnings("unchecked")
                                Map<String, Object> delta = (Map<String, Object>) firstChoice.get("delta");
                                if (delta != null)
                                {
                                    String content = (String) delta.get("content");
                                    if (content != null && !content.isEmpty())
                                    {
                                        fullResponse.append(content);
                                        callback.onToken(content);
                                    }
                                }
                            }
                        }
                        catch (Exception ignored)
                        {
                            // 解析失败的data行跳过
                        }
                    }
                }
            }
            finally
            {
                if (activeInputStream == myInputStream) activeInputStream = null;
                try { reader.close(); } catch (Exception ignored) {}
                try { is.close(); } catch (Exception ignored) {}
            }

            // 连接断开，没收到 [DONE] 标记 — 响应被截断
            if (!receivedDone && fullResponse.length() > 0)
            {
                // 走 onError 触发重试机制，而不是假装成功
                callback.onError(new AIProviderException("SSE 流被截断，未收到 [DONE]（已接收 "
                    + fullResponse.length() + " 字符）"));
                return;
            }
            callback.onComplete(fullResponse.toString());
        }
        catch (AIProviderException e)
        {
            callback.onError(e);
        }
        catch (Exception e)
        {
            if (streamingStopped.get())
            {
                callback.onComplete("");
            }
            else
            {
                if (api != null)
                {
                    api.logging().logToError("[AI] Request failed: " + e.getClass().getName() + " - " + e.getMessage());
                    java.io.StringWriter sw = new java.io.StringWriter();
                    e.printStackTrace(new java.io.PrintWriter(sw));
                    api.logging().logToError(sw.toString());
                }
                callback.onError(new AIProviderException("请求失败 [" + e.getClass().getSimpleName() + "]: " + e.getMessage(), e));
            }
        }
        catch (Throwable t)
        {
            // 安全网：捕获 NoClassDefFoundError 等 Error 类型
            // 防止 callback 永远不被调用导致 CountDownLatch 死锁
            callback.onError(new AIProviderException("内部错误: " + t.getClass().getSimpleName()
                + " - " + t.getMessage(), t instanceof Exception ? (Exception) t : null));
        }
        finally
        {
            if (activeInputStream == myInputStream) activeInputStream = null;
            activeConnection = null;
            if (conn != null) conn.disconnect();
        }
    }

    @Override
    public void stopStreaming()
    {
        streamingStopped.set(true);
        // 先关闭输入流，确保阻塞在 readLine() 的线程立即被唤醒
        InputStream is = activeInputStream;
        if (is != null)
        {
            try { is.close(); } catch (Exception ignored) {}
        }
        HttpURLConnection conn = activeConnection;
        if (conn != null)
        {
            try { conn.disconnect(); } catch (Exception ignored) {}
        }
    }

    @Override
    public String testConnection() throws AIProviderException
    {
        List<ChatMessage> messages = new ArrayList<>();
        messages.add(ChatMessage.system("请回复: OK"));
        messages.add(ChatMessage.user("测试连接"));
        String result = chat(messages);
        return "连接成功！响应: " + result;
    }

    @Override
    public boolean isConfigured()
    {
        return config.getApiKey() != null && !config.getApiKey().trim().isEmpty()
            && config.getApiUrl() != null && !config.getApiUrl().trim().isEmpty();
    }

    @Override
    public String getName()
    {
        return "OpenAI Compatible (Streaming)";
    }

    // ==================== 辅助方法 ====================

    /**
     * 构建完整的 chat/completions 请求 URL。
     * 如果用户输入的 URL 已包含 /chat/completions 或 /completions，直接使用；
     * 否则自动追加 /chat/completions 后缀。
     */
    private static String buildChatUrl(String baseUrl)
    {
        if (baseUrl == null || baseUrl.isEmpty()) return baseUrl;
        baseUrl = baseUrl.trim();
        if (baseUrl.contains("/chat/") || baseUrl.contains("/completions")) return baseUrl;
        return baseUrl + (baseUrl.endsWith("/") ? "chat/completions" : "/chat/completions");
    }

    private List<Map<String, String>> buildMessages(List<ChatMessage> messages)
    {
        List<Map<String, String>> result = new ArrayList<>();

        Map<String, String> systemMsg = new LinkedHashMap<>();
        systemMsg.put("role", "system");
        String systemContent = config.getSystemPrompt();
        // 在 system prompt 末尾注入 OOB 带外测试域名信息
        try
        {
            String oob = FullVulnDatabase.getOobDomain();
            if (oob != null && !oob.isEmpty())
            {
                systemContent += "\n\n[OOB带外测试] 当前可用的带外测试域名为 " + oob
                    + "。在分析SSRF、XXE、盲注等需要带外验证的漏洞时，应使用此域名构造payload。";
            }
        }
        catch (Throwable ignored)
        {
            // FullVulnDatabase 加载失败时安全降级，不注入 OOB 信息
        }
        systemMsg.put("content", systemContent);
        result.add(systemMsg);

        // 滑动窗口：估算 token 使用量，超出时截断最早的对话轮次
        // 估算：1 中文字 ≈ 2 token，1 英文词 ≈ 1.3 token
        // 保守上限：留 80k token 给输入（128k 模型留 48k 给输出+系统）
        List<ChatMessage> trimmed = trimToTokenBudget(messages, 80000);

        for (ChatMessage msg : trimmed)
        {
            Map<String, String> m = new LinkedHashMap<>();
            m.put("role", msg.role().value());
            m.put("content", msg.content());
            result.add(m);
        }

        return result;
    }

    /** 估算文本的 token 数（粗略：中文 *2 + 英文词数 *1.3） */
    private static int estimateTokens(String text)
    {
        if (text == null || text.isEmpty()) return 0;
        int cjk = 0;
        int ascii = 0;
        for (int i = 0; i < text.length(); i++)
        {
            char c = text.charAt(i);
            if (c >= 0x4E00 && c <= 0x9FFF) cjk++;
            else if (c < 128) ascii++;
        }
        return cjk * 2 + (int)(ascii / 4.0 * 1.3);
    }

    /**
     * 滑动窗口截断：保留 system 消息 + 最近的对话轮次，确保总 token 数不超过 budget。
     * 优先保留：system 消息 → 最后一条 user 消息 → 最近的 assistant+user 对。
     */
    private static List<ChatMessage> trimToTokenBudget(List<ChatMessage> messages, int tokenBudget)
    {
        if (messages == null || messages.isEmpty()) return messages;

        // 先计算总 token
        int totalTokens = 0;
        for (ChatMessage msg : messages)
        {
            totalTokens += estimateTokens(msg.content()) + 4; // 每条消息的 role/marker 开销
        }

        if (totalTokens <= tokenBudget) return messages;

        // 需要截断：从头部开始丢弃非 system 消息
        // 先分离 system 消息
        List<ChatMessage> systemMsgs = new ArrayList<>();
        List<ChatMessage> nonSystemMsgs = new ArrayList<>();
        for (ChatMessage msg : messages)
        {
            if (msg.role() == ChatMessage.Role.SYSTEM)
            {
                systemMsgs.add(msg);
            }
            else
            {
                nonSystemMsgs.add(msg);
            }
        }

        int systemTokens = 0;
        for (ChatMessage s : systemMsgs)
        {
            systemTokens += estimateTokens(s.content()) + 4;
        }

        int remainingBudget = tokenBudget - systemTokens;
        if (remainingBudget < 1000) remainingBudget = 1000;

        // 从尾部保留，确保最近的对话不被截断
        List<ChatMessage> kept = new ArrayList<>();
        int usedTokens = 0;
        for (int i = nonSystemMsgs.size() - 1; i >= 0; i--)
        {
            ChatMessage msg = nonSystemMsgs.get(i);
            int msgTokens = estimateTokens(msg.content()) + 4;
            if (usedTokens + msgTokens > remainingBudget)
            {
                break;
            }
            usedTokens += msgTokens;
            kept.add(0, msg); // 保持顺序
        }

        // 如果截断了部分对话，在开头加一个省略标记
        List<ChatMessage> result = new ArrayList<>(systemMsgs);
        if (kept.size() < nonSystemMsgs.size())
        {
            result.add(ChatMessage.system("[注意：为了适应上下文窗口，已省略前面的 "
                + (nonSystemMsgs.size() - kept.size()) + " 条历史消息。请基于当前可见的上下文继续分析。]"));
        }
        result.addAll(kept);
        return result;
    }

    private String readErrorStream(HttpURLConnection conn)
    {
        try
        {
            InputStream is = conn.getErrorStream();
            if (is == null) is = conn.getInputStream();
            if (is == null) return "";
            return readStream(is);
        }
        catch (Exception e)
        {
            return "";
        }
    }

    private String readStream(InputStream is) throws IOException
    {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8)))
        {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null)
            {
                sb.append(line);
            }
            return sb.toString();
        }
    }

    @SuppressWarnings("unchecked")
    private String parseNonStreamingResponse(String responseBody) throws AIProviderException
    {
        try
        {
            Map<String, Object> response = SimpleJson.parseObject(responseBody);
            List<Object> choices = SimpleJson.getList(response, "choices");
            if (choices == null || choices.isEmpty()) return "";

            Map<String, Object> firstChoice = (Map<String, Object>) choices.get(0);
            Map<String, Object> message = (Map<String, Object>) firstChoice.get("message");
            if (message == null) return "";

            String content = (String) message.get("content");
            return content != null ? content : "";
        }
        catch (Exception e)
        {
            throw new AIProviderException("解析非流式响应失败: " + e.getMessage(), e);
        }
    }
}
