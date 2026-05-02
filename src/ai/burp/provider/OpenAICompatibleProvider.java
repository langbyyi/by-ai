package ai.burp.provider;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

import ai.burp.config.ExtensionConfig;
import ai.burp.model.ChatMessage;
import ai.burp.util.SimpleJson;

/**
 * OpenAI-compatible API provider.
 * Supports: OpenAI, Azure OpenAI, Ollama, LM Studio, vLLM, LocalAI,
 * and any service that implements the /v1/chat/completions endpoint.
 */
public class OpenAICompatibleProvider implements AIProvider
{
    private final ExtensionConfig config;

    public OpenAICompatibleProvider(ExtensionConfig config)
    {
        this.config = config;
    }

    @Override
    public String chat(List<ChatMessage> messages) throws AIProviderException
    {
        if (!isConfigured())
        {
            throw new AIProviderException("API not configured. Please set API URL and Key in settings.");
        }

        // Build request body
        Map<String, Object> requestBody = new LinkedHashMap<>();
        requestBody.put("model", config.getModel());
        requestBody.put("messages", buildMessages(messages));

        // Add stream: false for non-streaming
        requestBody.put("stream", Boolean.FALSE);

        String jsonBody = SimpleJson.toJson(requestBody);

        // Make HTTP request
        String response = httpPost(buildChatUrl(config.getApiUrl()), jsonBody, config.getApiKey());

        // Parse response
        return parseResponse(response);
    }

    @Override
    public String testConnection() throws AIProviderException
    {
        List<ChatMessage> messages = new ArrayList<>();
        messages.add(ChatMessage.system("Reply with exactly: OK"));
        messages.add(ChatMessage.user("Test connection"));

        String result = chat(messages);
        return "Connection successful! Response: " + result;
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
        return "OpenAI Compatible";
    }

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

        // Add system prompt first
        Map<String, String> systemMsg = new LinkedHashMap<>();
        systemMsg.put("role", "system");
        systemMsg.put("content", config.getSystemPrompt());
        result.add(systemMsg);

        // Add conversation messages
        for (ChatMessage msg : messages)
        {
            Map<String, String> m = new LinkedHashMap<>();
            m.put("role", msg.role().value());
            m.put("content", msg.content());
            result.add(m);
        }

        return result;
    }

    private String httpPost(String urlStr, String body, String apiKey) throws AIProviderException
    {
        HttpURLConnection conn = null;
        try
        {
            URL url = URI.create(urlStr).toURL();

            // Handle proxy
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

            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("Accept", "application/json");

            // Set auth header - supports both Bearer and api-key patterns
            if (apiKey != null && !apiKey.trim().isEmpty())
            {
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
            conn.setReadTimeout(120000);

            // Send request body
            try (OutputStream os = conn.getOutputStream())
            {
                byte[] input = body.getBytes(StandardCharsets.UTF_8);
                os.write(input, 0, input.length);
            }

            int statusCode = conn.getResponseCode();

            // Read response
            String responseBody;
            InputStream is = null;
            try
            {
                is = statusCode >= 400 ? conn.getErrorStream() : conn.getInputStream();
                if (is == null) is = conn.getErrorStream();
                if (is == null)
                {
                    responseBody = "";
                }
                else
                {
                    BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8));
                    StringBuilder sb = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null)
                    {
                        sb.append(line);
                    }
                    responseBody = sb.toString();
                }
            }
            finally
            {
                if (is != null) try { is.close(); } catch (IOException ignored) {}
            }

            if (statusCode >= 400)
            {
                // Try to extract error message from response
                String errorMsg = responseBody;
                try
                {
                    Map<String, Object> errorResp = SimpleJson.parseObject(responseBody);
                    Map<String, Object> error = SimpleJson.getMap(errorResp, "error");
                    if (error != null)
                    {
                        String msg = SimpleJson.getString(error, "message");
                        if (msg != null) errorMsg = msg;
                    }
                }
                catch (Exception ignored) {}

                throw new AIProviderException(
                    "API request failed (HTTP " + statusCode + "): " + errorMsg, statusCode);
            }

            return responseBody;
        }
        catch (AIProviderException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new AIProviderException("Request failed: " + e.getMessage(), e);
        }
        finally
        {
            if (conn != null) conn.disconnect();
        }
    }

    private String parseResponse(String responseBody) throws AIProviderException
    {
        try
        {
            Map<String, Object> response = SimpleJson.parseObject(responseBody);

            // Extract content from: choices[0].message.content
            List<Object> choices = SimpleJson.getList(response, "choices");
            if (choices == null || choices.isEmpty())
            {
                throw new AIProviderException("No choices in API response");
            }

            @SuppressWarnings("unchecked")
            Map<String, Object> firstChoice = (Map<String, Object>) choices.get(0);
            @SuppressWarnings("unchecked")
            Map<String, Object> message = (Map<String, Object>) firstChoice.get("message");

            if (message == null)
            {
                throw new AIProviderException("No message in API response choice");
            }

            String content = (String) message.get("content");
            if (content == null)
            {
                throw new AIProviderException("No content in API response message");
            }

            return content;
        }
        catch (AIProviderException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new AIProviderException("Failed to parse API response: " + e.getMessage(), e);
        }
    }
}
