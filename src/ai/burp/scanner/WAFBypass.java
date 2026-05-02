package ai.burp.scanner;

import java.util.*;

import ai.burp.model.ChatMessage;
import ai.burp.provider.StreamingAIProvider;
import ai.burp.util.AiResponseParser;

/**
 * WAF/防护绕过方案生成器。
 * 处理自定义过滤规则、参数加密/加签、前端校验、WAF防护、动态Token等场景。
 */
public class WAFBypass
{
    private final StreamingAIProvider provider;
    private final AuditLogger logger;

    public WAFBypass(StreamingAIProvider provider, AuditLogger logger)
    {
        this.provider = provider;
        this.logger = logger;
    }

    /**
     * 分析被拦截的请求并生成绕过方案。
     *
     * @param originalRequest 原始请求文本
     * @param blockedResponse 被拦截时的响应文本
     * @param vulnType 目标漏洞类型
     * @param payload 被拦截的payload
     * @return 绕过方案列表
     */
    public List<BypassScheme> generateBypass(String originalRequest, String blockedResponse,
        String vulnType, String payload)
    {
        if (!provider.isConfigured()) return Collections.emptyList();

        try
        {
            String prompt = FullVulnDatabase.buildWAFBypassPrompt(
                originalRequest, blockedResponse, vulnType, payload);
            String aiResult = provider.chat(Collections.singletonList(ChatMessage.user(prompt)));

            List<BypassScheme> schemes = parseBypassSchemes(aiResult);
            logger.log("WAF绕过", vulnType, "生成 " + schemes.size() + " 个绕过方案");
            return schemes;
        }
        catch (Exception e)
        {
            logger.log("WAF绕过", vulnType, "生成失败: " + e.getMessage());
            return Collections.emptyList();
        }
    }

    /**
     * 检测响应是否被WAF/防护拦截。
     */
    public static boolean isBlocked(String response)
    {
        if (response == null || response.isEmpty()) return false;
        String lower = response.toLowerCase();

        // 常见WAF拦截特征
        return lower.contains("waf") && (lower.contains("block") || lower.contains("denied"))
            || lower.contains("firewall")
            || lower.contains("request rejected")
            || lower.contains("access denied")
            || lower.contains("forbidden")
            || lower.contains("security policy")
            || lower.contains(" intrusion")
            || (lower.contains("403") && lower.contains("not authorized"))
            || lower.contains("安全防护")
            || lower.contains("访问被拦截");
    }

    /**
     * 检测是否需要CSRF Token绕过。
     */
    public static boolean needsCSRFBypass(String response)
    {
        if (response == null) return false;
        String lower = response.toLowerCase();
        return lower.contains("csrf") || lower.contains("_token")
            || lower.contains("csrftoken") || lower.contains("xsrf-token")
            || lower.contains("anti_forgery");
    }

    /**
     * 检测响应中是否有参数加密/签名。
     */
    public static boolean hasEncryptedParams(String response)
    {
        if (response == null) return false;
        String lower = response.toLowerCase();
        return lower.contains("encrypt") || lower.contains("sign=")
            || lower.contains("signature") || lower.contains("hmac");
    }

    private List<BypassScheme> parseBypassSchemes(String aiResult)
    {
        List<BypassScheme> schemes = new ArrayList<>();
        try
        {
            for (Map<String, Object> m : AiResponseParser.parseFirstObjectArray(aiResult))
            {
                BypassScheme scheme = new BypassScheme();
                scheme.bypassType = AiResponseParser.getString(m, "bypassType");
                scheme.description = AiResponseParser.getString(m, "description");
                scheme.modifiedRequest = AiResponseParser.getString(m, "modifiedRequest");
                scheme.confidence = AiResponseParser.getDouble(m, "confidence", 0.0);

                schemes.add(scheme);
            }
        }
        catch (Exception ignored) {}
        return schemes;
    }

    /**
     * 绕过方案。
     */
    public static class BypassScheme
    {
        public String bypassType = "";
        public String description = "";
        public String modifiedRequest = "";
        public double confidence = 0.0;

        @Override
        public String toString()
        {
            return "[" + bypassType + "] " + description + " (置信度: " + confidence + ")";
        }
    }
}
