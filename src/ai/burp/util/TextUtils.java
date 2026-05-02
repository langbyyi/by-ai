package ai.burp.util;

import burp.api.montoya.http.message.HttpMessage;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import java.nio.charset.StandardCharsets;

/**
 * 文本处理工具类。
 * <p>
 * 统一 escapeHtml、truncate、isDestructivePayload 等在多个 UI/Scanner 类中重复的方法。
 * 所有方法均为静态，无外部依赖（仅 JDK）。
 */
public final class TextUtils
{
    private TextUtils() {} // 禁止实例化

    // ==================== Burp HTTP 消息 UTF-8 安全转换 ====================

    /**
     * 将 HttpRequest 转为 UTF-8 字符串，避免 toString() 编码问题导致中文乱码。
     */
    public static String toStringUtf8(HttpRequest request)
    {
        if (request == null) return "";
        return new String(request.toByteArray().getBytes(), StandardCharsets.UTF_8);
    }

    /**
     * 将 HttpResponse 转为 UTF-8 字符串，避免 toString() 编码问题导致中文乱码。
     */
    public static String toStringUtf8(HttpResponse response)
    {
        if (response == null) return "";
        return new String(response.toByteArray().getBytes(), StandardCharsets.UTF_8);
    }

    // ==================== HTML 转义 ====================

    /**
     * HTML 转义：{@code & < > "}。
     * 不转换换行符，适用于内嵌 HTML 属性或纯文本片段。
     */
    public static String escapeHtml(String text)
    {
        if (text == null) return "";
        return text.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\"", "&quot;");
    }

    /**
     * HTML 转义并将 {@code \n} 转为 {@code <br/>}，适用于日志/消息显示。
     */
    public static String escapeHtmlWithBr(String text)
    {
        if (text == null) return "";
        return text.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\"", "&quot;")
                   .replace("\n", "<br/>");
    }

    // ==================== 截断 ====================

    /**
     * 简单截断，超出 maxLength 时追加 "..."。
     */
    public static String truncate(String text, int maxLength)
    {
        if (text == null || text.isEmpty()) return "";
        if (text.length() <= maxLength) return text;
        return text.substring(0, maxLength) + "...";
    }

    /**
     * 通用截断，可自定义后缀。
     *
     * @param text   原始文本
     * @param maxLen 最大保留字符数（不含后缀）
     * @param suffix 截断后缀，例如 "..." 或 "\n... [已截断]"
     */
    public static String truncateWithSuffix(String text, int maxLen, String suffix)
    {
        if (text == null) return "";
        if (text.length() <= maxLen) return text;
        return text.substring(0, maxLen) + (suffix != null ? suffix : "...");
    }

    // ==================== 破坏性 Payload 检测 ====================

    /** 已知的破坏性模式（大写） */
    private static final String[] DESTRUCTIVE_PATTERNS = {
        "DROP TABLE", "DROP DATABASE", "DELETE FROM",
        "TRUNCATE", "RM -RF", "FORMAT C:",
        "DEL /F /S /Q", "SHUTDOWN", "DBCC",
        "EXEC(", "EXECUTE(", "XP_CMDSHELL", "SP_OACREATE",
        "LOAD_FILE(", "INTO OUTFILE", "INTO DUMPFILE",
        "INFORMATION_SCHEMA"
    };

    /**
     * 检测文本是否包含破坏性 payload。
     * <p>
     * 增强措施：
     * <ul>
     *   <li>URL 百分号解码（%XX）后再检测</li>
     *   <li>移除 SQL 块注释 (slash-star ... star-slash) 后再检测</li>
     *   <li>压缩关键字之间的空白字符后再检测</li>
     * </ul>
     */
    public static boolean isDestructivePayload(String text)
    {
        if (text == null) return false;

        // 1) URL 百分号解码
        String decoded = urlDecode(text);

        // 2) 移除 SQL 块注释
        String stripped = stripSqlComments(decoded);

        // 3) 压缩空白（使 "DR OP  TABLE" 之类绕过失效）
        String collapsed = collapseWhitespace(stripped);

        // 4) 转大写后逐一匹配
        String upper = collapsed.toUpperCase();
        for (String pattern : DESTRUCTIVE_PATTERNS)
        {
            if (upper.contains(pattern)) return true;
        }
        return false;
    }

    // ==================== UTF-8 字节长度 ====================

    /**
     * 返回字符串的 UTF-8 编码字节长度。
     */
    public static int byteLength(String text)
    {
        if (text == null || text.isEmpty()) return 0;
        return text.getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
    }

    // ==================== 内部辅助 ====================

    /**
     * 简易 URL 百分号解码（%XX），处理大小写混合和双编码的常见变体。
     */
    private static String urlDecode(String text)
    {
        if (text == null || text.indexOf('%') < 0) return text;

        StringBuilder sb = new StringBuilder(text.length());
        for (int i = 0; i < text.length(); i++)
        {
            char c = text.charAt(i);
            if (c == '%' && i + 2 < text.length())
            {
                int hi = hexValue(text.charAt(i + 1));
                int lo = hexValue(text.charAt(i + 2));
                if (hi >= 0 && lo >= 0)
                {
                    sb.append((char) (hi * 16 + lo));
                    i += 2;
                    continue;
                }
            }
            sb.append(c);
        }
        return sb.toString();
    }

    private static int hexValue(char c)
    {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    /**
     * 移除 SQL 块注释 (C-style block comments)，防止注释内嵌关键字绕过。
     */
    private static String stripSqlComments(String text)
    {
        if (text == null) return null;

        StringBuilder sb = new StringBuilder(text.length());
        int len = text.length();
        int i = 0;
        while (i < len)
        {
            if (i + 1 < len && text.charAt(i) == '/' && text.charAt(i + 1) == '*')
            {
                // 跳过到 */
                int end = text.indexOf("*/", i + 2);
                if (end >= 0)
                {
                    i = end + 2;
                }
                else
                {
                    break; // 未闭合注释，跳过剩余
                }
            }
            else
            {
                sb.append(text.charAt(i));
                i++;
            }
        }
        return sb.toString();
    }

    /**
     * 压缩连续空白字符（空格、制表符、换行、回车）为单个空格，
     * 使 "DR&lt;tab&gt;OP  &lt;newline&gt;TAB&lt;space&gt;LE" 这类绕过失效。
     */
    private static String collapseWhitespace(String text)
    {
        if (text == null) return null;

        StringBuilder sb = new StringBuilder(text.length());
        boolean lastWasWhitespace = false;
        for (int i = 0; i < text.length(); i++)
        {
            char c = text.charAt(i);
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
            {
                if (!lastWasWhitespace)
                {
                    sb.append(' ');
                    lastWasWhitespace = true;
                }
            }
            else
            {
                sb.append(c);
                lastWasWhitespace = false;
            }
        }
        return sb.toString();
    }
}
