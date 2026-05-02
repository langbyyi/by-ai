package ai.burp.util;

import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Lightweight Markdown to HTML renderer.
 * Zero dependency, handles common Markdown syntax from AI responses.
 */
public final class MarkdownRenderer
{
    public interface CodeBlockRegistrar
    {
        String register(String code);
    }

    private MarkdownRenderer() {}
    private static final int CODE_WRAP_COLUMN = 110;

    /**
     * Convert Markdown text to HTML.
     */
    public static String render(String markdown)
    {
        return render(markdown, null);
    }

    /**
     * Convert Markdown text to HTML with optional code-block link registration.
     */
    public static String render(String markdown, CodeBlockRegistrar codeBlockRegistrar)
    {
        if (markdown == null || markdown.isEmpty()) return "";

        StringBuilder html = new StringBuilder();
        String[] lines = markdown.replace("\r\n", "\n").replace('\r', '\n').split("\n", -1);
        boolean inCodeBlock = false;
        StringBuilder codeBlock = new StringBuilder();
        String codeLang = "";
        boolean inList = false;
        boolean inOrderedList = false;
        StringBuilder paragraph = new StringBuilder();

        for (int i = 0; i < lines.length; i++)
        {
            String line = lines[i];

            // === Code block toggle ===
            if (line.trim().startsWith("```"))
            {
                if (inCodeBlock)
                {
                    // End code block — 用最基础的 HTML 3.2 table+pre，Swing 100% 支持
                    appendCodeBlock(html, codeLang, codeBlock.toString(), codeBlockRegistrar);
                    codeBlock.setLength(0);
                    codeLang = "";
                    inCodeBlock = false;
                }
                else
                {
                    flushParagraph(html, paragraph);
                    // Close any open list
                    closeListIfNeeded(html, inList, inOrderedList);
                    inList = false;
                    inOrderedList = false;

                    // Start code block
                    inCodeBlock = true;
                    int markerIdx = line.indexOf("```");
                    codeLang = line.substring(markerIdx + 3).trim();
                    codeBlock.setLength(0);
                }
                continue;
            }

            // Inside code block - collect raw lines
            if (inCodeBlock)
            {
                codeBlock.append(line).append('\n');
                continue;
            }

            // === Close list if line is not a list item ===
            String trimmed = line.trim();
            boolean isUnordered = trimmed.startsWith("- ") || trimmed.startsWith("* ") || trimmed.startsWith("+ ");
            boolean isOrdered = trimmed.matches("^\\d+\\.\\s+.*");

            if (!isUnordered && !isOrdered && (inList || inOrderedList))
            {
                flushParagraph(html, paragraph);
                closeListIfNeeded(html, inList, inOrderedList);
                inList = false;
                inOrderedList = false;
            }

            // === Empty line ===
            if (trimmed.isEmpty())
            {
                flushParagraph(html, paragraph);
                continue;
            }

            // === Headers ===
            if (trimmed.startsWith("######"))
            {
                flushParagraph(html, paragraph);
                html.append("<h6 style='margin:12px 0 4px;'>").append(renderInline(trimmed.substring(6).trim())).append("</h6>");
            }
            else if (trimmed.startsWith("#####"))
            {
                flushParagraph(html, paragraph);
                html.append("<h5 style='margin:12px 0 4px;'>").append(renderInline(trimmed.substring(5).trim())).append("</h5>");
            }
            else if (trimmed.startsWith("####"))
            {
                flushParagraph(html, paragraph);
                html.append("<h4 style='margin:12px 0 4px;'>").append(renderInline(trimmed.substring(4).trim())).append("</h4>");
            }
            else if (trimmed.startsWith("###"))
            {
                flushParagraph(html, paragraph);
                html.append("<h3 style='margin:14px 0 6px;font-size:15px;'>").append(renderInline(trimmed.substring(3).trim())).append("</h3>");
            }
            else if (trimmed.startsWith("##"))
            {
                flushParagraph(html, paragraph);
                html.append("<h2 style='margin:14px 0 6px;font-size:16px;'>").append(renderInline(trimmed.substring(2).trim())).append("</h2>");
            }
            else if (trimmed.startsWith("#"))
            {
                flushParagraph(html, paragraph);
                html.append("<h1 style='margin:16px 0 8px;font-size:18px;'>").append(renderInline(trimmed.substring(1).trim())).append("</h1>");
            }
            // === Unordered list ===
            else if (isUnordered)
            {
                flushParagraph(html, paragraph);
                if (!inList)
                {
                    html.append("<ul style='margin:4px 0;padding-left:20px;'>");
                    inList = true;
                }
                String content = trimmed.substring(2).trim();
                html.append("<li>").append(renderInline(content)).append("</li>");
            }
            // === Ordered list ===
            else if (isOrdered)
            {
                flushParagraph(html, paragraph);
                if (!inOrderedList)
                {
                    html.append("<ol style='margin:4px 0;padding-left:20px;'>");
                    inOrderedList = true;
                }
                int dotIdx = trimmed.indexOf('.');
                String content = trimmed.substring(dotIdx + 1).trim();
                html.append("<li>").append(renderInline(content)).append("</li>");
            }
            // === Table ===
            else if (isTableStart(lines, i))
            {
                flushParagraph(html, paragraph);
                // Check if this line is a separator row (|---|---|)
                if (isTableSeparator(trimmed)) continue;

                // This is a header row, check next line for separator
                String[] cells = splitTableRow(trimmed);

                html.append("<table style='border-collapse:collapse;margin:8px 0;font-size:13px;'>");

                // Header row
                html.append("<tr>");
                for (String cell : cells)
                {
                    html.append("<th style='border:1px solid #ddd;padding:6px 10px;background:#f5f5f5;text-align:left;'>");
                    html.append(renderInline(cell.trim())).append("</th>");
                }
                html.append("</tr>");

                // Data rows: skip separator row, then collect data
                int j = i + 1;
                // Skip separator if present
                if (j < lines.length && isTableSeparator(lines[j].trim()))
                {
                    j++;
                }

                for (; j < lines.length; j++)
                {
                    String dataLine = lines[j].trim();
                    if (!dataLine.startsWith("|") || !dataLine.endsWith("|")) break;
                    if (isTableSeparator(dataLine)) continue;

                    String[] dataCells = splitTableRow(dataLine);
                    html.append("<tr>");
                    for (String cell : dataCells)
                    {
                        html.append("<td style='border:1px solid #ddd;padding:6px 10px;'>");
                        html.append(renderInline(cell.trim())).append("</td>");
                    }
                    html.append("</tr>");
                }

                html.append("</table>");
                i = j - 1; // Skip processed lines
            }
            // === Blockquote ===
            else if (trimmed.startsWith("> "))
            {
                flushParagraph(html, paragraph);
                String content = trimmed.substring(2).trim();
                html.append("<blockquote style='border-left:3px solid #ccc;margin:8px 0;padding:4px 12px;color:#555;'>");
                html.append(renderInline(content)).append("</blockquote>");
            }
            // === Horizontal rule ===
            else if (trimmed.matches("^[-*_]{3,}$"))
            {
                flushParagraph(html, paragraph);
                html.append("<hr style='border:none;border-top:1px solid #ddd;margin:12px 0;'/>");
            }
            // === Paragraph ===
            else
            {
                if (paragraph.length() > 0)
                {
                    paragraph.append(line.endsWith("  ") ? "\n" : " ");
                }
                paragraph.append(trimmed);
            }
        }

        flushParagraph(html, paragraph);

        // Close any remaining list
        closeListIfNeeded(html, inList, inOrderedList);

        // Unclosed code block
        if (inCodeBlock)
        {
            appendCodeBlock(html, codeLang, codeBlock.toString(), codeBlockRegistrar);
        }

        return html.toString();
    }

    /**
     * Render inline Markdown (bold, italic, code, links).
     */
    private static String renderInline(String text)
    {
        if (text == null || text.isEmpty()) return "";

        StringBuilder result = new StringBuilder();
        int len = text.length();
        int i = 0;

        while (i < len)
        {
            char c = text.charAt(i);

            // === Inline code ===
            if (c == '`')
            {
                int end = text.indexOf('`', i + 1);
                if (end > i)
                {
                    String code = text.substring(i + 1, end);
                    result.append("<tt>");
                    result.append(escapeHtml(code));
                    result.append("</tt>");
                    i = end + 1;
                    continue;
                }
            }

            // === Bold + Italic ===
            if (c == '*' && i + 2 < len && text.charAt(i + 1) == '*' && text.charAt(i + 2) == '*')
            {
                int end = findClosing(text, i + 3, "***");
                if (end > i)
                {
                    result.append("<b><i>").append(renderInline(text.substring(i + 3, end))).append("</i></b>");
                    i = end + 3;
                    continue;
                }
            }

            // === Bold ===
            if (c == '*' && i + 1 < len && text.charAt(i + 1) == '*')
            {
                int end = text.indexOf("**", i + 2);
                if (end > i + 1)
                {
                    result.append("<b>").append(renderInline(text.substring(i + 2, end))).append("</b>");
                    i = end + 2;
                    continue;
                }
            }

            // === Bold with underscores ===
            if (c == '_' && i + 1 < len && text.charAt(i + 1) == '_')
            {
                int end = text.indexOf("__", i + 2);
                if (end > i + 1)
                {
                    result.append("<b>").append(renderInline(text.substring(i + 2, end))).append("</b>");
                    i = end + 2;
                    continue;
                }
            }

            // === Strikethrough ===
            if (c == '~' && i + 1 < len && text.charAt(i + 1) == '~')
            {
                int end = text.indexOf("~~", i + 2);
                if (end > i + 1)
                {
                    result.append("<strike>").append(renderInline(text.substring(i + 2, end))).append("</strike>");
                    i = end + 2;
                    continue;
                }
            }

            // === Italic ===
            if (c == '*')
            {
                int end = text.indexOf('*', i + 1);
                if (end > i)
                {
                    result.append("<i>").append(renderInline(text.substring(i + 1, end))).append("</i>");
                    i = end + 1;
                    continue;
                }
            }

            // === Italic with underscores ===
            if (c == '_')
            {
                int end = text.indexOf('_', i + 1);
                if (end > i)
                {
                    result.append("<i>").append(renderInline(text.substring(i + 1, end))).append("</i>");
                    i = end + 1;
                    continue;
                }
            }

            // === Link ===
            if (c == '[')
            {
                int textEnd = text.indexOf(']', i + 1);
                if (textEnd > i && textEnd + 1 < len && text.charAt(textEnd + 1) == '(')
                {
                    int urlEnd = text.indexOf(')', textEnd + 2);
                    if (urlEnd > textEnd)
                    {
                        String linkText = text.substring(i + 1, textEnd);
                        String url = text.substring(textEnd + 2, urlEnd);
                        result.append("<a href='").append(escapeHtml(url)).append("' style='color:#1565c0;'>");
                        result.append(escapeHtml(linkText)).append("</a>");
                        i = urlEnd + 1;
                        continue;
                    }
                }
            }

            // === HTML escape ===
            if (c == '&') result.append("&amp;");
            else if (c == '<') result.append("&lt;");
            else if (c == '>') result.append("&gt;");
            else if (c == '"') result.append("&quot;");
            else result.append(c);

            i++;
        }

        return result.toString();
    }

    private static void flushParagraph(StringBuilder html, StringBuilder paragraph)
    {
        if (paragraph.length() == 0) return;
        html.append("<p style='margin:4px 0;line-height:1.6;'>")
            .append(renderInlineWithBreaks(paragraph.toString()))
            .append("</p>");
        paragraph.setLength(0);
    }

    private static String renderInlineWithBreaks(String text)
    {
        String[] parts = text.split("\n", -1);
        StringBuilder rendered = new StringBuilder();
        for (int i = 0; i < parts.length; i++)
        {
            if (i > 0) rendered.append("<br>");
            rendered.append(renderInline(parts[i]));
        }
        return rendered.toString();
    }

    private static void appendCodeBlock(StringBuilder html, String codeLang, String code, CodeBlockRegistrar codeBlockRegistrar)
    {
        String originalCode = trimTrailingNewlines(code);
        String displayCode = beautifyCodeBlock(codeLang, originalCode);
        String codeBlockId = codeBlockRegistrar == null ? null : codeBlockRegistrar.register(originalCode);
        boolean httpRequest = looksLikeHttpRequest(originalCode.trim());
        boolean httpResponse = looksLikeHttpResponse(originalCode.trim());
        html.append("<table border='0' bgcolor='#cfd6dd' width='100%' cellpadding='0' cellspacing='1'>");
        html.append("<tr bgcolor='#eef1f4'><td>");
        html.append("<table border='0' width='100%' cellpadding='4' cellspacing='0'><tr>");
        html.append("<td align='left' valign='middle'>");
        html.append("<font face='sans-serif' size='-1' color='#263238'>");
        if (httpRequest)
        {
            html.append("<b>HTTP Request</b>");
        }
        else if (httpResponse)
        {
            html.append("<b>HTTP Response</b>");
        }
        else if (codeLang != null && !codeLang.isEmpty())
        {
            html.append("<b>").append(escapeHtml(codeLang)).append("</b>");
        }
        else
        {
            html.append("<b>code</b>");
        }
        html.append("</font>");
        html.append("</td>");
        if (codeBlockId != null)
        {
            html.append("<td align='right' valign='middle'>");
            if (httpRequest)
            {
                appendActionLink(html, "repeater-code-" + codeBlockId, "Repeater", true);
                appendActionLink(html, "intruder-code-" + codeBlockId, "Intruder", true);
                appendActionLink(html, "copy-code-" + codeBlockId, "复制", true);
                appendActionLink(html, "send-analyze-code-" + codeBlockId, "发送分析", false);
            }
            else
            {
                appendActionLink(html, "copy-code-" + codeBlockId, "复制", false);
            }
            html.append("</td>");
        }
        else
        {
            html.append("<td></td>");
        }
        html.append("</tr></table></td></tr>");
        html.append("<tr bgcolor='#ffffff'><td>");
        html.append("<table border='0' width='100%' cellpadding='8' cellspacing='0'><tr><td>");
        html.append("<font face='monospaced'>");
        appendCodeLines(html, displayCode);
        html.append("</font></td></tr></table></td></tr></table>");
    }

    private static void appendActionLink(StringBuilder html, String href, String label, boolean withDivider)
    {
        html.append("<a href='").append(escapeHtml(href)).append("'>");
        html.append("<font face='sans-serif' size='-1' color='#0f5fa8'>")
            .append(escapeHtml(label)).append("</font>");
        html.append("</a>");
        if (withDivider)
        {
            html.append("<font color='#90a4ae'>&nbsp;|&nbsp;</font>");
        }
    }

    private static void appendCodeLines(StringBuilder html, String code)
    {
        String[] lines = code.split("\n", -1);
        for (int i = 0; i < lines.length; i++)
        {
            if (i > 0) html.append("<br>");
            appendWrappedCodeLine(html, lines[i]);
        }
    }

    private static void appendWrappedCodeLine(StringBuilder html, String line)
    {
        if (line == null || line.isEmpty())
        {
            html.append("&nbsp;");
            return;
        }

        int start = 0;
        boolean continuation = false;
        while (start < line.length())
        {
            if (continuation) html.append("<br>&nbsp;&nbsp;&nbsp;&nbsp;");
            int maxLen = continuation ? CODE_WRAP_COLUMN - 4 : CODE_WRAP_COLUMN;
            int end = Math.min(line.length(), start + maxLen);
            if (end < line.length())
            {
                int breakAt = findSoftBreak(line, start, end);
                if (breakAt > start + 24) end = breakAt + 1;
            }
            html.append(escapeHtml(line.substring(start, end)).replace(" ", "&nbsp;"));
            start = end;
            continuation = true;
        }
    }

    private static int findSoftBreak(String line, int start, int end)
    {
        for (int i = end - 1; i > start; i--)
        {
            char c = line.charAt(i);
            if (c == ',' || c == ';' || c == '&' || c == '?' || c == '/' || c == ':' || c == '.')
            {
                return i;
            }
        }
        return end;
    }

    private static String beautifyCodeBlock(String codeLang, String code)
    {
        if (code == null || code.isEmpty()) return "";
        String lang = codeLang == null ? "" : codeLang.trim().toLowerCase(Locale.ROOT);
        String normalized = code.replace("\r\n", "\n").replace('\r', '\n');
        String trimmed = normalized.trim();

        if ("json".equals(lang) || isJsonCandidate(trimmed))
        {
            String pretty = prettyJson(trimmed);
            if (pretty != null) return pretty;
        }

        if ("http".equals(lang) || looksLikeHttpMessage(trimmed))
        {
            return beautifyHttpMessage(normalized);
        }

        return normalized;
    }

    private static boolean looksLikeHttpMessage(String text)
    {
        return looksLikeHttpResponse(text) || looksLikeHttpRequest(text);
    }

    private static boolean looksLikeHttpRequest(String text)
    {
        return text != null
            && text.matches("(?s)^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\\s+\\S+\\s+HTTP/\\d\\.\\d.*");
    }

    private static boolean looksLikeHttpResponse(String text)
    {
        return text != null && text.startsWith("HTTP/");
    }

    private static String beautifyHttpMessage(String text)
    {
        String normalized = text.replace("\r\n", "\n").replace('\r', '\n');
        int split = normalized.indexOf("\n\n");
        if (split < 0)
        {
            return normalized;
        }

        String head = normalized.substring(0, split);
        String body = normalized.substring(split + 2).trim();
        StringBuilder result = new StringBuilder();
        String[] headLines = head.split("\n", -1);
        for (int i = 0; i < headLines.length; i++)
        {
            if (i > 0) result.append('\n');
            result.append(headLines[i]);
        }

        if (!body.isEmpty())
        {
            String prettyBody = isJsonCandidate(body) ? prettyJson(body) : null;
            result.append("\n\n").append(prettyBody != null ? prettyBody : body);
        }
        return result.toString();
    }

    private static boolean isJsonCandidate(String text)
    {
        if (text == null) return false;
        String trimmed = text.trim();
        return (trimmed.startsWith("{") && trimmed.endsWith("}"))
            || (trimmed.startsWith("[") && trimmed.endsWith("]"));
    }

    private static String prettyJson(String json)
    {
        try
        {
            Object parsed = SimpleJson.parse(json);
            StringBuilder sb = new StringBuilder();
            appendPrettyJson(sb, parsed, 0);
            return sb.toString();
        }
        catch (Exception e)
        {
            return null;
        }
    }

    private static void appendPrettyJson(StringBuilder sb, Object value, int indent)
    {
        if (value instanceof Map)
        {
            Map<?, ?> map = (Map<?, ?>) value;
            sb.append("{");
            if (!map.isEmpty()) sb.append('\n');
            int i = 0;
            for (Map.Entry<?, ?> entry : map.entrySet())
            {
                indent(sb, indent + 2);
                sb.append(SimpleJson.quoteString(String.valueOf(entry.getKey()))).append(": ");
                appendPrettyJson(sb, entry.getValue(), indent + 2);
                if (++i < map.size()) sb.append(",");
                sb.append('\n');
            }
            if (!map.isEmpty()) indent(sb, indent);
            sb.append("}");
        }
        else if (value instanceof List)
        {
            List<?> list = (List<?>) value;
            sb.append("[");
            if (!list.isEmpty()) sb.append('\n');
            for (int i = 0; i < list.size(); i++)
            {
                indent(sb, indent + 2);
                appendPrettyJson(sb, list.get(i), indent + 2);
                if (i + 1 < list.size()) sb.append(",");
                sb.append('\n');
            }
            if (!list.isEmpty()) indent(sb, indent);
            sb.append("]");
        }
        else if (value instanceof String)
        {
            sb.append(SimpleJson.quoteString((String) value));
        }
        else
        {
            sb.append(value == null ? "null" : value.toString());
        }
    }

    private static void indent(StringBuilder sb, int count)
    {
        for (int i = 0; i < count; i++) sb.append(' ');
    }

    private static String trimTrailingNewlines(String text)
    {
        if (text == null || text.isEmpty()) return "";
        int end = text.length();
        while (end > 0 && (text.charAt(end - 1) == '\n' || text.charAt(end - 1) == '\r'))
        {
            end--;
        }
        return text.substring(0, end);
    }

    private static int findClosing(String text, int start, String marker)
    {
        int idx = text.indexOf(marker, start);
        return idx >= start ? idx : -1;
    }

    private static String[] splitTableRow(String row)
    {
        String content = row;
        if (content.startsWith("|")) content = content.substring(1);
        if (content.endsWith("|")) content = content.substring(0, content.length() - 1);
        return content.split("\\|");
    }

    private static boolean isTableStart(String[] lines, int index)
    {
        String row = lines[index].trim();
        if (!row.startsWith("|") || !row.endsWith("|")) return false;
        if (isTableSeparator(row)) return false;
        if (index + 1 >= lines.length) return false;
        return isTableSeparator(lines[index + 1].trim());
    }

    /** Check if a table row is a separator like |---|---| or | :---: | --- | */
    private static boolean isTableSeparator(String row)
    {
        if (row == null || !row.startsWith("|") || !row.endsWith("|")) return false;
        String content = row;
        if (content.startsWith("|")) content = content.substring(1);
        if (content.endsWith("|")) content = content.substring(0, content.length() - 1);
        String[] cells = content.split("\\|");
        for (String cell : cells)
        {
            String trimmed = cell.trim();
            if (trimmed.isEmpty()) continue;
            // Separator cells contain only dashes, colons, and spaces
            if (!trimmed.matches("[-:]+")) return false;
        }
        return cells.length > 0;
    }

    private static void closeListIfNeeded(StringBuilder html, boolean inList, boolean inOrderedList)
    {
        if (inOrderedList) html.append("</ol>");
        if (inList) html.append("</ul>");
    }

    private static String escapeHtml(String text)
    {
        if (text == null) return "";
        return text.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\"", "&quot;");
    }
}
