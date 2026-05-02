package ai.burp.util;

import java.util.*;

/**
 * Lightweight JSON parser and serializer.
 * No external dependencies required.
 */
public class SimpleJson
{
    private final String json;
    private int pos;

    private SimpleJson(String json)
    {
        this.json = json;
        this.pos = 0;
    }

    // ==================== Parsing ====================

    public static Object parse(String json)
    {
        if (json == null || json.trim().isEmpty()) return null;
        SimpleJson p = new SimpleJson(json.trim());
        p.skipWhitespace();
        return p.parseValue();
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> parseObject(String json)
    {
        Object result = parse(json);
        return result instanceof Map ? (Map<String, Object>) result : new LinkedHashMap<>();
    }

    private Map<String, Object> doParseObject()
    {
        Map<String, Object> map = new LinkedHashMap<>();
        skipWhitespace();
        expect('{');
        skipWhitespace();
        if (peek() == '}')
        {
            pos++;
            return map;
        }
        while (true)
        {
            skipWhitespace();
            String key = doParseString();
            skipWhitespace();
            expect(':');
            skipWhitespace();
            Object value = parseValue();
            map.put(key, value);
            skipWhitespace();
            if (peek() == ',')
            {
                pos++;
                continue;
            }
            break;
        }
        skipWhitespace();
        expect('}');
        return map;
    }

    private List<Object> doParseArray()
    {
        List<Object> list = new ArrayList<>();
        skipWhitespace();
        expect('[');
        skipWhitespace();
        if (peek() == ']')
        {
            pos++;
            return list;
        }
        while (true)
        {
            skipWhitespace();
            list.add(parseValue());
            skipWhitespace();
            if (peek() == ',')
            {
                pos++;
                continue;
            }
            break;
        }
        skipWhitespace();
        expect(']');
        return list;
    }

    private Object parseValue()
    {
        skipWhitespace();
        char c = peek();
        if (c == '"') return doParseString();
        if (c == '{') return doParseObject();
        if (c == '[') return doParseArray();
        if (c == 't' || c == 'f') return doParseBoolean();
        if (c == 'n') return doParseNull();
        return doParseNumber();
    }

    private String doParseString()
    {
        expect('"');
        StringBuilder sb = new StringBuilder();
        while (pos < json.length())
        {
            char c = json.charAt(pos++);
            if (c == '\\')
            {
                if (pos >= json.length()) break;
                char esc = json.charAt(pos++);
                switch (esc)
                {
                    case '"':  sb.append('"'); break;
                    case '\\': sb.append('\\'); break;
                    case '/':  sb.append('/'); break;
                    case 'b':  sb.append('\b'); break;
                    case 'f':  sb.append('\f'); break;
                    case 'n':  sb.append('\n'); break;
                    case 'r':  sb.append('\r'); break;
                    case 't':  sb.append('\t'); break;
                    case 'u':
                        if (pos + 4 <= json.length())
                        {
                            String hex = json.substring(pos, pos + 4);
                            pos += 4;
                            sb.append((char) Integer.parseInt(hex, 16));
                        }
                        break;
                    default: sb.append(esc);
                }
            }
            else if (c == '"')
            {
                return sb.toString();
            }
            else
            {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private Number doParseNumber()
    {
        int start = pos;
        if (pos < json.length() && json.charAt(pos) == '-') pos++;
        // Integer part
        while (pos < json.length() && Character.isDigit(json.charAt(pos))) pos++;
        // Decimal part
        boolean isFloat = false;
        if (pos < json.length() && json.charAt(pos) == '.')
        {
            isFloat = true;
            pos++;
            while (pos < json.length() && Character.isDigit(json.charAt(pos))) pos++;
        }
        // Exponent part
        if (pos < json.length() && (json.charAt(pos) == 'e' || json.charAt(pos) == 'E'))
        {
            isFloat = true;
            pos++;
            if (pos < json.length() && (json.charAt(pos) == '+' || json.charAt(pos) == '-')) pos++;
            while (pos < json.length() && Character.isDigit(json.charAt(pos))) pos++;
        }
        String num = json.substring(start, pos);
        if (isFloat)
        {
            return Double.parseDouble(num);
        }
        return Long.parseLong(num);
    }

    private Boolean doParseBoolean()
    {
        if (json.startsWith("true", pos))
        {
            pos += 4;
            return Boolean.TRUE;
        }
        if (json.startsWith("false", pos))
        {
            pos += 5;
            return Boolean.FALSE;
        }
        throw new RuntimeException("Invalid boolean at position " + pos);
    }

    private Object doParseNull()
    {
        if (json.startsWith("null", pos))
        {
            pos += 4;
            return null;
        }
        throw new RuntimeException("Invalid null at position " + pos);
    }

    private void skipWhitespace()
    {
        while (pos < json.length() && Character.isWhitespace(json.charAt(pos))) pos++;
    }

    private char peek()
    {
        if (pos >= json.length()) throw new RuntimeException("Unexpected end of JSON at position " + pos);
        return json.charAt(pos);
    }

    private void expect(char c)
    {
        char actual = peek();
        if (actual != c) throw new RuntimeException("Expected '" + c + "' but found '" + actual + "' at position " + pos);
        pos++;
    }

    // ==================== Serialization ====================

    public static String toJson(Object obj)
    {
        if (obj == null) return "null";
        if (obj instanceof String) return quoteString((String) obj);
        if (obj instanceof Number) return obj.toString();
        if (obj instanceof Boolean) return obj.toString();
        if (obj instanceof Map) return mapToJson((Map<?, ?>) obj);
        if (obj instanceof List) return listToJson((List<?>) obj);
        if (obj instanceof ChatMessageLike) return messageToJson((ChatMessageLike) obj);
        return quoteString(obj.toString());
    }

    private static String mapToJson(Map<?, ?> map)
    {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<?, ?> e : map.entrySet())
        {
            if (!first) sb.append(",");
            sb.append(quoteString(e.getKey().toString())).append(":").append(toJson(e.getValue()));
            first = false;
        }
        sb.append("}");
        return sb.toString();
    }

    private static String listToJson(List<?> list)
    {
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        for (Object item : list)
        {
            if (!first) sb.append(",");
            sb.append(toJson(item));
            first = false;
        }
        sb.append("]");
        return sb.toString();
    }

    private static String messageToJson(ChatMessageLike msg)
    {
        StringBuilder sb = new StringBuilder("{");
        sb.append(quoteString("role")).append(":").append(quoteString(msg.role()));
        sb.append(",").append(quoteString("content")).append(":").append(quoteString(msg.content()));
        sb.append("}");
        return sb.toString();
    }

    public static String quoteString(String s)
    {
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++)
        {
            char c = s.charAt(i);
            switch (c)
            {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                default:
                    if (c < 0x20)
                    {
                        sb.append(String.format("\\u%04x", (int) c));
                    }
                    else
                    {
                        sb.append(c);
                    }
            }
        }
        sb.append("\"");
        return sb.toString();
    }

    // ==================== Convenience ====================

    @SuppressWarnings("unchecked")
    public static Map<String, Object> getMap(Map<String, Object> map, String key)
    {
        Object val = map.get(key);
        return val instanceof Map ? (Map<String, Object>) val : null;
    }

    @SuppressWarnings("unchecked")
    public static List<Object> getList(Map<String, Object> map, String key)
    {
        Object val = map.get(key);
        return val instanceof List ? (List<Object>) val : null;
    }

    public static String getString(Map<String, Object> map, String key)
    {
        Object val = map.get(key);
        return val instanceof String ? (String) val : null;
    }

    public static Integer getInt(Map<String, Object> map, String key)
    {
        Object val = map.get(key);
        return val instanceof Number ? ((Number) val).intValue() : null;
    }

    public static Double getDouble(Map<String, Object> map, String key)
    {
        Object val = map.get(key);
        return val instanceof Number ? ((Number) val).doubleValue() : null;
    }

    /**
     * Interface for serializable chat message objects.
     */
    public interface ChatMessageLike
    {
        String role();
        String content();
    }
}
