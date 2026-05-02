package ai.burp.util;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * 统一处理模型返回中的 JSON 提取、解析和字段读取。
 * 允许模型在 JSON 前后夹带解释文本，但所有调用方都通过同一套降级规则取值。
 */
public final class AiResponseParser
{
    private AiResponseParser() {}

    public static Map<String, Object> parseFirstObject(String text)
    {
        String json = extractFirstJsonObject(text);
        if (json == null) return Collections.<String, Object>emptyMap();

        Object parsed = tryParse(json);
        @SuppressWarnings("unchecked")
        Map<String, Object> result = parsed instanceof Map
            ? (Map<String, Object>) parsed : Collections.<String, Object>emptyMap();
        return result;
    }

    @SuppressWarnings("unchecked")
    public static List<Map<String, Object>> parseFirstObjectArray(String text)
    {
        String json = extractFirstJsonArray(text);
        if (json == null) return Collections.emptyList();

        Object parsed = tryParse(json);
        if (!(parsed instanceof List)) return Collections.emptyList();

        List<Map<String, Object>> result = new ArrayList<>();
        for (Object item : (List<Object>) parsed)
        {
            if (item instanceof Map)
            {
                result.add((Map<String, Object>) item);
            }
        }
        return result;
    }

    public static String getString(Map<String, Object> map, String key)
    {
        String value = SimpleJson.getString(map, key);
        return value != null ? value : "";
    }

    public static String getTrimmedLowerString(Map<String, Object> map, String key)
    {
        return getString(map, key).trim().toLowerCase(Locale.ROOT);
    }

    public static double getDouble(Map<String, Object> map, String key, double defaultValue)
    {
        Double value = SimpleJson.getDouble(map, key);
        return value != null ? value.doubleValue() : defaultValue;
    }

    public static int getInt(Map<String, Object> map, String key, int defaultValue)
    {
        Integer value = SimpleJson.getInt(map, key);
        return value != null ? value.intValue() : defaultValue;
    }

    public static boolean getBoolean(Map<String, Object> map, String key, boolean defaultValue)
    {
        Object value = map.get(key);
        return value instanceof Boolean ? ((Boolean) value).booleanValue() : defaultValue;
    }

    public static List<String> getStringList(Map<String, Object> map, String key)
    {
        List<Object> list = SimpleJson.getList(map, key);
        if (list == null || list.isEmpty()) return Collections.emptyList();

        List<String> result = new ArrayList<>();
        for (Object item : list)
        {
            if (item instanceof String)
            {
                String value = ((String) item).trim();
                if (!value.isEmpty()) result.add(value);
            }
        }
        return result;
    }

    @SuppressWarnings("unchecked")
    public static List<Map<String, Object>> getObjectList(Map<String, Object> map, String key)
    {
        List<Object> list = SimpleJson.getList(map, key);
        if (list == null || list.isEmpty()) return Collections.emptyList();

        List<Map<String, Object>> result = new ArrayList<>();
        for (Object item : list)
        {
            if (item instanceof Map)
            {
                result.add((Map<String, Object>) item);
            }
        }
        return result;
    }

    public static String extractFirstJsonObject(String text)
    {
        return findFirstParsableSegment(text, '{', '}', SegmentType.OBJECT);
    }

    public static String extractFirstJsonArray(String text)
    {
        return findFirstParsableSegment(text, '[', ']', SegmentType.ARRAY);
    }

    private static String findFirstParsableSegment(String text, char open, char close, SegmentType type)
    {
        if (text == null || text.trim().isEmpty()) return null;

        for (int start = 0; start < text.length(); start++)
        {
            if (text.charAt(start) != open) continue;

            int end = findBalancedEnd(text, start, open, close);
            if (end < 0) continue;

            String candidate = text.substring(start, end + 1);
            Object parsed = tryParse(candidate);
            if (parsed == null) continue;
            if (type == SegmentType.OBJECT && parsed instanceof Map) return candidate;
            if (type == SegmentType.ARRAY && parsed instanceof List) return candidate;
        }

        return null;
    }

    private static int findBalancedEnd(String text, int start, char open, char close)
    {
        int depth = 0;
        boolean inString = false;
        boolean escaped = false;

        for (int i = start; i < text.length(); i++)
        {
            char c = text.charAt(i);

            if (escaped)
            {
                escaped = false;
                continue;
            }
            if (c == '\\')
            {
                escaped = true;
                continue;
            }
            if (c == '"')
            {
                inString = !inString;
                continue;
            }
            if (inString) continue;

            if (c == open)
            {
                depth++;
            }
            else if (c == close && depth > 0)
            {
                depth--;
                if (depth == 0 && start >= 0)
                {
                    return i;
                }
            }
        }

        return -1;
    }

    private static Object tryParse(String candidate)
    {
        try
        {
            return SimpleJson.parse(candidate);
        }
        catch (Exception ignored)
        {
            return null;
        }
    }

    private enum SegmentType
    {
        OBJECT,
        ARRAY
    }
}
