package ai.burp.util;

import java.util.Locale;
import java.util.Objects;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * 目标范围匹配器，用于流量分析和实时监控共享范围规则。
 */
public class TargetScopeMatcher
{
    private static final class ParsedEndpoint
    {
        private final String host;
        private final Integer port;
        private final boolean hasPort;

        private ParsedEndpoint(String host, Integer port, boolean hasPort)
        {
            this.host = host;
            this.port = port;
            this.hasPort = hasPort;
        }
    }

    public enum Mode
    {
        EXACT,
        SUBDOMAIN,
        REGEX;

        public static Mode fromUiValue(String value)
        {
            if (value == null) return EXACT;
            String normalized = value.trim().toLowerCase(Locale.ROOT);
            if (normalized.contains("子域")) return SUBDOMAIN;
            if (normalized.contains("regex") || normalized.contains("正则")) return REGEX;
            return EXACT;
        }
    }

    private final Mode mode;
    private final String patternText;
    private final Pattern regex;
    private final String normalizedHost;
    private final Integer normalizedPort;
    private final boolean portSpecified;

    private TargetScopeMatcher(Mode mode, String patternText, Pattern regex,
        String normalizedHost, Integer normalizedPort, boolean portSpecified)
    {
        this.mode = mode;
        this.patternText = patternText;
        this.regex = regex;
        this.normalizedHost = normalizedHost;
        this.normalizedPort = normalizedPort;
        this.portSpecified = portSpecified;
    }

    public static TargetScopeMatcher disabled()
    {
        return new TargetScopeMatcher(Mode.EXACT, "", null, "", null, false);
    }

    public static TargetScopeMatcher create(Mode mode, String patternText)
    {
        if (mode == Mode.REGEX)
        {
            try
            {
                String regexText = patternText == null ? "" : patternText.trim();
                if (regexText.isEmpty())
                {
                    throw new IllegalArgumentException("目标范围不能为空");
                }
                return new TargetScopeMatcher(mode, regexText,
                    Pattern.compile(regexText, Pattern.CASE_INSENSITIVE),
                    null, null, false);
            }
            catch (PatternSyntaxException e)
            {
                throw new IllegalArgumentException("目标正则无效: " + e.getDescription(), e);
            }
        }

        ParsedEndpoint parsed = parseEndpoint(patternText);
        if (parsed.host.isEmpty())
        {
            throw new IllegalArgumentException("目标范围不能为空");
        }

        return new TargetScopeMatcher(mode, formatEndpoint(parsed.host, parsed.port, parsed.hasPort),
            null, parsed.host, parsed.port, parsed.hasPort);
    }

    public boolean isEnabled()
    {
        return !patternText.isEmpty();
    }

    public boolean matchesHost(String host)
    {
        if (!isEnabled()) return true;
        if (host == null || host.trim().isEmpty()) return false;

        if (mode == Mode.REGEX)
        {
            return regex != null && regex.matcher(host.trim()).find();
        }

        ParsedEndpoint candidate = parseEndpoint(host);
        if (candidate.host.isEmpty()) return false;

        if (mode == Mode.EXACT)
        {
            if (!candidate.host.equals(normalizedHost))
            {
                return false;
            }
            if (portSpecified)
            {
                return candidate.hasPort && Objects.equals(candidate.port, normalizedPort);
            }
            return true;
        }

        if (portSpecified && (!candidate.hasPort || !Objects.equals(candidate.port, normalizedPort)))
        {
            return false;
        }

        return candidate.host.equals(normalizedHost) || candidate.host.endsWith("." + normalizedHost);
    }

    public String describe()
    {
        if (!isEnabled()) return "未设置";
        switch (mode)
        {
            case SUBDOMAIN: return "子域名匹配: " + patternText;
            case REGEX: return "正则匹配: " + patternText;
            default: return "精确主机: " + patternText;
        }
    }

    private static ParsedEndpoint parseEndpoint(String input)
    {
        if (input == null) return new ParsedEndpoint("", null, false);
        String value = input.trim().toLowerCase(Locale.ROOT);
        if (value.startsWith("http://")) value = value.substring(7);
        else if (value.startsWith("https://")) value = value.substring(8);
        int slash = value.indexOf('/');
        if (slash >= 0) value = value.substring(0, slash);
        int question = value.indexOf('?');
        if (question >= 0) value = value.substring(0, question);

        int hash = value.indexOf('#');
        if (hash >= 0) value = value.substring(0, hash);
        value = value.trim();
        if (value.isEmpty()) return new ParsedEndpoint("", null, false);

        if (value.startsWith("["))
        {
            int bracket = value.indexOf(']');
            if (bracket > 0)
            {
                String host = value.substring(1, bracket).trim();
                String rest = value.substring(bracket + 1).trim();
                if (rest.startsWith(":"))
                {
                    Integer port = tryParsePort(rest.substring(1));
                    if (port != null)
                    {
                        return new ParsedEndpoint(host, port, true);
                    }
                }
                return new ParsedEndpoint(host, null, false);
            }
        }

        int firstColon = value.indexOf(':');
        int lastColon = value.lastIndexOf(':');
        if (firstColon > 0 && firstColon == lastColon)
        {
            Integer port = tryParsePort(value.substring(lastColon + 1));
            if (port != null)
            {
                return new ParsedEndpoint(value.substring(0, lastColon).trim(), port, true);
            }
        }

        return new ParsedEndpoint(value, null, false);
    }

    private static Integer tryParsePort(String value)
    {
        try
        {
            int port = Integer.parseInt(value.trim());
            if (port >= 0 && port <= 65535)
            {
                return port;
            }
        }
        catch (Exception ignored) {}
        return null;
    }

    private static String formatEndpoint(String host, Integer port, boolean hasPort)
    {
        if (host == null || host.isEmpty()) return "";
        if (!hasPort || port == null) return host;
        if (host.indexOf(':') >= 0 && !host.startsWith("["))
        {
            return "[" + host + "]:" + port;
        }
        return host + ":" + port;
    }
}
