package ai.burp.util;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import ai.burp.model.VulnReport;

/**
 * AI 漏洞发现结果的统一筛选策略。
 * 目标：减少低价值噪声，并将同一请求上的发现收敛为一个最有价值的漏洞。
 */
public final class VulnFindingPolicy
{
    private VulnFindingPolicy() {}

    public static boolean shouldKeep(VulnReport report)
    {
        if (report == null) return false;
        return shouldKeep(report.getVulnType(),
            report.getSeverity() != null ? report.getSeverity().label() : "",
            report.getConfidence(),
            report.getEvidence(),
            report.getDescription(),
            report.getCategory());
    }

    public static boolean shouldKeep(String vulnType, String severityText, double confidence,
        String evidence, String description, String category)
    {
        String type = lower(vulnType);
        String severity = lower(severityText);
        String detail = lower(description);
        String cat = lower(category);
        String ev = lower(evidence);

        if (type.isEmpty()) return false;
        if (confidence < 0.7) return false;

        // POC库匹配结果（技术栈关键词匹配+已知CVE）直接放行，有CVE编号作为强证据
        if (type.startsWith("潜在组件风险:")) return true;

        if ((severity.contains("信息") || severity.contains("info")) && !hasStrongEvidence(ev))
        {
            return false;
        }

        if (isWeakEvidence(ev))
        {
            return false;
        }

        boolean genericLowValue = isGenericLowValueType(type, cat, detail);
        if (genericLowValue)
        {
            if (!hasStrongEvidence(ev)) return false;
            if (isSensitiveLeakEvidence(ev))
            {
                return true;
            }
            if (!(severity.contains("中") || severity.contains("高") || severity.contains("严重")
                || severity.contains("medium") || severity.contains("high") || severity.contains("critical")))
            {
                return false;
            }
        }

        return true;
    }

    public static List<VulnReport> keepTopOnePerRequest(List<VulnReport> reports)
    {
        Map<String, VulnReport> bestByRequest = new LinkedHashMap<>();
        if (reports == null || reports.isEmpty()) return new ArrayList<>();

        for (VulnReport report : reports)
        {
            if (!shouldKeep(report)) continue;

            String key = requestKey(report);
            VulnReport existing = bestByRequest.get(key);
            if (existing == null || score(report) > score(existing))
            {
                bestByRequest.put(key, report);
            }
        }

        return new ArrayList<>(bestByRequest.values());
    }

    public static int score(VulnReport report)
    {
        if (report == null) return Integer.MIN_VALUE;
        int severityScore = report.getSeverity() != null ? report.getSeverity().level() * 100 : 0;
        int confidenceScore = (int) Math.round(report.getConfidence() * 100);
        int typeScore = vulnTypePriority(report.getVulnType());
        int evidenceScore = Math.min(30, safe(report.getEvidence()).length() / 8);
        return severityScore + confidenceScore + typeScore + evidenceScore;
    }

    public static int score(String vulnType, String severityText, double confidence,
        String evidence, String description, String category)
    {
        VulnReport tmp = new VulnReport();
        tmp.setVulnType(vulnType);
        tmp.setSeverity(VulnReport.Severity.fromString(severityText));
        tmp.setConfidence(confidence);
        tmp.setEvidence(evidence);
        tmp.setDescription(description);
        tmp.setCategory(category);
        return score(tmp);
    }

    private static String requestKey(VulnReport report)
    {
        String originalRequest = safe(report.getOriginalRequest()).trim();
        if (!originalRequest.isEmpty())
        {
            return originalRequest;
        }
        String method = safe(report.getMethod()).trim();
        String url = safe(report.getUrl()).trim();
        if (!method.isEmpty() || !url.isEmpty())
        {
            return method + "|" + url;
        }
        return safe(report.getHost()).trim() + "|" + safe(report.getVulnType()).trim();
    }

    private static boolean isGenericLowValueType(String type, String category, String detail)
    {
        String text = type + " " + category + " " + detail;
        return text.contains("配置不当")
            || text.contains("安全配置")
            || text.contains("misconfig")
            || text.contains("header")
            || text.contains("banner")
            || text.contains("版本泄露")
            || text.contains("server头")
            || text.contains("x-powered-by")
            || text.contains("csp")
            || text.contains("hsts")
            || text.contains("x-frame-options")
            || text.contains("x-content-type-options")
            || text.contains("调试信息")
            || text.contains("目录索引")
            || (text.contains("信息泄露") && !text.contains("敏感文件") && !text.contains("敏感数据"));
    }

    private static boolean hasStrongEvidence(String evidence)
    {
        if (evidence.isEmpty()) return false;
        return evidence.contains("sql")
            || evidence.contains("syntax")
            || evidence.contains("exception")
            || evidence.contains("stack")
            || evidence.contains("trace")
            || evidence.contains("token")
            || evidence.contains("secret")
            || evidence.contains("password")
            || evidence.contains("passwd")
            || evidence.contains("authorization")
            || evidence.contains("bearer")
            || evidence.contains("session")
            || evidence.contains("cookie")
            || evidence.contains(".env")
            || evidence.contains("web.config")
            || evidence.contains("/etc/passwd")
            || evidence.contains("private key")
            || evidence.contains("jdbc")
            || evidence.contains("burpcollaborator")
            || evidence.contains("dns")
            || evidence.contains("凭证")
            || evidence.contains("密钥")
            || evidence.contains("口令")
            || evidence.contains("堆栈")
            || evidence.contains("报错")
            || evidence.contains("回显");
    }

    private static boolean isSensitiveLeakEvidence(String evidence)
    {
        if (evidence.isEmpty()) return false;
        return evidence.contains("token")
            || evidence.contains("secret")
            || evidence.contains("password")
            || evidence.contains("passwd")
            || evidence.contains("authorization")
            || evidence.contains("bearer")
            || evidence.contains("session")
            || evidence.contains("cookie")
            || evidence.contains(".env")
            || evidence.contains("web.config")
            || evidence.contains("/etc/passwd")
            || evidence.contains("private key")
            || evidence.contains("stack")
            || evidence.contains("trace")
            || evidence.contains("凭证")
            || evidence.contains("密钥")
            || evidence.contains("口令")
            || evidence.contains("堆栈");
    }

    private static boolean isWeakEvidence(String evidence)
    {
        if (evidence.isEmpty()) return true;
        return evidence.contains("可能存在")
            || evidence.contains("疑似")
            || evidence.contains("需要进一步验证")
            || evidence.contains("推测")
            || evidence.contains("无直接证据")
            || evidence.equals("存在风险")
            || evidence.equals("响应异常");
    }

    private static int vulnTypePriority(String vulnType)
    {
        String type = lower(vulnType);
        if (type.contains("rce") || type.contains("命令注入") || type.contains("代码执行")) return 120;
        if (type.contains("sql") || type.contains("sqli")) return 110;
        if (type.contains("ssrf") || type.contains("xxe")) return 105;
        if (type.contains("反序列化") || type.contains("ssti")) return 100;
        if (type.contains("越权") || type.contains("idor") || type.contains("未授权")) return 95;
        if (type.contains("上传") || type.contains("文件包含") || type.contains("路径遍历")) return 90;
        if (type.contains("xss")) return 80;
        if (type.contains("信息泄露") || type.contains("配置不当") || type.contains("csp")
            || type.contains("hsts") || type.contains("cors"))
        {
            return 10;
        }
        return 50;
    }

    private static String lower(String value)
    {
        return safe(value).trim().toLowerCase(Locale.ROOT);
    }

    private static String safe(String value)
    {
        return value == null ? "" : value;
    }
}
