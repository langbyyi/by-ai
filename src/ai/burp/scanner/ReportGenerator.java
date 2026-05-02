package ai.burp.scanner;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;

import ai.burp.model.VulnReport;

/**
 * 标准化漏洞报告生成器。
 * 每个漏洞包含：漏洞名称、风险等级、漏洞原理、影响范围、复现步骤、验证Payload、修复建议。
 * 支持导出为HTML和纯文本格式。
 */
public class ReportGenerator
{
    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    /**
     * 导出报告到文件。
     */
    public static void exportToFile(String filePath, String content) throws IOException
    {
        try (OutputStreamWriter writer = new OutputStreamWriter(
            new FileOutputStream(filePath), StandardCharsets.UTF_8))
        {
            writer.write(content);
        }
    }

    /**
     * 从 VulnReport 列表生成 Markdown 格式漏洞报告（符合企业报告规范）。
     */
    public static String generateVulnReportMarkdown(String target, List<VulnReport> reports)
    {
        StringBuilder sb = new StringBuilder();

        // 报告头
        sb.append("# 安全漏洞评估报告\n\n");
        sb.append("---\n\n");

        // 基本信息
        sb.append("## 1. 报告概要\n\n");
        sb.append("| 项目 | 内容 |\n| --- | --- |\n");
        sb.append("| 报告标题 | 安全漏洞评估报告 |\n");
        sb.append("| 评估目标 | ").append(target).append(" |\n");
        sb.append("| 生成时间 | ").append(LocalDateTime.now().format(FMT)).append(" |\n");
        sb.append("| 扫描引擎 | by ai |\n");
        sb.append("| 漏洞总数 | ").append(reports.size()).append(" |\n");
        sb.append("| 风险评分 | ").append(calcRiskScore(reports)).append(" |\n\n");

        // 统计摘要
        Map<VulnReport.Severity, Integer> sevCount = new LinkedHashMap<>();
        Map<String, Integer> typeCount = new LinkedHashMap<>();
        int confirmed = 0, pending = 0, unverified = 0, falsePositive = 0;
        for (VulnReport r : reports)
        {
            sevCount.merge(r.getSeverity(), 1, Integer::sum);
            typeCount.merge(r.getVulnType(), 1, Integer::sum);
            switch (r.getVerifyStatus())
            {
                case CONFIRMED: confirmed++; break;
                case PENDING: pending++; break;
                case UNVERIFIED: unverified++; break;
                case FALSE_POSITIVE: falsePositive++; break;
            }
        }

        sb.append("## 2. 风险统计\n\n");
        sb.append("### 2.1 验证状态分布\n\n");
        sb.append("| 状态 | 数量 |\n| --- | --- |\n");
        sb.append("| 已确认 | ").append(confirmed).append(" |\n");
        sb.append("| 待验证 | ").append(pending).append(" |\n");
        sb.append("| 无法验证 | ").append(unverified).append(" |\n");
        sb.append("| 误报 | ").append(falsePositive).append(" |\n\n");

        sb.append("### 2.2 严重性分布\n\n");
        sb.append("| 严重性 | 数量 |\n| --- | --- |\n");
        for (Map.Entry<VulnReport.Severity, Integer> e : sevCount.entrySet())
        {
            sb.append("| ").append(e.getKey().label()).append(" | ").append(e.getValue()).append(" |\n");
        }
        sb.append("\n");

        sb.append("### 2.3 漏洞类型分布\n\n");
        sb.append("| 漏洞类型 | 数量 |\n| --- | --- |\n");
        typeCount.entrySet().stream()
            .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
            .forEach(e -> sb.append("| ").append(e.getKey()).append(" | ").append(e.getValue()).append(" |\n"));
        sb.append("\n");

        // 漏洞详情
        sb.append("## 3. 漏洞详情\n\n");
        int idx = 1;
        for (VulnReport r : reports)
        {
            sb.append("### 3.").append(idx).append(" ").append(r.getVulnType())
              .append(" [").append(r.getSeverity().label()).append("]\n\n");

            sb.append("| 属性 | 值 |\n| --- | --- |\n");
            if (r.getUrl() != null) sb.append("| URL | `").append(r.getUrl()).append("` |\n");
            if (r.getMethod() != null) sb.append("| HTTP方法 | ").append(r.getMethod()).append(" |\n");
            if (r.getHost() != null) sb.append("| 主机 | ").append(r.getHost()).append(" |\n");
            if (r.getParameter() != null && !r.getParameter().isEmpty())
                sb.append("| 受影响参数 | `").append(r.getParameter()).append("` |\n");
            if (r.hasTimingData())
            {
                StringBuilder timing = new StringBuilder();
                if (r.getTtfbMs() > 0) timing.append("TTFB=").append(r.getTtfbMs()).append("ms");
                if (r.getTtlbMs() > 0)
                {
                    if (r.getTtfbMs() > 0) timing.append(", ");
                    timing.append("TTLB=").append(r.getTtlbMs()).append("ms");
                }
                if (timing.length() > 0) sb.append("| 响应时间 | ").append(timing).append(" |\n");
            }
            sb.append("| 严重性 | ").append(r.getSeverity().label()).append(" |\n");
            sb.append("| 验证状态 | ").append(r.getVerifyStatus().label()).append(" |\n");
            if (r.getConfidence() > 0) sb.append("| 置信度 | ").append(String.format("%.0f%%", r.getConfidence() * 100)).append(" |\n");
            if (r.getCategory() != null) sb.append("| 分类 | ").append(r.getCategory()).append(" |\n");
            if (!r.getTags().isEmpty()) sb.append("| 标签 | ").append(String.join(", ", r.getTags())).append(" |\n");
            sb.append("\n");

            if (r.getDescription() != null && !r.getDescription().isEmpty())
                sb.append("**漏洞描述:** ").append(r.getDescription()).append("\n\n");

            if (r.getEvidence() != null && !r.getEvidence().isEmpty())
                sb.append("**验证证据:** ").append(r.getEvidence()).append("\n\n");

            if (r.getSuggestion() != null && !r.getSuggestion().isEmpty())
                sb.append("**修复建议:** ").append(r.getSuggestion()).append("\n\n");

            if (r.getTestPayload() != null && !r.getTestPayload().isEmpty())
                sb.append("**测试Payload:**\n```\n").append(r.getTestPayload()).append("\n```\n\n");

            if (r.getVerificationDetail() != null && !r.getVerificationDetail().isEmpty())
                sb.append("**验证详情:** ").append(r.getVerificationDetail()).append("\n\n");

            if (r.getOriginalRequest() != null && !r.getOriginalRequest().isEmpty())
            {
                String origReq = r.getOriginalRequest();
                if (origReq.length() > 8000) origReq = origReq.substring(0, 8000) + "\n... [已截断]";
                sb.append("**原始请求:**\n```http\n").append(origReq).append("\n```\n\n");
            }

            if (r.getReproduceRequest() != null && !r.getReproduceRequest().isEmpty())
                sb.append("**可复现请求:**\n```http\n").append(r.getReproduceRequest()).append("\n```\n\n");

            if (r.getOriginalResponse() != null && !r.getOriginalResponse().isEmpty())
            {
                String resp = r.getOriginalResponse();
                if (resp.length() > 8000) resp = resp.substring(0, 8000) + "\n... [已截断]";
                sb.append("**原始响应:**\n```http\n").append(resp).append("\n```\n\n");
            }

            if (r.getTestResponse() != null && !r.getTestResponse().isEmpty()
                && !r.getTestResponse().equals(r.getOriginalResponse()))
            {
                String tResp = r.getTestResponse();
                if (tResp.length() > 8000) tResp = tResp.substring(0, 8000) + "\n... [已截断]";
                sb.append("**测试响应:**\n```http\n").append(tResp).append("\n```\n\n");
            }

            sb.append("---\n\n");
            idx++;
        }

        // 附录
        sb.append("## 4. 附录\n\n");
        sb.append("本报告由 by ai 自动生成，所有漏洞均经 AI 辅助分析和验证。\n");
        sb.append("建议结合手动测试进一步确认漏洞的可利用性和实际影响。\n");

        return sb.toString();
    }

    /**
     * 增强版 HTML 报告（符合企业报告规范）。
     * 包含封面、目录、统计概要（含可视化柱状图）、风险评分、详细漏洞描述、修复优先级、附录。
     */
    public static String generateVulnReportHtmlEnterprise(String target, List<VulnReport> reports)
    {
        StringBuilder sb = new StringBuilder();
        sb.append("<!DOCTYPE html>\n<html lang='zh-CN'>\n<head>\n");
        sb.append("<meta charset='UTF-8'>\n");
        sb.append("<meta name='viewport' content='width=device-width, initial-scale=1.0'>\n");
        sb.append("<title>安全漏洞评估报告 - ").append(escape(target)).append("</title>\n");
        sb.append("<style>\n");

        // 基础重置
        sb.append("*, *::before, *::after { box-sizing: border-box; }\n");
        sb.append("body { font-family: 'Microsoft YaHei', 'PingFang SC', 'SimHei', Arial, sans-serif; margin: 0; background: #f0f2f5; color: #333; line-height: 1.6; }\n");

        // 封面 - 浅色
        sb.append(".cover { background: #fff; color: #1a237e; padding: 48px 50px; border-bottom: 3px solid #1a237e; }\n");
        sb.append(".cover h1 { font-size: 28px; margin: 0 0 6px 0; border: none; font-weight: 700; letter-spacing: 1px; }\n");
        sb.append(".cover .subtitle { font-size: 14px; color: #666; font-weight: 400; letter-spacing: 2px; }\n");
        sb.append(".cover .meta-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-top: 30px; }\n");
        sb.append(".cover .meta-item { background: #f5f7ff; border: 1px solid #e0e3f0; border-radius: 6px; padding: 12px 16px; }\n");
        sb.append(".cover .meta-label { font-size: 11px; color: #888; text-transform: uppercase; letter-spacing: 1px; }\n");
        sb.append(".cover .meta-value { font-size: 16px; font-weight: 600; margin-top: 4px; color: #333; }\n");

        // 内容容器
        sb.append(".content { max-width: 1100px; margin: 0 auto; padding: 24px 20px; }\n");

        // 目录
        sb.append(".toc { background: #fff; padding: 24px 28px; border-radius: 10px; margin: 24px 0; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }\n");
        sb.append(".toc h2 { color: #1a237e; margin: 0 0 16px 0; font-size: 18px; }\n");
        sb.append(".toc ul { list-style: none; padding: 0; margin: 0; }\n");
        sb.append(".toc li { padding: 6px 0; }\n");
        sb.append(".toc a { color: #3949ab; text-decoration: none; font-size: 14px; }\n");
        sb.append(".toc a:hover { color: #1a237e; text-decoration: underline; }\n");

        // 区块
        sb.append(".section { background: #fff; padding: 24px 28px; border-radius: 10px; margin: 20px 0; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }\n");
        sb.append("h1 { color: #1a237e; border-bottom: 3px solid #1a237e; padding-bottom: 10px; margin-top: 40px; }\n");
        sb.append("h2 { color: #1a237e; margin: 0 0 16px 0; font-size: 18px; }\n");
        sb.append("h3 { color: #3949ab; margin: 20px 0 12px 0; font-size: 16px; }\n");

        // 风险评分卡 - 浅色
        sb.append(".risk-card { background: #f5f7ff; color: #333; border: 2px solid #1a237e; border-radius: 8px; padding: 24px; margin: 20px 0; display: flex; align-items: center; gap: 32px; }\n");
        sb.append(".risk-score { text-align: center; min-width: 120px; }\n");
        sb.append(".risk-score .number { font-size: 44px; font-weight: 800; line-height: 1; color: #1a237e; }\n");
        sb.append(".risk-score .label { font-size: 14px; color: #666; margin-top: 6px; }\n");
        sb.append(".risk-details { flex: 1; }\n");
        sb.append(".risk-bar { height: 8px; background: #e0e0e0; border-radius: 4px; margin: 8px 0; }\n");
        sb.append(".risk-bar-fill { height: 100%; border-radius: 4px; transition: width 0.3s; }\n");

        // 表格
        sb.append("table { border-collapse: collapse; width: 100%; margin: 12px 0; }\n");
        sb.append("th { background: #1a237e; color: #fff; padding: 10px 14px; text-align: left; font-size: 13px; font-weight: 600; }\n");
        sb.append("td { padding: 10px 14px; border-bottom: 1px solid #eee; font-size: 13px; }\n");
        sb.append("tr:hover { background: #f5f7ff; }\n");

        // 严重性徽章
        sb.append(".sev-badge { display: inline-block; padding: 3px 12px; border-radius: 4px; font-size: 12px; font-weight: 700; color: #fff; }\n");
        sb.append(".sev-critical { background: #b71c1c; }\n");
        sb.append(".sev-high { background: #d32f2f; }\n");
        sb.append(".sev-medium { background: #e65100; }\n");
        sb.append(".sev-low { background: #1976d2; }\n");
        sb.append(".sev-info { background: #78909c; }\n");

        // 状态徽章
        sb.append(".badge { display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 12px; font-weight: 600; }\n");
        sb.append(".badge-confirmed { background: #e8f5e9; color: #2e7d32; }\n");
        sb.append(".badge-pending { background: #fff3e0; color: #e65100; }\n");
        sb.append(".badge-unverified { background: #fce4ec; color: #c62828; }\n");
        sb.append(".badge-false-positive { background: #f5f5f5; color: #999; }\n");

        // 漏洞卡片
        sb.append(".vuln-card { margin: 16px 0; padding: 0; border: 1px solid #e8eaf6; border-radius: 10px; background: #fff; overflow: hidden; transition: box-shadow 0.2s; }\n");
        sb.append(".vuln-card:hover { box-shadow: 0 4px 12px rgba(0,0,0,0.1); }\n");
        sb.append(".vuln-header { display: flex; justify-content: space-between; align-items: center; padding: 16px 20px; background: #fafbff; border-bottom: 1px solid #e8eaf6; }\n");
        sb.append(".vuln-id { font-size: 12px; color: #9e9e9e; font-family: 'Consolas', monospace; }\n");
        sb.append(".vuln-title { font-size: 16px; font-weight: 700; color: #1a237e; margin-left: 8px; }\n");
        sb.append(".vuln-badges { display: flex; gap: 8px; align-items: center; }\n");
        sb.append(".vuln-body { padding: 16px 20px; }\n");
        sb.append(".detail-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 10px 24px; margin: 10px 0; }\n");
        sb.append(".detail-item { display: flex; gap: 8px; }\n");
        sb.append(".detail-label { font-weight: 600; color: #666; min-width: 70px; font-size: 13px; }\n");
        sb.append(".detail-value { color: #333; font-size: 13px; word-break: break-all; }\n");

        // 严重性侧边条
        sb.append(".sev-strip-critical { border-left: 4px solid #b71c1c; }\n");
        sb.append(".sev-strip-high { border-left: 4px solid #d32f2f; }\n");
        sb.append(".sev-strip-medium { border-left: 4px solid #e65100; }\n");
        sb.append(".sev-strip-low { border-left: 4px solid #1976d2; }\n");
        sb.append(".sev-strip-info { border-left: 4px solid #78909c; }\n");

        // 代码块 - 浅色
        sb.append("code { background: #f0f0f0; padding: 2px 6px; border-radius: 3px; font-family: 'Consolas', 'Courier New', monospace; font-size: 12px; }\n");
        sb.append("pre { background: #f8f8f8; color: #333; padding: 14px; border-radius: 6px; overflow-x: auto; font-family: 'Consolas', 'Courier New', monospace; font-size: 12px; line-height: 1.5; margin: 8px 0; border: 1px solid #e0e0e0; }\n");

        // 描述区块
        sb.append(".desc-block { margin: 12px 0; padding: 10px 14px; border-radius: 6px; font-size: 13px; }\n");
        sb.append(".desc-block-title { font-weight: 700; margin-bottom: 4px; }\n");
        sb.append(".desc-danger { background: #fff5f5; border-left: 3px solid #d32f2f; }\n");
        sb.append(".desc-danger .desc-block-title { color: #c62828; }\n");
        sb.append(".desc-info { background: #f0f4ff; border-left: 3px solid #3949ab; }\n");
        sb.append(".desc-info .desc-block-title { color: #1a237e; }\n");
        sb.append(".desc-success { background: #f0fff4; border-left: 3px solid #2e7d32; }\n");
        sb.append(".desc-success .desc-block-title { color: #2e7d32; }\n");
        sb.append(".desc-warning { background: #fffbf0; border-left: 3px solid #e65100; }\n");
        sb.append(".desc-warning .desc-block-title { color: #e65100; }\n");

        // 柱状图
        sb.append(".chart-bar-container { margin: 8px 0; }\n");
        sb.append(".chart-row { display: flex; align-items: center; margin: 6px 0; }\n");
        sb.append(".chart-label { width: 60px; font-size: 13px; font-weight: 600; text-align: right; padding-right: 12px; }\n");
        sb.append(".chart-bar-bg { flex: 1; height: 24px; background: #f0f0f0; border-radius: 4px; overflow: hidden; position: relative; }\n");
        sb.append(".chart-bar-fill { height: 100%; border-radius: 4px; display: flex; align-items: center; justify-content: flex-end; padding-right: 8px; color: #fff; font-size: 11px; font-weight: 700; min-width: 24px; transition: width 0.3s; }\n");

        // 页脚
        sb.append(".footer { text-align: center; color: #aaa; margin-top: 40px; padding: 24px; font-size: 12px; border-top: 1px solid #eee; }\n");

        // 打印
        sb.append("@media print {\n");
        sb.append("  .cover { background: #1a237e !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }\n");
        sb.append("  .section, .vuln-card { break-inside: avoid; }\n");
        sb.append("  .vuln-card:hover { box-shadow: none; }\n");
        sb.append("  .risk-card { background: #1a237e !important; -webkit-print-color-adjust: exact; }\n");
        sb.append("  body { background: #fff; }\n");
        sb.append("}\n");

        sb.append("</style>\n</head>\n<body>\n");

        // ==================== 封面 ====================
        sb.append("<div class='cover'>\n");
        sb.append("<h1>安全漏洞评估报告</h1>\n");
        sb.append("<div class='subtitle'>SECURITY VULNERABILITY ASSESSMENT REPORT</div>\n");
        sb.append("<div class='meta-grid'>\n");
        sb.append("<div class='meta-item'><div class='meta-label'>评估目标</div><div class='meta-value'>").append(escape(target)).append("</div></div>\n");
        sb.append("<div class='meta-item'><div class='meta-label'>报告日期</div><div class='meta-value'>").append(LocalDateTime.now().format(FMT)).append("</div></div>\n");
        sb.append("<div class='meta-item'><div class='meta-label'>漏洞总数</div><div class='meta-value'>").append(reports.size()).append("</div></div>\n");
        sb.append("<div class='meta-item'><div class='meta-label'>扫描引擎</div><div class='meta-value'>by ai</div></div>\n");
        sb.append("</div>\n</div>\n");

        sb.append("<div class='content'>\n");

        // ==================== 统计数据 ====================
        Map<VulnReport.Severity, Integer> severityCount = new LinkedHashMap<>();
        Map<String, Integer> typeCount = new LinkedHashMap<>();
        int confirmed = 0, pending = 0, unverified = 0, falsePositive = 0;
        for (VulnReport r : reports)
        {
            severityCount.merge(r.getSeverity(), 1, Integer::sum);
            typeCount.merge(r.getVulnType(), 1, Integer::sum);
            switch (r.getVerifyStatus())
            {
                case CONFIRMED: confirmed++; break;
                case PENDING: pending++; break;
                case UNVERIFIED: unverified++; break;
                case FALSE_POSITIVE: falsePositive++; break;
            }
        }

        int riskScore = calcRiskScore(reports);
        String riskLevel = riskLabel(riskScore);
        String riskColor = riskHexColor(riskScore);

        // ==================== 目录 ====================
        sb.append("<div class='toc'>\n<h2>目录</h2>\n<ul>\n");
        sb.append("<li><a href='#summary'>1. 风险评估概要</a></li>\n");
        sb.append("<li><a href='#severity'>2. 严重性分布</a></li>\n");
        sb.append("<li><a href='#details'>3. 漏洞总览</a></li>\n");
        sb.append("<li><a href='#vulndetail'>4. 漏洞详情</a></li>\n");
        sb.append("<li><a href='#appendix'>5. 附录</a></li>\n");
        sb.append("</ul>\n</div>\n");

        // ==================== 风险评分卡 ====================
        sb.append("<div class='risk-card' id='summary'>\n");
        sb.append("<div class='risk-score'>\n");
        sb.append("<div class='number'>").append(riskScore).append("</div>\n");
        sb.append("<div class='label'>").append(riskLevel).append("</div>\n");
        sb.append("</div>\n");
        sb.append("<div class='risk-details'>\n");
        sb.append("<div style='display:grid;grid-template-columns:repeat(4,1fr);gap:16px;'>\n");
        sb.append("<div><div style='font-size:24px;font-weight:700;color:#1a237e;'>").append(confirmed)
          .append("</div><div style='font-size:12px;color:#666;'>已确认</div></div>\n");
        sb.append("<div><div style='font-size:24px;font-weight:700;color:#e65100;'>").append(pending)
          .append("</div><div style='font-size:12px;color:#666;'>待验证</div></div>\n");
        sb.append("<div><div style='font-size:24px;font-weight:700;color:#f57c00;'>").append(unverified)
          .append("</div><div style='font-size:12px;color:#666;'>无法验证</div></div>\n");
        sb.append("<div><div style='font-size:24px;font-weight:700;color:#999;'>").append(falsePositive)
          .append("</div><div style='font-size:12px;color:#666;'>误报</div></div>\n");
        sb.append("</div>\n");
        // 风险条
        int maxRisk = reports.size() * 10; // 每个漏洞最高10分
        int riskPct = maxRisk > 0 ? Math.min(100, riskScore * 100 / maxRisk) : 0;
        sb.append("<div class='risk-bar'><div class='risk-bar-fill' style='width:")
          .append(riskPct).append("%;background:").append(riskColor).append(";'></div></div>\n");
        sb.append("<div style='font-size:12px;opacity:0.6;'>综合风险指数: ")
          .append(riskPct).append("%</div>\n");
        sb.append("</div>\n</div>\n");

        // ==================== 严重性分布 ====================
        sb.append("<div class='section' id='severity'>\n<h2>2. 严重性分布</h2>\n");
        sb.append("<div class='chart-bar-container'>\n");
        int maxSev = severityCount.values().stream().mapToInt(i -> i).max().orElse(1);
        for (Map.Entry<VulnReport.Severity, Integer> e : severityCount.entrySet())
        {
            String css = getSevBarClass(e.getKey());
            String barColor = getSevBarColor(e.getKey());
            double pct = e.getValue() * 100.0 / maxSev;
            sb.append("<div class='chart-row'>\n");
            sb.append("<div class='chart-label'>").append(e.getKey().label()).append("</div>\n");
            sb.append("<div class='chart-bar-bg'><div class='chart-bar-fill' style='width:")
              .append(String.format("%.0f%%", pct)).append(";background:").append(barColor).append(";'>")
              .append(e.getValue()).append("</div></div>\n");
            sb.append("</div>\n");
        }
        sb.append("</div>\n");

        // 详细表格
        sb.append("<table style='margin-top:16px;'><tr><th>严重性</th><th>数量</th><th>占比</th><th>风险权重</th></tr>\n");
        for (Map.Entry<VulnReport.Severity, Integer> e : severityCount.entrySet())
        {
            String css = getSevBarClass(e.getKey());
            double pct = reports.size() > 0 ? (e.getValue() * 100.0 / reports.size()) : 0;
            sb.append("<tr><td><span class='sev-badge ").append(css).append("'>").append(e.getKey().label())
              .append("</span></td><td>").append(e.getValue()).append("</td><td>")
              .append(String.format("%.1f%%", pct)).append("</td><td>").append(e.getKey().level()).append("</td></tr>\n");
        }
        sb.append("</table>\n</div>\n");

        // ==================== 漏洞总览表 ====================
        sb.append("<div class='section' id='details'>\n<h2>3. 漏洞总览</h2>\n");
        sb.append("<table><tr><th>#</th><th>漏洞类型</th><th>URL</th><th>参数</th><th>严重性</th><th>状态</th><th>置信度</th></tr>\n");
        for (int i = 0; i < reports.size(); i++)
        {
            VulnReport r = reports.get(i);
            String sevCss = getSevBarClass(r.getSeverity());
            String statusBadge = r.getVerifyStatus() == VulnReport.VerifyStatus.CONFIRMED ? "badge-confirmed"
                : r.getVerifyStatus() == VulnReport.VerifyStatus.FALSE_POSITIVE ? "badge-false-positive"
                : r.getVerifyStatus() == VulnReport.VerifyStatus.UNVERIFIED ? "badge-unverified"
                : "badge-pending";
            sb.append("<tr><td><a href='#vuln-").append(i + 1).append("'>").append(i + 1).append("</a></td>");
            sb.append("<td><b>").append(escape(r.getVulnType())).append("</b></td>");
            sb.append("<td style='max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;'>")
              .append(escape(r.getUrl() != null ? r.getUrl() : "")).append("</td>");
            sb.append("<td>").append(escape(r.getParameter() != null ? r.getParameter() : "")).append("</td>");
            sb.append("<td><span class='sev-badge ").append(sevCss).append("'>").append(r.getSeverity().label())
              .append("</span></td>");
            sb.append("<td><span class='badge ").append(statusBadge).append("'>")
              .append(r.getVerifyStatus().label()).append("</span></td>");
            sb.append("<td>").append(r.getConfidence() > 0 ? String.format("%.0f%%", r.getConfidence() * 100) : "—").append("</td></tr>\n");
        }
        sb.append("</table>\n</div>\n");

        // ==================== 漏洞详情 ====================
        sb.append("<div class='section' id='vulndetail'>\n<h2>4. 漏洞详情</h2>\n");
        int idx = 1;
        for (VulnReport r : reports)
        {
            String sevCss = getSevBarClass(r.getSeverity());
            String stripCss = getSevStripClass(r.getSeverity());
            String statusBadge = r.getVerifyStatus() == VulnReport.VerifyStatus.CONFIRMED ? "badge-confirmed"
                : r.getVerifyStatus() == VulnReport.VerifyStatus.FALSE_POSITIVE ? "badge-false-positive"
                : r.getVerifyStatus() == VulnReport.VerifyStatus.UNVERIFIED ? "badge-unverified"
                : "badge-pending";

            sb.append("<div class='vuln-card ").append(stripCss).append("' id='vuln-").append(idx).append("'>\n");
            sb.append("<div class='vuln-header'>\n");
            sb.append("<div style='display:flex;align-items:center;'>\n");
            sb.append("<span class='vuln-id'>VULN-").append(String.format("%03d", idx)).append("</span>\n");
            sb.append("<span class='vuln-title'>").append(escape(r.getVulnType())).append("</span>\n");
            sb.append("</div>\n");
            sb.append("<div class='vuln-badges'>\n");
            sb.append("<span class='sev-badge ").append(sevCss).append("'>").append(r.getSeverity().label())
              .append("</span>\n");
            sb.append("<span class='badge ").append(statusBadge).append("'>")
              .append(r.getVerifyStatus().label()).append("</span>\n");
            sb.append("</div>\n</div>\n");

            sb.append("<div class='vuln-body'>\n");

            // 属性网格
            sb.append("<div class='detail-grid'>\n");
            detailItem(sb, "URL", r.getUrl() != null ? "<code>" + escape(r.getUrl()) + "</code>" : null);
            detailItem(sb, "HTTP 方法", r.getMethod());
            detailItem(sb, "主机", r.getHost());
            detailItem(sb, "参数", r.getParameter());
            if (r.hasTimingData())
            {
                StringBuilder timing = new StringBuilder();
                if (r.getTtfbMs() > 0) timing.append("TTFB=").append(r.getTtfbMs()).append("ms");
                if (r.getTtlbMs() > 0)
                {
                    if (r.getTtfbMs() > 0) timing.append(", ");
                    timing.append("TTLB=").append(r.getTtlbMs()).append("ms");
                }
                if (timing.length() > 0) detailItem(sb, "响应时间", timing.toString());
            }
            if (r.getConfidence() > 0) detailItem(sb, "置信度", String.format("%.0f%%", r.getConfidence() * 100));
            if (r.getCategory() != null) detailItem(sb, "分类", r.getCategory());
            if (!r.getTags().isEmpty()) detailItem(sb, "标签", String.join(", ", r.getTags()));
            sb.append("</div>\n");

            // 描述段落
            if (r.getDescription() != null && !r.getDescription().isEmpty())
                descBlock(sb, "漏洞描述", r.getDescription(), "desc-danger");
            if (r.getEvidence() != null && !r.getEvidence().isEmpty())
                descBlock(sb, "验证证据", r.getEvidence(), "desc-warning");
            if (r.getSuggestion() != null && !r.getSuggestion().isEmpty())
                descBlock(sb, "修复建议", r.getSuggestion(), "desc-success");
            if (r.getTestPayload() != null && !r.getTestPayload().isEmpty())
            {
                sb.append("<div class='desc-block desc-info'><div class='desc-block-title'>测试 Payload</div><pre>")
                  .append(escape(r.getTestPayload())).append("</pre></div>\n");
            }
            if (r.getVerificationDetail() != null && !r.getVerificationDetail().isEmpty())
                descBlock(sb, "验证详情", r.getVerificationDetail(), "desc-info");

            if (r.getOriginalRequest() != null && !r.getOriginalRequest().isEmpty())
            {
                String origReq = r.getOriginalRequest();
                if (origReq.length() > 8000) origReq = origReq.substring(0, 8000) + "\n... [已截断]";
                sb.append("<div class='desc-block desc-info'><div class='desc-block-title'>原始请求 (Original Request)</div><pre>")
                  .append(escape(origReq)).append("</pre></div>\n");
            }
            // 可复现请求
            if (r.getReproduceRequest() != null && !r.getReproduceRequest().isEmpty())
            {
                sb.append("<div class='desc-block desc-info'><div class='desc-block-title'>可复现请求 (Reproduce Request)</div><pre>")
                  .append(escape(r.getReproduceRequest())).append("</pre></div>\n");
            }
            // 原始响应
            if (r.getOriginalResponse() != null && !r.getOriginalResponse().isEmpty())
            {
                String origResp = r.getOriginalResponse();
                if (origResp.length() > 8000) origResp = origResp.substring(0, 8000) + "\n... [已截断]";
                sb.append("<div class='desc-block desc-warning'><div class='desc-block-title'>原始响应 (Original Response)</div><pre>")
                  .append(escape(origResp)).append("</pre></div>\n");
            }
            // 测试响应（仅在与原始响应不同时）
            if (r.getTestResponse() != null && !r.getTestResponse().isEmpty()
                && !r.getTestResponse().equals(r.getOriginalResponse()))
            {
                String testResp = r.getTestResponse();
                if (testResp.length() > 8000) testResp = testResp.substring(0, 8000) + "\n... [已截断]";
                sb.append("<div class='desc-block desc-danger'><div class='desc-block-title'>测试响应 (Test Response - 漏洞证据)</div><pre>")
                  .append(escape(testResp)).append("</pre></div>\n");
            }

            sb.append("</div>\n</div>\n");
            idx++;
        }
        sb.append("</div>\n");

        // ==================== 附录 ====================
        sb.append("<div class='section' id='appendix'>\n<h2>5. 附录</h2>\n");
        sb.append("<p>本报告由 by ai 自动生成。所有漏洞均经 AI 辅助分析和验证。</p>\n");
        sb.append("<p>建议结合手动渗透测试进一步确认漏洞的可利用性和实际影响范围。</p>\n");
        sb.append("<table><tr><th>风险等级说明</th><th>分值范围</th><th>处置建议</th></tr>\n");
        sb.append("<tr><td><span class='sev-badge sev-critical'>严重</span></td><td>≥30</td><td>立即修复，部署缓解措施</td></tr>\n");
        sb.append("<tr><td><span class='sev-badge sev-high'>高</span></td><td>15-29</td><td>优先修复，限定修复时间</td></tr>\n");
        sb.append("<tr><td><span class='sev-badge sev-medium'>中</span></td><td>8-14</td><td>计划修复，评估影响范围</td></tr>\n");
        sb.append("<tr><td><span class='sev-badge sev-low'>低</span></td><td>3-7</td><td>建议修复，可排入迭代</td></tr>\n");
        sb.append("<tr><td><span class='sev-badge sev-info'>信息</span></td><td>&lt;3</td><td>知晓即可，无需立即操作</td></tr>\n");
        sb.append("</table>\n</div>\n");

        sb.append("</div>\n");

        sb.append("<div class='footer'>\n");
        sb.append("by ai | 自动化安全评估报告 | ").append(LocalDateTime.now().format(FMT)).append("\n");
        sb.append("</div>\n");

        sb.append("</body>\n</html>");
        return sb.toString();
    }

    // ==================== 辅助方法 ====================

    private static void detailItem(StringBuilder sb, String label, String value)
    {
        if (value == null || value.isEmpty()) return;
        sb.append("<div class='detail-item'><div class='detail-label'>").append(label)
          .append("</div><div class='detail-value'>").append(value).append("</div></div>\n");
    }

    private static void descBlock(StringBuilder sb, String title, String content, String cssClass)
    {
        sb.append("<div class='desc-block ").append(cssClass).append("'>\n");
        sb.append("<div class='desc-block-title'>").append(title).append("</div>\n");
        sb.append("<div>").append(escape(content)).append("</div>\n");
        sb.append("</div>\n");
    }

    private static int calcRiskScore(List<VulnReport> reports)
    {
        int score = 0;
        for (VulnReport r : reports)
        {
            score += r.getSeverity().level() * (r.getVerifyStatus() == VulnReport.VerifyStatus.CONFIRMED ? 2 : 1);
        }
        return score;
    }

    private static String riskLabel(int score)
    {
        if (score >= 30) return "极高风险";
        if (score >= 15) return "高风险";
        if (score >= 8) return "中风险";
        if (score >= 3) return "低风险";
        return "信息级";
    }

    private static String riskHexColor(int score)
    {
        if (score >= 30) return "#b71c1c";
        if (score >= 15) return "#d32f2f";
        if (score >= 8) return "#e65100";
        if (score >= 3) return "#1976d2";
        return "#78909c";
    }

    private static String getSevBarClass(VulnReport.Severity severity)
    {
        switch (severity)
        {
            case CRITICAL: return "sev-critical";
            case HIGH: return "sev-high";
            case MEDIUM: return "sev-medium";
            case LOW: return "sev-low";
            default: return "sev-info";
        }
    }

    private static String getSevBarColor(VulnReport.Severity severity)
    {
        switch (severity)
        {
            case CRITICAL: return "#b71c1c";
            case HIGH: return "#d32f2f";
            case MEDIUM: return "#e65100";
            case LOW: return "#1976d2";
            default: return "#78909c";
        }
    }

    private static String getSevStripClass(VulnReport.Severity severity)
    {
        switch (severity)
        {
            case CRITICAL: return "sev-strip-critical";
            case HIGH: return "sev-strip-high";
            case MEDIUM: return "sev-strip-medium";
            case LOW: return "sev-strip-low";
            default: return "sev-strip-info";
        }
    }

    private static String escape(String s)
    {
        if (s == null) return "";
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;");
    }
}
