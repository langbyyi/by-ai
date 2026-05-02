package ai.burp.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import ai.burp.provider.StreamingAIProvider;
import ai.burp.util.TextUtils;
import ai.burp.scanner.AttackSurfaceMapper;
import ai.burp.scanner.AttackSurfaceMapper.AttackSurface;
import ai.burp.scanner.AuditLogger;
import ai.burp.scanner.FullVulnDatabase;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static ai.burp.ui.ChineseUI.*;

/**
 * 右键菜单处理器 - 提供AI分析和全量扫描功能。
 */
public class ContextMenuHandler implements ContextMenuItemsProvider
{
    private final MainTabPanel mainTabPanel;
    private final StreamingAIProvider provider;
    private final MontoyaApi api;
    private final AuditLogger auditLogger;
    private String currentHost = null;
    private String currentRequestStr = null;
    private String currentResponseStr = null;
    private SwingWorker<AttackSurface, Void> activeFullScanWorker;

    public ContextMenuHandler(MainTabPanel mainTabPanel, StreamingAIProvider provider,
        MontoyaApi api, AuditLogger auditLogger)
    {
        this.mainTabPanel = mainTabPanel;
        this.provider = provider;
        this.api = api;
        this.auditLogger = auditLogger;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event)
    {
        List<Component> items = new ArrayList<>();

        // Get selected request/response
        List<HttpRequestResponse> requestResponses = event.selectedRequestResponses();
        Optional<HttpRequestResponse> editorRequestResponse =
            event.messageEditorRequestResponse().map(e -> e.requestResponse());

        if (requestResponses.isEmpty() && editorRequestResponse.isEmpty())
        {
            return items;
        }

        // Create AI submenu
        JMenu aiMenu = new JMenu(MENU_AI);

        // Get the HTTP data
        HttpRequestResponse httpData = editorRequestResponse.orElse(
            requestResponses.isEmpty() ? null : requestResponses.get(0));

        if (httpData == null) return items;

        final String requestStr = TextUtils.toStringUtf8(httpData.request());
        final String responseStr = httpData.hasResponse() ? TextUtils.toStringUtf8(httpData.response()) : "";

        // 保存当前请求的 host，供全量扫描和 session 路由使用
        boolean currentSecure = false;
        try { currentHost = httpData.httpService().host(); currentSecure = httpData.httpService().secure(); } catch (Exception ignored) {}
        final String menuHost = currentHost;
        final boolean menuSecure = currentSecure;
        currentRequestStr = requestStr;
        currentResponseStr = responseStr;

        // 分析此请求
        aiMenu.add(makeItem(menuHost, MENU_EXPLAIN_REQ,
            "请结构化分析以下HTTP请求：\n"
            + "1. 功能描述：这个请求在做什么？\n"
            + "2. 关键参数：列出所有参数及其用途推断\n"
            + "3. 安全关注点：哪些参数可能存在安全问题？\n"
            + "4. 有趣的模式：不寻常的请求头、路径、参数值\n\n"
            + "```http\n" + truncate(requestStr, 8000) + "\n```", menuSecure));

        // 分析此响应
        if (!responseStr.isEmpty())
        {
            aiMenu.add(makeItem(menuHost, MENU_EXPLAIN_RESP,
                "请结构化分析以下HTTP响应：\n"
                + "1. 响应概要：状态码、Content-Type、响应体摘要\n"
                + "2. 有趣的响应头：Server、X-Powered-By、Set-Cookie等\n"
                + "3. 安全关注点：敏感信息泄露、错误信息、调试接口\n"
                + "4. 技术栈推断：从响应推断后端使用的技术\n\n"
                + "```http\n" + truncate(responseStr, 8000) + "\n```", menuSecure));
        }

        aiMenu.addSeparator();

        // 查找漏洞
        aiMenu.add(makeItem(menuHost, MENU_FIND_VULN,
            "请按以下流程分析HTTP交换中的潜在安全漏洞：\n"
            + "1. 识别所有用户可控参数（URL参数、POST body、Cookie、HTTP头）\n"
            + "2. 对每个参数，判断响应中是否有漏洞的直接证据（非推测）\n"
            + "3. 检查认证/授权问题\n"
            + "4. 检查信息泄露（仅限凭证/token/密钥/堆栈等高价值内容）\n\n"
            + "检查范围：SQL注入、XSS、SSRF、IDOR、命令注入、越权、XXE等OWASP Top 10。\n\n"
            + "报告规则：\n"
            + "- 仅报告有响应中直接证据支持的发现，不要推测\n"
            + "- 每个漏洞必须同时满足三条件：可复现、可利用、有实际危害。缺一不报\n"
            + "- evidence字段必须引用响应中的具体内容，不接受模糊描述\n"
            + "- 优先报告根因型漏洞（注入/RCE/越权），不报告衍生现象（配置不当/头缺失）\n"
            + "- 为每个漏洞提供深度验证建议（如：用UNION SELECT回显version()验证SQL注入）\n\n"
            + "请求:\n```http\n" + truncate(requestStr, 4000) + "\n```\n\n"
            + (responseStr.isEmpty() ? "" : "响应:\n```http\n" + truncate(responseStr, 4000) + "\n```\n\n")
            + getOobContext(), menuSecure));

        // 生成攻击载荷
        aiMenu.add(makeItem(menuHost, MENU_SUGGEST_PAYLOAD,
            "请根据以下HTTP请求，生成针对性的安全测试载荷。\n"
            + "要求：\n"
            + "1. 根据每个参数的用途推断最可能成功的漏洞类型\n"
            + "2. 为每种类型生成基础payload和WAF绕过变体\n"
            + "3. SQL注入payload要求有回显验证：优先使用UNION SELECT回显version()/database()等数据，或报错注入(extractvalue/updatexml)，不要只测单引号报错\n"
            + "4. 用 ```http``` 代码块包裹完整的测试请求\n\n"
            + "```http\n" + truncate(requestStr, 6000) + "\n```\n\n"
            + getOobContext(), menuSecure));

        // 自动验证漏洞
        aiMenu.add(makeItem(menuHost, MENU_AUTO_VERIFY,
            "请对以下HTTP交换执行结构化安全验证：\n"
            + "1. 分析请求，识别所有可能存在漏洞的参数\n"
            + "2. 为每个可疑参数生成深度验证载荷（要求有实际回显，不只是触发报错）\n"
            + "3. SQL注入：使用UNION SELECT回显数据库信息(version()/database()/user())，或报错注入(extractvalue/updatexml)\n"
            + "4. XSS：确认payload在响应体中未被转义原样回显\n"
            + "5. 命令注入：使用无副作用命令(whoami/id)确认响应中有执行结果\n"
            + "6. 仅当漏洞同时满足以下三条件才生成 ```vuln``` 代码块："
            + "可复现（能稳定重放得到一致结果）、可利用（存在明确利用路径）、有实际危害（能造成数据泄露/权限提升/业务破坏）。缺一不报。\n\n"
            + "请求:\n```http\n" + truncate(requestStr, 4000) + "\n```\n\n"
            + (responseStr.isEmpty() ? "" : "响应:\n```http\n" + truncate(responseStr, 4000) + "\n```\n\n")
            + getOobContext()
            + "请返回结构化的验证结果。", menuSecure));

        // 分析认证机制
        aiMenu.add(makeItem(menuHost, MENU_ANALYZE_AUTH,
            "请结构化分析以下HTTP交换中的认证机制：\n"
            + "1. 认证类型识别（Basic/Bearer/JWT/Cookie/OAuth/API Key）\n"
            + "2. 令牌安全性分析（强度、过期、签名、加密）\n"
            + "3. 认证绕过风险（缺失的验证、弱密码、默认凭证）\n"
            + "4. 会话管理安全性（Session fixation、CSRF保护）\n"
            + "5. 改进建议\n\n"
            + "请求:\n```http\n" + truncate(requestStr, 4000) + "\n```\n\n"
            + (responseStr.isEmpty() ? "" : "响应:\n```http\n" + truncate(responseStr, 4000) + "\n```"), menuSecure));

        // 生成 CSRF PoC
        aiMenu.add(makeItem(menuHost, MENU_CSRF_POC,
            "请为以下请求生成CSRF概念验证HTML页面：\n"
            + "1. 分析请求的CSRF保护状态（检查CSRF Token、SameSite Cookie、Origin验证）\n"
            + "2. 生成自动提交的HTML表单或JavaScript\n"
            + "3. 包含说明：为什么这个请求存在CSRF风险\n\n"
            + "```http\n" + truncate(requestStr, 6000) + "\n```", menuSecure));

        aiMenu.addSeparator();

        // 解码与分析
        aiMenu.add(makeItem(menuHost, MENU_DECODE,
            "请解码并解释以下HTTP交换中的编码值：\n"
            + "1. Base64编码的值 → 解码结果和用途\n"
            + "2. URL编码的值 → 解码结果\n"
            + "3. JWT令牌 → 完整解析Header/Payload/Signature\n"
            + "4. 其他编码（HTML实体、Unicode、Hex等）\n\n"
            + "请求:\n```http\n" + truncate(requestStr, 4000) + "\n```\n\n"
            + (responseStr.isEmpty() ? "" : "响应:\n```http\n" + truncate(responseStr, 4000) + "\n```"), menuSecure));

        aiMenu.addSeparator();

        // AI 智能改写 - 让AI基于当前请求生成安全测试变体
        aiMenu.add(makeItem(menuHost, MENU_AI_REWRITE,
            "基于以下HTTP请求，生成安全测试变体。保留原始请求结构，修改参数为安全测试Payload：\n\n"
            + "原始请求:\n```http\n" + truncate(requestStr, 6000) + "\n```\n\n"
            + (responseStr.isEmpty() ? "" : "原始响应:\n```http\n" + truncate(responseStr, 4000) + "\n```\n\n")
            + getOobContext()
            + "请生成3-5个测试变体请求，每个变体用 ```http``` 代码块包裹，"
            + "并在代码块前说明测试的漏洞类型和目的。确保变体请求是安全的、仅用于测试的。", menuSecure));

        aiMenu.addSeparator();

        // 全量扫描此目标（新功能）
        JMenuItem fullScanItem = new JMenuItem(MENU_FULL_SCAN);
        fullScanItem.addActionListener(new ActionListener()
        {
            @Override
            public void actionPerformed(ActionEvent e)
            {
                runFullScan();
            }
        });
        aiMenu.add(fullScanItem);

        aiMenu.addSeparator();

        // 发送到 AI 对话
        aiMenu.add(makeItem(menuHost, MENU_SEND_TO_CHAT,
            "分析以下HTTP交换，重点关注：\n"
            + "1. 请求的功能和关键参数\n"
            + "2. 响应中的技术栈信息和异常内容\n"
            + "3. 潜在的安全风险点\n"
            + "4. 建议的测试方向\n\n"
            + "请求:\n```http\n" + truncate(requestStr, 6000) + "\n```\n\n"
            + (responseStr.isEmpty() ? "" : "响应:\n```http\n" + truncate(responseStr, 6000) + "\n```"), menuSecure));

        items.add(aiMenu);
        return items;
    }

    /**
     * 执行全量扫描 - 攻击面测绘。
     */
    private void runFullScan()
    {
        // 获取当前右键选中请求的 host
        final String scanHost = currentHost;

        // 取消上一次全量扫描 + 仪表盘上的所有分析
        if (activeFullScanWorker != null) { activeFullScanWorker.cancel(false); activeFullScanWorker = null; }
        mainTabPanel.getDashboardPanel().cancelAllAnalysis();

        // 立即切到仪表盘并选中目标主机，显示扫描中状态
        SwingUtilities.invokeLater(() -> {
            mainTabPanel.switchToDashboard();
            if (scanHost != null)
            {
                mainTabPanel.getDashboardPanel().selectHost(scanHost);
            }
            mainTabPanel.getDashboardPanel().setStatus(
                DASHBOARD_STATUS_ANALYZING + " (" + (scanHost != null ? scanHost : "全部") + ")", false);
        });

        activeFullScanWorker = new SwingWorker<AttackSurface, Void>()
        {
            @Override
            protected AttackSurface doInBackground() throws Exception
            {
                auditLogger.log("攻击面测绘", scanHost != null ? scanHost : "", "开始全量攻击面测绘...");
                AttackSurfaceMapper mapper = new AttackSurfaceMapper(api, provider, auditLogger);
                return mapper.map(scanHost);
            }

            @Override
            protected void done()
            {
                // 如果已被更新的扫描取代，直接跳过
                if (activeFullScanWorker != this) return;
                activeFullScanWorker = null;
                try
                {
                    AttackSurface surface = get();
                    // 更新仪表盘数据
                    mainTabPanel.getDashboardPanel().updateAttackSurface(surface);
                    auditLogger.log("攻击面测绘", scanHost != null ? scanHost : "", "全量扫描完成: "
                        + surface.totalEndpoints + " 个端点, " + surface.highRisk.size() + " 个高风险");
                    // 状态提示（10秒自动清除）
                    mainTabPanel.getDashboardPanel().setStatus(
                        "全量扫描完成: " + surface.totalEndpoints + " 个端点, "
                            + surface.highRisk.size() + " 个高风险", true);
                    // 触发附加分析：技术栈识别 + 关键信息提取
                    mainTabPanel.getDashboardPanel().runPostAnalysis(scanHost);
                }
                catch (Exception e)
                {
                    auditLogger.log("攻击面测绘", scanHost != null ? scanHost : "", "全量扫描失败: " + e.getMessage());
                    mainTabPanel.getDashboardPanel().setStatus("全量扫描失败: " + e.getMessage(), true);
                }
            }
        };
        activeFullScanWorker.execute();
    }

    private JMenuItem makeItem(String host, String text, String prompt, boolean secure)
    {
        JMenuItem item = new JMenuItem(text);
        item.addActionListener(new ActionListener()
        {
            @Override
            public void actionPerformed(ActionEvent e)
            {
                mainTabPanel.switchToChat();
                mainTabPanel.getChatPanel().sendPromptForHostWithContext(
                    host, prompt, currentRequestStr, currentResponseStr, host, secure);
            }
        });
        return item;
    }

    private String truncate(String text, int maxLen)
    {
        if (text == null) return "";
        if (text.length() <= maxLen) return text;
        return text.substring(0, maxLen) + "\n... [truncated]";
    }

    /**
     * 构建 OOB 带外测试域名的上下文片段。
     * 当存在 OOB 域名时，附加到 SSRF 相关的 AI prompt 中。
     */
    private String getOobContext()
    {
        String oob = FullVulnDatabase.getOobDomain();
        if (oob == null || oob.isEmpty())
        {
            return "";
        }
        return "\n重要：当前可用的带外测试(OOB)域名为 " + oob
            + "。在生成SSRF、XXE等需要带外验证的payload时，必须使用此域名构造payload，"
            + "例如 http://" + oob + "/ssrf-test 。\n\n";
    }
}
