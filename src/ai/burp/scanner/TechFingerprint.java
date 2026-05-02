package ai.burp.scanner;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ai.burp.util.TextUtils;
import burp.api.montoya.http.message.HttpRequestResponse;

import ai.burp.model.ChatMessage;
import ai.burp.provider.StreamingAIProvider;
import ai.burp.util.AiResponseParser;

/**
 * 技术指纹识别 - 自动识别目标技术栈。
 * 通过AI分析HTTP请求/响应中的特征，识别：
 * 开发语言、Web框架、中间件、CMS、服务器OS、第三方组件版本。
 */
public class TechFingerprint
{
    /** 已识别的技术栈缓存（按host索引） */
    private static final ConcurrentHashMap<String, TechStack> cache = new ConcurrentHashMap<>();

    private final StreamingAIProvider provider;
    private final AuditLogger logger;

    public TechFingerprint(StreamingAIProvider provider, AuditLogger logger)
    {
        this.provider = provider;
        this.logger = logger;
    }

    /**
     * 识别请求/响应中的技术栈。
     * 使用双重策略：先规则匹配（快速），再AI分析（深度）。
     */
    public TechStack identify(HttpRequestResponse httpData)
    {
        String host = httpData.httpService().host();

        // 获取或创建该 host 的 TechStack（computeIfAbsent 保证同一 host 只有一个实例）
        TechStack stack = cache.computeIfAbsent(host, TechStack::new);

        synchronized (stack)
        {
            // 已完整识别则直接返回
            if (stack.isComplete()) return stack;

            String request = TextUtils.toStringUtf8(httpData.request());
            String response = httpData.hasResponse() ? TextUtils.toStringUtf8(httpData.response()) : "";

            // 阶段1: 规则快速匹配（在已有结果上增量补充）
            ruleBasedDetect(request, response, stack);

            // 阶段2: AI深度分析（如果已配置且规则未能完整识别）
            if (provider.isConfigured() && !stack.isComplete())
            {
                try
                {
                    String prompt = FullVulnDatabase.buildFingerprintPrompt(request, response);
                    String aiResult = provider.chat(Collections.singletonList(ChatMessage.user(prompt)));
                    aiBasedDetect(aiResult, stack);
                }
                catch (Exception e)
                {
                    // AI分析失败不影响规则匹配结果
                }
            }

            logger.log("技术识别", host, stack.summary());
        }
        return stack;
    }

    // ===================== 精确匹配工具方法 =====================

    /**
     * 精确token匹配，避免子串误报（如 yii 匹配到 lyii）。
     * 使用前后非字母数字断言，兼容中文指纹。
     */
    private static boolean containsToken(String text, String token)
    {
        if (text == null || token == null || token.isEmpty()) return false;
        Pattern p = Pattern.compile("(?i)(?<![a-z0-9])" + Pattern.quote(token) + "(?![a-z0-9])");
        return p.matcher(text).find();
    }

    /** 匹配任意一个token */
    private static boolean containsAnyToken(String text, String... tokens)
    {
        for (String t : tokens) { if (containsToken(text, t)) return true; }
        return false;
    }

    /** 路径片段匹配（确保前后不是字母数字或下划线） */
    private static boolean containsPath(String text, String path)
    {
        if (text == null || path == null || path.isEmpty()) return false;
        Pattern p = Pattern.compile("(?i)(?<![a-z0-9_.-])" + Pattern.quote(path) + "(?![a-z0-9_.-])");
        return p.matcher(text).find();
    }

    /** HTML meta 标签精确匹配（支持 name/content 两种属性顺序） */
    private static boolean containsMeta(String text, String name, String content)
    {
        if (text == null) return false;
        String n = Pattern.quote(name);
        String c = Pattern.quote(content);
        String p1 = "name=[\"']?" + n + "[\"']?\\s+[^>]*content=[\"']?" + c;
        String p2 = "content=[\"']?" + c + "[\"']?\\s+[^>]*name=[\"']?" + n;
        Pattern p = Pattern.compile("(?i)<meta\\s+[^>]*(?:" + p1 + "|" + p2 + ")");
        return p.matcher(text).find();
    }

    /** 正则提取第一个匹配组 */
    private static String extract(String text, String regex)
    {
        if (text == null) return "";
        Matcher m = Pattern.compile(regex, Pattern.CASE_INSENSITIVE).matcher(text);
        return m.find() ? m.group(1).trim() : "";
    }

    /** 从Server/X-Powered-By等头中提取版本号 */
    private static String extractVersion(String headerValue)
    {
        if (headerValue == null) return "";
        String v = extract(headerValue, "[ /:]\\s*([0-9]+\\.[0-9]+(?:\\.[0-9]+)?(?:[-._]?[a-z0-9]+)?)");
        if (!v.isEmpty() && v.length() < 20) return v;
        return "";
    }

    /** 解析请求Cookie名或响应Set-Cookie名 */
    private static Set<String> extractCookieNames(String text, boolean fromResponse)
    {
        Set<String> names = new HashSet<>();
        if (text == null) return names;
        String key = fromResponse ? "set-cookie:" : "cookie:";
        for (String line : text.split("\r?\n"))
        {
            if (line.toLowerCase().trim().startsWith(key))
            {
                String part = line.substring(line.indexOf(':') + 1);
                for (String cookie : part.split(";\\s*"))
                {
                    int eq = cookie.indexOf('=');
                    String name = (eq > 0) ? cookie.substring(0, eq).trim() : cookie.trim();
                    if (!name.isEmpty()) names.add(name.toLowerCase());
                }
            }
        }
        return names;
    }

    /** 同时检查头值和体内容 */
    private static boolean inHeaderOrBody(String headerVal, String body, String token)
    {
        return (headerVal != null && containsToken(headerVal, token)) || containsToken(body, token);
    }

    // ===================== 规则快速匹配 =====================

    /**
     * 规则快速匹配 - 基于HTTP头、响应体、Cookie、HTML特征综合识别。
     * 采用词边界匹配减少误报，支持版本号提取，覆盖主流+国产技术栈。
     */
    private void ruleBasedDetect(String request, String response, TechStack stack)
    {
        String lowerResp = response.toLowerCase();
        String lowerReq  = request.toLowerCase();

        // ---- 解析响应头和响应体 ----
        Map<String, String> headers = new LinkedHashMap<>();
        String body = "";
        int headerEnd = response.indexOf("\r\n\r\n");
        if (headerEnd < 0) headerEnd = response.indexOf("\n\n");
        if (headerEnd >= 0)
        {
            String headerPart = response.substring(0, headerEnd);
            body = response.substring(headerEnd + 4);
            for (String line : headerPart.split("\r?\n"))
            {
                if (line.toLowerCase().startsWith("http/")) continue;
                int colon = line.indexOf(':');
                if (colon > 0)
                {
                    headers.put(line.substring(0, colon).trim().toLowerCase(),
                                line.substring(colon + 1).trim());
                }
            }
        }
        else
        {
            body = response;
        }
        String lowerBody = body.toLowerCase();
        String server = headers.get("server");
        String poweredBy = headers.get("x-powered-by");

        // ---- Cookie名提取 ----
        Set<String> reqCookies = extractCookieNames(request, false);
        Set<String> respCookies = extractCookieNames(response, true);
        Set<String> allCookies = new HashSet<>(reqCookies);
        allCookies.addAll(respCookies);

        // ========== Web服务器/中间件 + 版本提取 ==========
        if (server != null)
        {
            String svr = server.toLowerCase();
            stack.setWebServer(server);
            String ver = extractVersion(server);
            if (svr.contains("nginx"))       stack.addComponent("Nginx" + fmtVer(ver));
            if (svr.contains("apache"))      stack.addComponent("Apache" + fmtVer(ver));
            if (svr.contains("iis"))         stack.addComponent("IIS" + fmtVer(ver));
            if (svr.contains("openresty"))   stack.addComponent("OpenResty" + fmtVer(ver));
            if (svr.contains("caddy"))       stack.addComponent("Caddy" + fmtVer(ver));
            if (svr.contains("lighttpd"))    stack.addComponent("lighttpd" + fmtVer(ver));
            if (svr.contains("tomcat"))      stack.addComponent("Apache Tomcat" + fmtVer(ver));
            if (svr.contains("jetty"))       stack.addComponent("Jetty" + fmtVer(ver));
            if (svr.contains("undertow"))    stack.addComponent("Undertow" + fmtVer(ver));
            if (svr.contains("cowboy"))      stack.addComponent("Cowboy" + fmtVer(ver));
            if (svr.contains("gunicorn"))    stack.addComponent("Gunicorn" + fmtVer(ver));
            if (svr.contains("uwsgi"))       stack.addComponent("uWSGI" + fmtVer(ver));
            if (svr.contains("waitress"))    stack.addComponent("Waitress" + fmtVer(ver));
            if (svr.contains("tengine"))     stack.addComponent("Tengine" + fmtVer(ver));
            if (svr.contains("weblogic"))    stack.addComponent("Oracle WebLogic" + fmtVer(ver));
            if (svr.contains("websphere"))   stack.addComponent("IBM WebSphere" + fmtVer(ver));
            if (svr.contains("jboss"))       stack.addComponent("JBoss" + fmtVer(ver));
            if (svr.contains("wildfly"))     stack.addComponent("WildFly" + fmtVer(ver));
            if (svr.contains("resin"))       stack.addComponent("Resin" + fmtVer(ver));
            if (svr.contains("glassfish"))   stack.addComponent("GlassFish" + fmtVer(ver));
            if (svr.contains("haproxy"))     stack.addComponent("HAProxy" + fmtVer(ver));
            if (svr.contains("traefik"))     stack.addComponent("Traefik" + fmtVer(ver));
            if (svr.contains("envoy"))       stack.addComponent("Envoy" + fmtVer(ver));
            if (svr.contains("istio"))       stack.addComponent("Istio" + fmtVer(ver));
            if (svr.contains("kong"))        stack.addComponent("Kong" + fmtVer(ver));
            if (svr.contains("squid"))       stack.addComponent("Squid" + fmtVer(ver));
            if (svr.contains("varnish"))     stack.addComponent("Varnish" + fmtVer(ver));
            if (svr.contains("ats") || svr.contains("traffic server")) stack.addComponent("Apache Traffic Server");
        }

        // ---- X-Powered-By + 版本 ----
        if (poweredBy != null)
        {
            String pb = poweredBy.toLowerCase();
            String pver = extractVersion(poweredBy);
            if (pb.contains("php"))        { stack.setLanguage("PHP"); stack.addComponent("PHP" + fmtVer(pver)); }
            if (pb.contains("asp.net"))    { stack.setLanguage("C#"); stack.addFramework("ASP.NET" + fmtVer(pver)); }
            if (pb.contains("servlet"))    { stack.setLanguage("Java"); }
            if (pb.contains("express"))    { stack.setLanguage("JavaScript"); stack.addFramework("Express" + fmtVer(pver)); }
            if (pb.contains("wsgi"))       { stack.setLanguage("Python"); }
            if (pb.contains("p powered by")) { stack.setLanguage("PHP"); stack.addComponent("PHP" + fmtVer(pver)); }
        }

        // ========== WAF/CDN（Header特征） ==========
        if (headers.containsKey("cf-ray") || headers.containsKey("cf-cache-status"))
            stack.addComponent("CloudFlare WAF/CDN");
        if (headers.containsKey("x-alicdn-da-status") || headers.containsKey("x-swift-cache"))
            stack.addComponent("阿里云CDN");
        if (headers.containsKey("x-tencent-cdn") || headers.containsKey("x-qcloud-cdn"))
            stack.addComponent("腾讯云CDN");
        if (headers.containsKey("x-baidu-cdn")) stack.addComponent("百度云CDN");
        if (headers.containsKey("x-upyun-cdn") || headers.containsKey("x-upyun"))
            stack.addComponent("又拍云CDN");
        if (headers.containsKey("x-qiniu")) stack.addComponent("七牛云CDN");
        if (headers.containsKey("x-aws-waf") || headers.containsKey("x-amz-cf-id"))
            stack.addComponent(headers.containsKey("x-amz-cf-id") ? "AWS CloudFront" : "AWS WAF");
        if (headers.containsKey("x-azure-ref")) stack.addComponent("Azure CDN");
        if (headers.containsKey("x-sucuri-id")) stack.addComponent("Sucuri WAF");
        if (headers.containsKey("x-waf-eventid") || headers.containsKey("x-waf-rule"))
            stack.addComponent("WAF");
        if (headers.containsKey("x-yunjiasu")) stack.addComponent("百度云加速(安全)");
        if (headers.containsKey("x-chuangyu")) stack.addComponent("知道创宇WAF");
        if (headers.containsKey("x-anheng")) stack.addComponent("安恒WAF");
        if (headers.containsKey("x-chaitin") || headers.containsKey("x-safe3waf"))
            stack.addComponent("长亭雷池WAF");
        if (headers.containsKey("x-xss-protection") && headers.containsKey("x-content-type-options"))
        {
            // 有安全头但不一定就是WAF，仅作低置信度提示
            // stack.addComponent("可能部署安全响应头");
        }
        if (lowerResp.contains("safedog") || lowerResp.contains("safedog_site"))
            stack.addComponent("安全狗WAF");
        if (lowerResp.contains("yunjiasu"))
            stack.addComponent("百度云加速");
        if (lowerResp.contains("mod_security") || lowerResp.contains("modsecurity"))
            stack.addComponent("ModSecurity");
        if (lowerResp.contains("blocked by") && lowerResp.contains("waf"))
            stack.addComponent("WAF");
        if (lowerResp.contains("imperva") || headers.containsKey("x-iinfo"))
            stack.addComponent("Imperva WAF");
        if (headers.containsKey("akamai-grn") || headers.containsKey("x-akamai-transformed"))
            stack.addComponent("Akamai CDN/WAF");
        if (headers.containsKey("x-cache") || headers.containsKey("x-cache-hits") || headers.containsKey("x-cached-by"))
            stack.addComponent("CDN/缓存层");

        // ========== 反向代理/负载均衡 ==========
        if (headers.containsKey("via"))
            stack.addComponent("反向代理: " + headers.get("via"));
        if (headers.containsKey("x-varnish")) stack.addComponent("Varnish");
        if (headers.containsKey("x-haproxy-server-state")) stack.addComponent("HAProxy");
        if (headers.containsKey("x-f5-") || headers.containsKey("x-bigip")) stack.addComponent("F5 BIG-IP");
        if (headers.containsKey("x-forwarded-for") || headers.containsKey("x-real-ip"))
            stack.addComponent("反向代理");
        if (headers.containsKey("x-lb")) stack.addComponent("负载均衡");
        if (headers.containsKey("x-nginx-upstream") || headers.containsKey("x-nginx-cache"))
            stack.addComponent("Nginx反向代理/负载均衡");
        if (headers.containsKey("x-apigw")) stack.addComponent("API网关");
        if (headers.containsKey("x-kong-upstream-latency")) stack.addComponent("Kong API网关");
        if (headers.containsKey("x-envoy-upstream-service-time")) stack.addComponent("Envoy代理");
        if (headers.containsKey("x-istio-attributes")) stack.addComponent("Istio Service Mesh");
        if (headers.containsKey("x-spring-cloud-gateway")) stack.addComponent("Spring Cloud Gateway");
        if (headers.containsKey("x-zuul")) stack.addComponent("Netflix Zuul");
        if (headers.containsKey("x-apisix")) stack.addComponent("Apache APISIX");

        // ========== 数据库/缓存（错误信息 + Header） ==========
        boolean hasDbError = lowerResp.contains("error") || lowerResp.contains("exception") || lowerResp.contains("sql");
        if (hasDbError || lowerResp.contains("mysql"))
        {
            String mv = extract(response, "(?i)mysql[^0-9]{0,10}([0-9]+\\.[0-9]+(?:\\.[0-9]+)?)");
            stack.addComponent("MySQL" + fmtVer(mv));
        }
        if (hasDbError && lowerResp.contains("mariadb"))
        {
            String mv = extract(response, "(?i)mariadb[^0-9]{0,10}([0-9]+\\.[0-9]+(?:\\.[0-9]+)?)");
            stack.addComponent("MariaDB" + fmtVer(mv));
        }
        if (hasDbError && lowerResp.contains("postgresql"))
        {
            String mv = extract(response, "(?i)postgresql[^0-9]{0,10}([0-9]+\\.[0-9]+(?:\\.[0-9]+)?)");
            stack.addComponent("PostgreSQL" + fmtVer(mv));
        }
        if (lowerResp.contains("ora-") && lowerResp.contains("oracle"))
            stack.addComponent("Oracle");
        if (lowerResp.contains("sql server") || lowerResp.contains("mssql") || lowerResp.contains("microsoft sql"))
            stack.addComponent("SQL Server");
        if (containsToken(lowerResp, "sqlite"))
        {
            String mv = extract(response, "(?i)sqlite[^0-9]{0,10}([0-9]+\\.[0-9]+(?:\\.[0-9]+)?)");
            stack.addComponent("SQLite" + fmtVer(mv));
        }
        if (lowerResp.contains("mongodb") || lowerResp.contains("mongoservererror"))
            stack.addComponent("MongoDB");
        if (lowerResp.contains("redis") && (hasDbError || lowerResp.contains("redis")))
        {
            String mv = extract(response, "(?i)redis[^0-9]{0,10}([0-9]+\\.[0-9]+(?:\\.[0-9]+)?)");
            stack.addComponent("Redis" + fmtVer(mv));
        }
        if (lowerResp.contains("memcached")) stack.addComponent("Memcached");
        if (lowerResp.contains("cassandra")) stack.addComponent("Cassandra");
        if (lowerResp.contains("neo4j"))     stack.addComponent("Neo4j");
        if (lowerResp.contains("clickhouse")) stack.addComponent("ClickHouse");
        if (lowerResp.contains("influxdb"))  stack.addComponent("InfluxDB");
        if (lowerResp.contains("elasticsearch"))
        {
            String mv = extract(response, "(?i)elasticsearch[^0-9]{0,10}([0-9]+\\.[0-9]+(?:\\.[0-9]+)?)");
            stack.addComponent("ElasticSearch" + fmtVer(mv));
        }

        // ========== 开发语言/框架（Cookie + 响应体 + 路径） ==========
        // --- PHP 家族 ---
        if (allCookies.contains("phpsessid")) { stack.setLanguage("PHP"); stack.addFramework("PHP"); }
        if (allCookies.contains("laravel_session")) { stack.setLanguage("PHP"); stack.addFramework("Laravel"); }
        if (allCookies.contains("symfony")) { stack.setLanguage("PHP"); stack.addFramework("Symfony"); }
        if (allCookies.contains("cakephp") || containsPath(lowerBody, "/cakephp/")) { stack.setLanguage("PHP"); stack.addFramework("CakePHP"); }
        if (containsToken(lowerBody, "thinkphp") || containsPath(lowerBody, "/thinkphp/") || containsToken(lowerBody, "thinkphp_exception"))
            { stack.setLanguage("PHP"); stack.addFramework("ThinkPHP"); }
        if (containsPath(lowerBody, "/wp-content/") || containsPath(lowerBody, "/wp-includes/") || containsToken(lowerBody, "wordpress"))
            { stack.setCms("WordPress"); stack.setLanguage("PHP"); }
        if (containsPath(lowerBody, "/drupal/") || containsToken(lowerBody, "drupal") || containsMeta(body, "generator", "drupal"))
            { stack.setCms("Drupal"); stack.setLanguage("PHP"); }
        if (containsToken(lowerBody, "joomla") || containsPath(lowerBody, "/joomla/") || containsMeta(body, "generator", "joomla"))
            { stack.setCms("Joomla"); stack.setLanguage("PHP"); }
        if (containsToken(lowerBody, "discuz") || containsPath(lowerBody, "/discuz/"))
            { stack.setCms("Discuz!"); stack.setLanguage("PHP"); }
        if (containsToken(lowerBody, "dedecms") || containsPath(lowerBody, "/dede/") || containsToken(lowerBody, "powered by dede"))
            { stack.setCms("DedeCMS"); stack.setLanguage("PHP"); }
        if (containsToken(lowerBody, "empirecms") || containsPath(lowerBody, "/e/") || containsToken(lowerBody, "powered by empirecms"))
            { stack.setCms("EmpireCMS"); stack.setLanguage("PHP"); }
        if (containsToken(lowerBody, "phpmyadmin") || containsPath(lowerBody, "/phpmyadmin/"))
            { stack.setCms("phpMyAdmin"); stack.setLanguage("PHP"); }
        if (containsToken(lowerBody, "typecho") || containsPath(lowerBody, "/typecho/"))
            { stack.setCms("Typecho"); stack.setLanguage("PHP"); }
        if (containsToken(lowerBody, "z-blog") || containsPath(lowerBody, "/zb_system/"))
            { stack.setCms("Z-Blog"); stack.setLanguage("PHP"); }
        if (containsToken(lowerBody, "phpcms") || containsPath(lowerBody, "/phpcms/"))
            { stack.setCms("PHPCMS"); stack.setLanguage("PHP"); }
        if (containsToken(lowerBody, "ecshop") || containsPath(lowerBody, "/ecshop/"))
            { stack.setCms("ECShop"); stack.setLanguage("PHP"); }
        if (containsToken(lowerBody, "shopex") || containsPath(lowerBody, "/shopex/"))
            { stack.setCms("ShopEX"); stack.setLanguage("PHP"); }
        if (containsToken(lowerBody, "phpwind") || containsPath(lowerBody, "/phpwind/"))
            { stack.setCms("phpwind"); stack.setLanguage("PHP"); }
        if (containsToken(lowerBody, "codeigniter")) { stack.setLanguage("PHP"); stack.addFramework("CodeIgniter"); }
        if (containsToken(lowerBody, "yii")) { stack.setLanguage("PHP"); stack.addFramework("Yii"); }
        if (containsToken(lowerBody, "zend")) { stack.setLanguage("PHP"); stack.addFramework("Zend Framework"); }
        if (containsToken(lowerBody, "whoops") || containsToken(lowerBody, "filp/whoops"))
            { stack.setLanguage("PHP"); stack.addFramework("Laravel/Symfony"); }

        // --- Java 家族 ---
        if (allCookies.contains("jsessionid")) { stack.setLanguage("Java"); stack.addFramework("Java Servlet"); }
        if (allCookies.contains("rememberme")) { stack.setLanguage("Java"); stack.addComponent("Apache Shiro"); }
        if (containsToken(lowerBody, "spring") || containsToken(lowerBody, "spring_security"))
            { stack.setLanguage("Java"); stack.addFramework("Spring"); }
        if (containsPath(lowerBody, "/spring-boot/") || containsToken(lowerBody, "whitelabel error page"))
            { stack.setLanguage("Java"); stack.addFramework("Spring Boot"); }
        if (containsPath(lowerBody, "/actuator/"))
            { stack.setLanguage("Java"); stack.addComponent("Spring Boot Actuator"); }
        if (containsToken(lowerBody, "struts2") || containsToken(lowerBody, "struts"))
            { stack.setLanguage("Java"); stack.addFramework("Apache Struts2"); }
        if (containsToken(lowerBody, "shiro")) { stack.setLanguage("Java"); stack.addComponent("Apache Shiro"); }
        if (containsToken(lowerBody, "fastjson")) { stack.setLanguage("Java"); stack.addComponent("Fastjson"); }
        if (containsToken(lowerBody, "weblogic")) { stack.setLanguage("Java"); stack.addComponent("Oracle WebLogic"); }
        if (containsToken(lowerBody, "websphere")) { stack.setLanguage("Java"); stack.addComponent("IBM WebSphere"); }
        if (containsToken(lowerBody, "jboss")) { stack.setLanguage("Java"); stack.addComponent("JBoss"); }
        if (containsPath(lowerBody, "/solr/")) { stack.setLanguage("Java"); stack.addComponent("Apache Solr"); }
        if (containsPath(lowerBody, "/jenkins")) { stack.setLanguage("Java"); stack.addComponent("Jenkins"); }
        if (containsToken(lowerBody, "activiti")) { stack.setLanguage("Java"); stack.addComponent("Activiti"); }
        if (containsToken(lowerBody, "camunda")) { stack.setLanguage("Java"); stack.addComponent("Camunda"); }
        if (containsToken(lowerBody, "jeecgboot") || containsPath(lowerBody, "/jeecg/"))
            { stack.setLanguage("Java"); stack.addFramework("JeecgBoot"); }
        if (containsToken(lowerBody, "ruoyi") || containsPath(lowerBody, "/ruoyi/"))
            { stack.setLanguage("Java"); stack.addFramework("RuoYi"); }
        if (containsToken(lowerBody, "solon") || containsPath(lowerBody, "/solon/"))
            { stack.setLanguage("Java"); stack.addFramework("Solon"); }

        // --- C# / ASP.NET ---
        if (allCookies.contains("asp.net_sessionid")) { stack.setLanguage("C#"); stack.addFramework("ASP.NET"); }
        if (lowerResp.contains("__viewstate")) { stack.setLanguage("C#"); stack.addFramework("ASP.NET WebForms"); }
        if (lowerResp.contains("aspsessionid")) stack.setLanguage("VBScript/ASP");
        if (containsToken(lowerBody, "asp.net") && lowerResp.contains("yellow screen"))
            { stack.setLanguage("C#"); stack.addFramework("ASP.NET"); }

        // --- Python 家族 ---
        if (lowerReq.contains("csrfmiddlewaretoken")) { stack.setLanguage("Python"); stack.addFramework("Django"); }
        if (allCookies.contains("session") && lowerBody.contains(".ejw"))
            { stack.setLanguage("Python"); stack.addFramework("Flask"); }
        if (allCookies.contains("flask_session")) { stack.setLanguage("Python"); stack.addFramework("Flask"); }
        if (containsToken(lowerBody, "django") && (lowerResp.contains("debug") || lowerResp.contains("traceback")))
            { stack.setLanguage("Python"); stack.addFramework("Django"); }
        if (containsToken(lowerBody, "flask") && lowerResp.contains("traceback"))
            { stack.setLanguage("Python"); stack.addFramework("Flask"); }
        if (containsToken(lowerBody, "fastapi")) { stack.setLanguage("Python"); stack.addFramework("FastAPI"); }
        if (containsToken(lowerBody, "tornado")) { stack.setLanguage("Python"); stack.addFramework("Tornado"); }
        if (containsToken(lowerBody, "aiohttp")) { stack.setLanguage("Python"); stack.addFramework("aiohttp"); }
        if (containsToken(lowerBody, "bottle")) { stack.setLanguage("Python"); stack.addFramework("Bottle"); }

        // --- JavaScript / Node.js 家族 ---
        if (allCookies.contains("connect.sid")) { stack.setLanguage("JavaScript"); stack.addFramework("Express"); }
        if (containsToken(lowerBody, "express") && lowerResp.contains("error"))
            { stack.setLanguage("JavaScript"); stack.addFramework("Express"); }
        if (containsToken(lowerBody, "nestjs")) { stack.setLanguage("JavaScript/TypeScript"); stack.addFramework("NestJS"); }
        if (containsToken(lowerBody, "koa")) { stack.setLanguage("JavaScript"); stack.addFramework("Koa"); }
        if (containsToken(lowerBody, "egg.js") || containsToken(lowerBody, "eggjs"))
            { stack.setLanguage("JavaScript"); stack.addFramework("Egg.js"); }
        if (containsToken(lowerBody, "adonisjs") || containsPath(lowerBody, "/adonis/"))
            { stack.setLanguage("JavaScript"); stack.addFramework("AdonisJS"); }
        if (containsToken(lowerBody, "sails.js") || containsToken(lowerBody, "sailsjs"))
            { stack.setLanguage("JavaScript"); stack.addFramework("Sails.js"); }
        if (containsToken(lowerBody, "hapi")) { stack.setLanguage("JavaScript"); stack.addFramework("Hapi"); }

        // --- Go 家族 ---
        if (allCookies.contains("gin-session") || allCookies.contains("_gorilla_csrf"))
            stack.setLanguage("Go");
        if (containsToken(lowerBody, "gin-gonic") || containsToken(lowerBody, "go-gin"))
            { stack.setLanguage("Go"); stack.addFramework("Gin"); }
        if (containsToken(lowerBody, "beego")) { stack.setLanguage("Go"); stack.addFramework("Beego"); }
        if (containsToken(lowerBody, "iris-go") || containsToken(lowerBody, "iris framework"))
            { stack.setLanguage("Go"); stack.addFramework("Iris"); }
        if (containsToken(lowerBody, "echo framework") || containsToken(lowerBody, "labstack/echo"))
            { stack.setLanguage("Go"); stack.addFramework("Echo"); }
        if (containsToken(lowerBody, "revel")) { stack.setLanguage("Go"); stack.addFramework("Revel"); }

        // --- Ruby 家族 ---
        if (allCookies.contains("rack.session")) { stack.setLanguage("Ruby"); stack.addFramework("Rack"); }
        if (containsToken(lowerBody, "rails")) { stack.setLanguage("Ruby"); stack.addFramework("Ruby on Rails"); }
        if (containsToken(lowerBody, "sinatra")) { stack.setLanguage("Ruby"); stack.addFramework("Sinatra"); }
        if (containsToken(lowerBody, "padrino")) { stack.setLanguage("Ruby"); stack.addFramework("Padrino"); }

        // --- Rust 家族 ---
        if (containsToken(lowerBody, "actix-web") || containsToken(lowerBody, "actix"))
            { stack.setLanguage("Rust"); stack.addFramework("Actix-web"); }
        if (containsToken(lowerBody, "rocket.rs") || containsToken(lowerBody, "rocket framework"))
            { stack.setLanguage("Rust"); stack.addFramework("Rocket"); }
        if (containsToken(lowerBody, "axum")) { stack.setLanguage("Rust"); stack.addFramework("Axum"); }

        // ========== CMS（更多） ==========
        if (containsToken(lowerBody, "magento")) { stack.setCms("Magento"); stack.setLanguage("PHP"); }
        if (containsToken(lowerBody, "prestashop")) { stack.setCms("PrestaShop"); stack.setLanguage("PHP"); }
        if (containsToken(lowerBody, "shopify")) stack.setCms("Shopify");
        if (containsToken(lowerBody, "ghost")) { stack.setCms("Ghost"); stack.setLanguage("JavaScript"); }
        if (containsToken(lowerBody, "metabase")) { stack.setCms("Metabase"); stack.setLanguage("Java/JavaScript"); }
        if (containsToken(lowerBody, "grafana")) { stack.setCms("Grafana"); stack.setLanguage("Go/TypeScript"); }
        if (containsToken(lowerBody, "confluence")) { stack.setCms("Atlassian Confluence"); stack.setLanguage("Java"); }
        if (containsToken(lowerBody, "jira")) { stack.setCms("Atlassian Jira"); stack.setLanguage("Java"); }
        if (containsToken(lowerBody, "bitbucket")) { stack.setCms("Atlassian Bitbucket"); stack.setLanguage("Java"); }
        if (containsToken(lowerBody, "gitlab")) { stack.setCms("GitLab"); stack.setLanguage("Ruby"); }
        if (containsToken(lowerBody, "github enterprise")) { stack.setCms("GitHub Enterprise"); }
        if (containsToken(lowerBody, "gitea")) { stack.setCms("Gitea"); stack.setLanguage("Go"); }
        if (containsToken(lowerBody, "gogs")) { stack.setCms("Gogs"); stack.setLanguage("Go"); }
        if (containsToken(lowerBody, "mediawiki")) { stack.setCms("MediaWiki"); stack.setLanguage("PHP"); }
        if (containsToken(lowerBody, "xwiki")) { stack.setCms("XWiki"); stack.setLanguage("Java"); }
        if (containsToken(lowerBody, "nopcommerce")) { stack.setCms("NopCommerce"); stack.setLanguage("C#"); }
        if (containsToken(lowerBody, "umbraco")) { stack.setCms("Umbraco"); stack.setLanguage("C#"); }
        if (containsToken(lowerBody, "sitecore")) { stack.setCms("Sitecore"); stack.setLanguage("C#"); }
        if (containsToken(lowerBody, "sharepoint")) { stack.setCms("Microsoft SharePoint"); stack.setLanguage("C#"); }
        if (containsToken(lowerBody, "exchange")) { stack.setCms("Microsoft Exchange"); }
        if (containsToken(lowerBody, "金蝶") || containsToken(lowerBody, "kingdee"))
            { stack.setCms("金蝶EAS/K3Cloud"); stack.setLanguage("Java/C#"); }
        if (containsToken(lowerBody, "用友") || containsToken(lowerBody, "yonyou") || containsToken(lowerBody, "ufida"))
            { stack.setCms("用友NC/U8"); stack.setLanguage("Java"); }
        if (containsToken(lowerBody, "泛微") || containsToken(lowerBody, "weaver") || containsPath(lowerBody, "/weaver/"))
            { stack.setCms("泛微e-cology"); stack.setLanguage("Java"); }
        if (containsToken(lowerBody, "通达oa") || containsToken(lowerBody, "tongda") || containsPath(lowerBody, "/general/"))
            { stack.setCms("通达OA"); stack.setLanguage("PHP"); }
        if (containsToken(lowerBody, "帆软") || containsToken(lowerBody, "finereport") || containsPath(lowerBody, "/webroot/"))
            { stack.setCms("帆软报表"); stack.setLanguage("Java"); }
        if (containsToken(lowerBody, "东方通") || containsToken(lowerBody, "tongweb"))
            { stack.setCms("东方通TongWeb"); stack.setLanguage("Java"); }
        if (containsToken(lowerBody, "宝兰德") || containsToken(lowerBody, "bES"))
            { stack.setCms("宝兰德BES"); stack.setLanguage("Java"); }
        if (containsToken(lowerBody, "中创") || containsToken(lowerBody, "inforbus"))
            { stack.setCms("中创InforBus"); stack.setLanguage("Java"); }
        if (containsToken(lowerBody, "普元") || containsToken(lowerBody, "primeton"))
            { stack.setCms("普元EOS"); stack.setLanguage("Java"); }
        if (containsToken(lowerBody, "蓝凌") || containsToken(lowerBody, "landray") || containsPath(lowerBody, "/ekp/"))
            { stack.setCms("蓝凌EKP"); stack.setLanguage("Java"); }

        // ========== 前端框架（HTML特征 + JS路径） ==========
        if (containsPath(lowerBody, "react") || lowerBody.contains("__reactrootnode") || lowerBody.contains("data-reactroot") || lowerBody.contains("data-reactid"))
            { stack.setFrontend("React"); stack.setLanguage("JavaScript"); }
        if (containsPath(lowerBody, "vue") || lowerBody.contains("v-cloak") || lowerBody.contains("__vue__") || lowerBody.contains("vue-router") || lowerBody.contains("data-v-"))
            { stack.setFrontend("Vue.js"); stack.setLanguage("JavaScript"); }
        if (containsPath(lowerBody, "angular") || lowerBody.contains("ng-version") || lowerBody.contains("ng-app") || lowerBody.contains("ng-controller"))
            { stack.setFrontend("Angular"); stack.setLanguage("JavaScript/TypeScript"); }
        if (containsToken(lowerBody, "ember") || lowerBody.contains("data-ember"))
            { stack.setFrontend("Ember.js"); stack.setLanguage("JavaScript"); }
        if (containsToken(lowerBody, "svelte") || lowerBody.contains("svelte-"))
            { stack.setFrontend("Svelte"); stack.setLanguage("JavaScript"); }
        if (containsToken(lowerBody, "preact")) { stack.setFrontend("Preact"); stack.setLanguage("JavaScript"); }
        if (containsToken(lowerBody, "alpine.js") || containsToken(lowerBody, "alpinejs"))
            { stack.setFrontend("Alpine.js"); stack.setLanguage("JavaScript"); }
        if (containsToken(lowerBody, "htmx")) { stack.setFrontend("HTMX"); stack.setLanguage("JavaScript"); }
        if (containsToken(lowerBody, "jquery")) { stack.addComponent("jQuery"); stack.setLanguage("JavaScript"); }
        if (containsToken(lowerBody, "bootstrap")) stack.addComponent("Bootstrap");
        if (containsToken(lowerBody, "tailwind")) stack.addComponent("Tailwind CSS");
        if (containsToken(lowerBody, "bulma")) stack.addComponent("Bulma CSS");
        if (containsToken(lowerBody, "foundation")) stack.addComponent("Foundation");
        if (containsToken(lowerBody, "semantic-ui")) stack.addComponent("Semantic UI");
        if (containsToken(lowerBody, "material-ui") || containsToken(lowerBody, "mui"))
            stack.addComponent("Material-UI");
        if (containsToken(lowerBody, "ant design") || containsPath(lowerBody, "antd"))
            stack.addComponent("Ant Design");
        if (containsToken(lowerBody, "element ui")) stack.addComponent("Element UI");
        if (containsToken(lowerBody, "vuetify")) stack.addComponent("Vuetify");
        if (containsToken(lowerBody, "quasar")) stack.addComponent("Quasar");
        if (containsPath(lowerBody, "_next/"))
            { stack.addFramework("Next.js"); stack.setLanguage("JavaScript/TypeScript"); }
        if (containsPath(lowerBody, "_nuxt/") || containsToken(lowerBody, "nuxt"))
            { stack.addFramework("Nuxt.js"); stack.setLanguage("JavaScript/TypeScript"); }
        if (containsPath(lowerBody, "gatsby"))
            { stack.addFramework("Gatsby"); stack.setLanguage("JavaScript"); }
        if (containsPath(lowerBody, "astro"))
            { stack.addFramework("Astro"); stack.setLanguage("JavaScript"); }
        if (containsPath(lowerBody, "remix"))
            { stack.addFramework("Remix"); stack.setLanguage("JavaScript/TypeScript"); }

        // ========== API风格 ==========
        if (lowerReq.contains("content-type: application/json") || lowerResp.contains("application/json"))
            stack.setApiStyle("REST/JSON");
        if (lowerReq.contains("content-type: application/graphql") || lowerResp.contains("graphql"))
            stack.setApiStyle("GraphQL");
        if (lowerReq.contains("content-type: application/soap") || lowerResp.contains("soap"))
            stack.setApiStyle("SOAP");
        if (lowerReq.contains("content-type: application/xml") || lowerResp.contains("application/xml"))
            stack.setApiStyle("XML-RPC");
        if (lowerResp.contains("grpc") || lowerResp.contains("application/grpc"))
            stack.setApiStyle("gRPC");
        if (containsToken(lowerResp, "swagger") || containsToken(lowerResp, "openapi"))
            stack.addComponent("Swagger/OpenAPI");
        if (containsPath(lowerBody, "swagger-ui") || containsPath(lowerBody, "swaggerui"))
            stack.addComponent("Swagger UI");
        if (containsToken(lowerResp, "postman")) stack.addComponent("Postman Collection");
        if (containsToken(lowerResp, "redoc")) stack.addComponent("ReDoc");
        if (containsToken(lowerResp, "stoplight")) stack.addComponent("Stoplight");

        // ========== 安全组件 ==========
        if (lowerResp.contains("rememberme=deleteme"))
            { stack.addComponent("Apache Shiro"); stack.setLanguage("Java"); }
        if (containsToken(lowerResp, "jwt") || lowerReq.contains("authorization: bearer"))
            stack.addComponent("JWT");
        if (containsToken(lowerResp, "oauth")) stack.addComponent("OAuth");
        if (containsToken(lowerResp, "saml")) stack.addComponent("SAML");
        if (containsToken(lowerResp, "cas") || containsPath(lowerBody, "/cas/"))
            stack.addComponent("CAS单点登录");
        if (containsToken(lowerResp, "keycloak")) stack.addComponent("Keycloak");

        // ========== 更多中间件/组件 ==========
        if (containsToken(lowerResp, "elasticsearch")) { stack.addComponent("ElasticSearch"); stack.setLanguage("Java"); }
        if (containsToken(lowerResp, "kibana")) stack.addComponent("Kibana");
        if (containsToken(lowerResp, "kafka")) { stack.addComponent("Apache Kafka"); stack.setLanguage("Java/Scala"); }
        if (containsToken(lowerResp, "rabbitmq")) { stack.addComponent("RabbitMQ"); stack.setLanguage("Erlang"); }
        if (containsToken(lowerResp, "activemq")) { stack.addComponent("ActiveMQ"); stack.setLanguage("Java"); }
        if (containsToken(lowerResp, "rocketmq")) { stack.addComponent("RocketMQ"); stack.setLanguage("Java"); }
        if (containsToken(lowerResp, "dubbo")) { stack.addComponent("Apache Dubbo"); stack.setLanguage("Java"); }
        if (containsToken(lowerResp, "consul")) { stack.addComponent("Consul"); stack.setLanguage("Go"); }
        if (containsToken(lowerResp, "etcd")) { stack.addComponent("etcd"); stack.setLanguage("Go"); }
        if (containsToken(lowerResp, "zookeeper")) { stack.addComponent("ZooKeeper"); stack.setLanguage("Java"); }
        if (containsToken(lowerResp, "prometheus")) { stack.addComponent("Prometheus"); stack.setLanguage("Go"); }
        if (containsToken(lowerResp, "docker")) stack.addComponent("Docker");
        if (containsToken(lowerResp, "kubernetes") || containsToken(lowerResp, "k8s"))
            stack.addComponent("Kubernetes");
        if (containsToken(lowerResp, "rancher")) { stack.addComponent("Rancher"); stack.setLanguage("Go"); }
        if (containsToken(lowerResp, "harbor")) { stack.addComponent("Harbor"); stack.setLanguage("Go"); }
        if (containsToken(lowerResp, "openshift")) { stack.addComponent("OpenShift"); }
        if (containsToken(lowerResp, "minio")) { stack.addComponent("MinIO"); stack.setLanguage("Go"); }
        if (containsToken(lowerResp, "nacos")) { stack.addComponent("Nacos"); stack.setLanguage("Java"); }
        if (containsToken(lowerResp, "seata")) { stack.addComponent("Seata"); stack.setLanguage("Java"); }
        if (containsToken(lowerResp, "sentinel")) { stack.addComponent("Alibaba Sentinel"); stack.setLanguage("Java"); }
        if (containsToken(lowerResp, "rocketmq")) { stack.addComponent("RocketMQ"); stack.setLanguage("Java"); }
        if (containsToken(lowerResp, "nexus")) { stack.addComponent("Sonatype Nexus"); stack.setLanguage("Java"); }
        if (containsToken(lowerResp, "artifactory")) { stack.addComponent("JFrog Artifactory"); stack.setLanguage("Java"); }
        if (containsToken(lowerResp, "sonarqube")) { stack.addComponent("SonarQube"); stack.setLanguage("Java"); }
        if (containsToken(lowerResp, "vault")) { stack.addComponent("HashiCorp Vault"); stack.setLanguage("Go"); }
        if (containsToken(lowerResp, "nomad")) { stack.addComponent("HashiCorp Nomad"); stack.setLanguage("Go"); }
        if (containsToken(lowerResp, "consul")) { stack.addComponent("Consul"); stack.setLanguage("Go"); }
        if (containsToken(lowerResp, "terraform")) { stack.addComponent("Terraform"); }
        if (containsToken(lowerResp, "ansible")) { stack.addComponent("Ansible"); stack.setLanguage("Python"); }
        if (containsToken(lowerResp, "puppet")) { stack.addComponent("Puppet"); stack.setLanguage("Ruby"); }
        if (containsToken(lowerResp, "chef")) { stack.addComponent("Chef"); stack.setLanguage("Ruby"); }
        if (containsToken(lowerResp, "saltstack")) { stack.addComponent("SaltStack"); stack.setLanguage("Python"); }

        // ========== 宝塔/面板类 ==========
        if (containsToken(lowerBody, "宝塔") || containsToken(lowerBody, "bt.cn") || containsPath(lowerBody, "/bt_"))
            stack.addComponent("宝塔面板");
        if (containsToken(lowerBody, "cPanel")) stack.addComponent("cPanel");
        if (containsToken(lowerBody, "plesk")) stack.addComponent("Plesk");
        if (containsToken(lowerBody, "directadmin")) stack.addComponent("DirectAdmin");
        if (containsToken(lowerBody, "webmin") || containsPath(lowerBody, "/webmin/"))
            stack.addComponent("Webmin");
        if (containsToken(lowerBody, "ajenti")) stack.addComponent("Ajenti");
        if (containsToken(lowerBody, "cockpit")) stack.addComponent("Cockpit");

        // ========== 操作系统 ==========
        if (server != null)
        {
            String svr = server.toLowerCase();
            if (svr.contains("win32") || svr.contains("windows") || svr.contains("microsoft-iis")) stack.setOs("Windows");
            if (svr.contains("ubuntu")) stack.setOs("Ubuntu/Linux");
            if (svr.contains("debian")) stack.setOs("Debian/Linux");
            if (svr.contains("centos")) stack.setOs("CentOS/Linux");
            if (svr.contains("red hat") || svr.contains("rhel")) stack.setOs("RHEL/Linux");
            if (svr.contains("fedora")) stack.setOs("Fedora/Linux");
            if (svr.contains("alpine")) stack.setOs("Alpine/Linux");
            if (svr.contains("suse") || svr.contains("opensuse")) stack.setOs("openSUSE/Linux");
            if (svr.contains("arch")) stack.setOs("Arch Linux");
            if (svr.contains("gentoo")) stack.setOs("Gentoo/Linux");
        }
        if (lowerResp.contains("windows nt")) stack.setOs("Windows");
        if (lowerResp.contains("linux")) stack.setOs("Linux");
        if (lowerResp.contains("freebsd")) stack.setOs("FreeBSD");
        if (lowerResp.contains("openbsd")) stack.setOs("OpenBSD");
        if (lowerResp.contains("netbsd")) stack.setOs("NetBSD");
        if (lowerResp.contains("darwin")) stack.setOs("macOS");
        if (lowerResp.contains("aix")) stack.setOs("AIX");
        if (lowerResp.contains("solaris")) stack.setOs("Solaris");

        // ========== HTML Meta 标签精确匹配 ==========
        if (containsMeta(body, "generator", "wordpress"))
            { stack.setCms("WordPress"); stack.setLanguage("PHP"); }
        if (containsMeta(body, "generator", "drupal"))
            { stack.setCms("Drupal"); stack.setLanguage("PHP"); }
        if (containsMeta(body, "generator", "joomla"))
            { stack.setCms("Joomla"); stack.setLanguage("PHP"); }
        if (containsMeta(body, "generator", "ghost"))
            { stack.setCms("Ghost"); stack.setLanguage("JavaScript"); }
        if (containsMeta(body, "generator", "mediawiki"))
            { stack.setCms("MediaWiki"); stack.setLanguage("PHP"); }
        if (containsMeta(body, "generator", "django"))
            { stack.setLanguage("Python"); stack.addFramework("Django"); }

        // ========== 特定HTML class/id特征 ==========
        if (lowerBody.contains("class=\"ant-") || lowerBody.contains("class='ant-"))
            stack.addComponent("Ant Design");
        if (lowerBody.contains("class=\"el-") || lowerBody.contains("class='el-"))
            stack.addComponent("Element UI");
        if (lowerBody.contains("class=\"mud-") || lowerBody.contains("class='mud-"))
            stack.addComponent("MudBlazor");
        if (lowerBody.contains("class=\"v-application") || lowerBody.contains("class='v-application"))
            stack.addComponent("Vuetify");
        if (lowerBody.contains("data-bs-theme") || lowerBody.contains("data-toggle"))
            stack.addComponent("Bootstrap");
        if (lowerBody.contains("tailwindcss") || lowerBody.contains("tailwind-merge"))
            stack.addComponent("Tailwind CSS");

        // ========== 路径特征（补充高置信度识别） ==========
        if (containsPath(lowerReq, "/wp-admin/") || containsPath(lowerReq, "/wp-login.php"))
            { stack.setCms("WordPress"); stack.setLanguage("PHP"); }
        if (containsPath(lowerReq, "/administrator/") || containsPath(lowerReq, "/administrator/index.php"))
            { stack.setCms("Joomla"); stack.setLanguage("PHP"); }
        if (containsPath(lowerReq, "/user/login") && containsToken(lowerBody, "drupal"))
            { stack.setCms("Drupal"); stack.setLanguage("PHP"); }
        if (containsPath(lowerReq, "/solr/"))
            { stack.setLanguage("Java"); stack.addComponent("Apache Solr"); }
        if (containsPath(lowerReq, "/console/login/login.jsp") || containsPath(lowerReq, "/console/"))
            { stack.setLanguage("Java"); stack.addComponent("Oracle WebLogic Console"); }
        if (containsPath(lowerReq, "/manager/html") || containsPath(lowerReq, "/host-manager/html"))
            { stack.setLanguage("Java"); stack.addComponent("Apache Tomcat Manager"); }
        if (containsPath(lowerReq, "/jenkins/login") || containsPath(lowerReq, "/jenkins/"))
            { stack.setLanguage("Java"); stack.addComponent("Jenkins"); }
        if (containsPath(lowerReq, "/actuator/"))
            { stack.setLanguage("Java"); stack.addComponent("Spring Boot Actuator"); }
        if (containsPath(lowerReq, "/api/v1/") || containsPath(lowerReq, "/api/v2/"))
            stack.setApiStyle("REST/JSON");
        if (containsPath(lowerReq, "/graphql"))
            stack.setApiStyle("GraphQL");
        if (containsPath(lowerReq, "/grafana/"))
            { stack.setCms("Grafana"); stack.setLanguage("Go"); }
        if (containsPath(lowerReq, "/confluence/"))
            { stack.setCms("Atlassian Confluence"); stack.setLanguage("Java"); }
        if (containsPath(lowerReq, "/jira/"))
            { stack.setCms("Atlassian Jira"); stack.setLanguage("Java"); }
        if (containsPath(lowerReq, "/nacos/"))
            { stack.setLanguage("Java"); stack.addComponent("Nacos"); }
        if (containsPath(lowerReq, "/druid/"))
            { stack.setLanguage("Java"); stack.addComponent("Alibaba Druid"); }
        if (containsPath(lowerReq, "/swagger-ui.html") || containsPath(lowerReq, "/swagger-ui/"))
            stack.addComponent("Swagger UI");
        if (containsPath(lowerReq, "/api-docs") || containsPath(lowerReq, "/v2/api-docs"))
            stack.addComponent("SpringFox/Swagger");
        if (containsPath(lowerReq, "/redoc") || containsPath(lowerReq, "/redoc.html"))
            stack.addComponent("ReDoc");
        if (containsPath(lowerReq, "/phpmyadmin/"))
            { stack.setCms("phpMyAdmin"); stack.setLanguage("PHP"); }
        if (containsPath(lowerReq, "/dede/"))
            { stack.setCms("DedeCMS"); stack.setLanguage("PHP"); }
        if (containsPath(lowerReq, "/e/"))
            { stack.setCms("EmpireCMS"); stack.setLanguage("PHP"); }
        if (containsPath(lowerReq, "/general/"))
            { stack.setCms("通达OA"); stack.setLanguage("PHP"); }
        if (containsPath(lowerReq, "/weaver/"))
            { stack.setCms("泛微e-cology"); stack.setLanguage("Java"); }
        if (containsPath(lowerReq, "/webroot/"))
            { stack.setCms("帆软报表"); stack.setLanguage("Java"); }
    }

    private static String fmtVer(String ver)
    {
        return (ver != null && !ver.isEmpty()) ? " " + ver : "";
    }

    /**
     * AI深度分析 - 解析AI返回的技术栈JSON，提取所有字段。
     */
    private void aiBasedDetect(String aiResult, TechStack stack)
    {
        try
        {
            Map<String, Object> parsed = AiResponseParser.parseFirstObject(aiResult);
            if (parsed.isEmpty()) return;

            String lang = AiResponseParser.getString(parsed, "language");
            if (!lang.isEmpty()) stack.setLanguage(lang);

            String framework = AiResponseParser.getString(parsed, "framework");
            if (!framework.isEmpty()) stack.addFramework(framework);

            String webServer = AiResponseParser.getString(parsed, "webServer");
            if (!webServer.isEmpty()) stack.setWebServer(webServer);

            String os = AiResponseParser.getString(parsed, "os");
            if (!os.isEmpty()) stack.setOs(os);

            String cms = AiResponseParser.getString(parsed, "cms");
            if (!cms.isEmpty()) stack.setCms(cms);

            String frontend = AiResponseParser.getString(parsed, "frontend");
            if (!frontend.isEmpty()) stack.setFrontend(frontend);

            String apiStyle = AiResponseParser.getString(parsed, "apiStyle");
            if (!apiStyle.isEmpty()) stack.setApiStyle(apiStyle);

            // 扩展字段：WAF、CDN、数据库、缓存、反向代理、负载均衡等
            String[] extraFields = {"waf", "cdn", "database", "cache", "reverseProxy", "loadBalancer", "middleware", "sessionFramework"};
            for (String field : extraFields)
            {
                String val = AiResponseParser.getString(parsed, field);
                if (!val.isEmpty()) stack.addComponent(field + ": " + val);
            }

            String confidence = AiResponseParser.getString(parsed, "confidence");
            if (!confidence.isEmpty()) stack.addComponent("AI置信度: " + confidence);

            for (String comp : AiResponseParser.getStringList(parsed, "components"))
            {
                if (!comp.trim().isEmpty()) stack.addComponent(comp);
            }
        }
        catch (Exception ignored) {}
    }

    private void extractHeader(String response, String headerName, TechStack stack)
    {
        for (String line : response.split("\r?\n"))
        {
            if (line.toLowerCase().startsWith(headerName))
            {
                String value = line.substring(line.indexOf(':') + 1).trim();
                stack.setWebServer(value);
                break;
            }
        }
    }
    /**
     * 获取指定host的技术栈（从缓存）。
     */
    public static TechStack get(String host)
    {
        return cache.get(host);
    }

    /**
     * 清除指定 host 的缓存，强制下次重新分析。
     */
    public static void invalidate(String host)
    {
        cache.remove(host);
    }

    /**
     * 技术栈数据模型。
     */
    public static class TechStack
    {
        private final String host;
        private String language = "";
        private final Set<String> frameworks = new LinkedHashSet<>();
        private String webServer = "";
        private String os = "";
        private String cms = "";
        private String frontend = "";
        private String apiStyle = "";
        private final Set<String> components = new LinkedHashSet<>();

        public TechStack(String host) { this.host = host; }

        public boolean isComplete()
        {
            return !language.isEmpty() && !webServer.isEmpty();
        }

        public String summary()
        {
            StringBuilder sb = new StringBuilder(host + ": ");
            if (!language.isEmpty()) sb.append(language).append(" | ");
            if (!frameworks.isEmpty()) sb.append(String.join("+", frameworks)).append(" | ");
            if (!webServer.isEmpty()) sb.append(webServer).append(" | ");
            if (!cms.isEmpty()) sb.append("CMS:").append(cms).append(" | ");
            if (!frontend.isEmpty()) sb.append(frontend).append(" | ");
            if (!components.isEmpty()) sb.append("[").append(String.join(",", components)).append("]");
            return sb.toString();
        }

        // Getters and Setters
        public String getHost() { return host; }
        public String getLanguage() { return language; }
        public void setLanguage(String v) { language = v; }
        public Set<String> getFrameworks() { return frameworks; }
        public void addFramework(String v) { frameworks.add(v); }
        public String getWebServer() { return webServer; }
        public void setWebServer(String v) { webServer = v; }
        public String getOs() { return os; }
        public void setOs(String v) { os = v; }
        public String getCms() { return cms; }
        public void setCms(String v) { cms = v; }
        public String getFrontend() { return frontend; }
        public void setFrontend(String v) { frontend = v; }
        public String getApiStyle() { return apiStyle; }
        public void setApiStyle(String v) { apiStyle = v; }
        public Set<String> getComponents() { return components; }
        public void addComponent(String v) { components.add(v); }

        /**
         * 获取所有已识别技术的合集。
         */
        public Set<String> getTechnologies()
        {
            Set<String> all = new LinkedHashSet<>();
            if (!language.isEmpty()) all.add(language);
            all.addAll(frameworks);
            if (!webServer.isEmpty()) all.add(webServer);
            if (!os.isEmpty()) all.add(os);
            if (!cms.isEmpty()) all.add(cms);
            if (!frontend.isEmpty()) all.add(frontend);
            if (!apiStyle.isEmpty()) all.add(apiStyle);
            all.addAll(components);
            return all;
        }
    }
}
