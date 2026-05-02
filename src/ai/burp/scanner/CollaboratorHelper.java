package ai.burp.scanner;

import java.util.*;

import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.Interaction;

/**
 * Collaborator 回调验证助手。
 * 独立于 FullVulnDatabase，避免 Pro-only API 类加载失败导致核心功能不可用。
 *
 * 仅在 Burp Suite Professional 环境下可用，
 * Community Edition 或 API 不兼容时，所有方法安全降级（返回空/false）。
 */
public final class CollaboratorHelper
{
    private CollaboratorHelper() {}

    /** 运行时 Collaborator 客户端引用 */
    private static volatile CollaboratorClient collaboratorClient = null;

    /** 标记 Collaborator 是否可用（避免反复尝试失败的类加载） */
    private static volatile boolean available = true;

    /**
     * 设置 Collaborator 客户端引用。
     */
    public static void setCollaboratorClient(CollaboratorClient client)
    {
        collaboratorClient = client;
        available = (client != null);
    }

    public static CollaboratorClient getCollaboratorClient()
    {
        return available ? collaboratorClient : null;
    }

    /**
     * 检查 Collaborator 是否收到了带外交互回调。
     * 返回所有交互列表，不可用或出错时返回空列表。
     */
    public static List<Interaction> checkOobInteractions()
    {
        if (!available || collaboratorClient == null)
        {
            return Collections.emptyList();
        }
        try
        {
            return collaboratorClient.getAllInteractions();
        }
        catch (Exception e)
        {
            return Collections.emptyList();
        }
        catch (NoClassDefFoundError e)
        {
            // Pro-only API 不可用时的安全降级
            available = false;
            return Collections.emptyList();
        }
    }

    /**
     * 快速判断是否存在 Collaborator 带外回调。
     */
    public static boolean hasOobInteraction()
    {
        return !checkOobInteractions().isEmpty();
    }

    /**
     * 获取 Collaborator 交互的详细信息描述（用于 AI 验证报告）。
     * 返回人类可读的交互摘要，无交互时返回空字符串。
     */
    public static String getOobInteractionSummary()
    {
        try
        {
            List<Interaction> interactions = checkOobInteractions();
            if (interactions.isEmpty())
            {
                return "";
            }
            StringBuilder sb = new StringBuilder();
            sb.append("检测到 ").append(interactions.size()).append(" 个带外交互回调:\n");
            for (Interaction interaction : interactions)
            {
                sb.append("- 类型: ").append(interaction.type())
                  .append(", 来源IP: ").append(interaction.clientIp().getHostAddress())
                  .append(", 时间: ").append(interaction.timeStamp()).append("\n");
            }
            return sb.toString();
        }
        catch (NoClassDefFoundError e)
        {
            available = false;
            return "";
        }
    }
}
