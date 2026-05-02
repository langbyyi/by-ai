package ai.burp.model;

/**
 * Represents a chat message with a role and content.
 */
public class ChatMessage
{
    public enum Role
    {
        SYSTEM("system"),
        USER("user"),
        ASSISTANT("assistant");

        private final String value;

        Role(String value)
        {
            this.value = value;
        }

        public String value()
        {
            return value;
        }
    }

    private final Role role;
    private final String content;

    public ChatMessage(Role role, String content)
    {
        this.role = role;
        this.content = content;
    }

    public static ChatMessage system(String content)
    {
        return new ChatMessage(Role.SYSTEM, content);
    }

    public static ChatMessage user(String content)
    {
        return new ChatMessage(Role.USER, content);
    }

    public static ChatMessage assistant(String content)
    {
        return new ChatMessage(Role.ASSISTANT, content);
    }

    public Role role()
    {
        return role;
    }

    public String content()
    {
        return content;
    }

    @Override
    public String toString()
    {
        return "[" + role.value() + "] " + content;
    }
}
