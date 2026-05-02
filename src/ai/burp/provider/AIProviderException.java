package ai.burp.provider;

/**
 * Exception thrown by AI providers.
 */
public class AIProviderException extends Exception
{
    private final int statusCode;

    public AIProviderException(String message)
    {
        super(message);
        this.statusCode = -1;
    }

    public AIProviderException(String message, int statusCode)
    {
        super(message);
        this.statusCode = statusCode;
    }

    public AIProviderException(String message, Throwable cause)
    {
        super(message, cause);
        this.statusCode = -1;
    }

    public int getStatusCode()
    {
        return statusCode;
    }
}
