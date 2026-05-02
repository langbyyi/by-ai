package ai.burp.provider;

import java.util.List;

import ai.burp.model.ChatMessage;

/**
 * Interface for AI providers.
 * Implementations can connect to different AI APIs.
 */
public interface AIProvider
{
    /**
     * Send messages to the AI and get a response.
     *
     * @param messages the conversation messages
     * @return the AI response content
     * @throws AIProviderException if the request fails
     */
    String chat(List<ChatMessage> messages) throws AIProviderException;

    /**
     * Test the connection to the AI provider.
     *
     * @return a success message
     * @throws AIProviderException if the connection fails
     */
    String testConnection() throws AIProviderException;

    /**
     * Check if the provider is properly configured.
     *
     * @return true if configured
     */
    boolean isConfigured();

    /**
     * Get the provider name.
     */
    String getName();
}
