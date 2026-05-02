package ai.burp.provider;

import java.util.List;

import ai.burp.model.ChatMessage;

/**
 * 支持流式输出的AI提供者接口。
 * 继承AIProvider，增加流式对话和中断能力。
 */
public interface StreamingAIProvider extends AIProvider
{
    /**
     * 流式对话回调接口。
     */
    interface StreamCallback
    {
        /** 收到一个token，从网络线程调用 */
        void onToken(String token);

        /** 流式输出完成，fullResponse为完整回复 */
        void onComplete(String fullResponse);

        /** 发生错误 */
        void onError(Exception e);
    }

    /**
     * 流式发送对话消息，逐token通过回调输出。
     *
     * @param messages 对话消息列表
     * @param callback 流式回调
     * @throws AIProviderException 如果请求失败
     */
    void chatStream(List<ChatMessage> messages, StreamCallback callback) throws AIProviderException;

    /**
     * 中断当前正在进行的流式请求。
     */
    void stopStreaming();
}
