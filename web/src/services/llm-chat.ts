import { getDefaultBaseURL, buildEndpointURL } from '../config/llm-providers-adapter';
import { LLMProvider } from '../types/llm';
import { Message } from '../types/message';

// Provider-specific interfaces
interface ProviderConfig {
  handlePayload: (payload: ChatCompletionRequest, provider: LLMProvider) => ChatCompletionRequest;
  buildHeaders: (provider: LLMProvider) => Record<string, string>;
  getEndpoint: (provider: LLMProvider) => string;
  handleToolNames: (tools: ToolDefinition[]) => ToolDefinition[];
  restoreToolNames: (toolCalls: ToolCallData[], originalTools: AvailableTool[]) => ToolCallData[];
}

interface AvailableTool {
  name: string;
  description: string;
  parameters: Record<string, unknown>;
}

interface ToolDefinition {
  type: 'function';
  function: {
    name: string;
    description: string;
    parameters: {
      type: string;
      properties: Record<string, unknown>;
      required?: string[];
    };
  };
}

interface ToolCallData {
  id: string;
  type: string;
  function: {
    name: string;
    arguments: string;
  };
}

interface ChatMessage {
  role: 'system' | 'user' | 'assistant' | 'tool';
  content: string;
  tool_call_id?: string;
  tool_calls?: Array<{
    id: string;
    type: 'function';
    function: {
      name: string;
      arguments: string;
    };
  }>;
}

interface ChatCompletionRequest {
  model: string;
  messages: ChatMessage[];
  tools?: Array<{
    type: 'function';
    function: {
      name: string;
      description: string;
      parameters: {
        type: string;
        properties: Record<string, unknown>;
        required?: string[];
      };
    };
  }>;
  temperature?: number;
  top_p?: number;
  max_tokens?: number;
  max_completion_tokens?: number;
  stream?: boolean;
  frequency_penalty?: number;
  presence_penalty?: number;
}

interface ChatCompletionResponse {
  id: string;
  object: string;
  created: number;
  model: string;
  choices: Array<{
    index: number;
    delta: {
      role?: string;
      content?: string | null;
      reasoning_content?: string | null;
      tool_calls?: Array<{
        id?: string;
        type?: 'function';
        index?: number;
        function?: {
          name?: string;
          arguments?: string;
        };
      }>;
    };
    finish_reason: string | null;
  }>;
  usage?: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  };
}

const REASONING_MODEL_PREFIXES = ['o1', 'o3', 'o4'];
const SYSTEM_TO_USER_MODELS = new Set([
  'o1-preview',
  'o1-preview-2024-09-12', 
  'o1-mini',
  'o1-mini-2024-09-12',
  'o4-mini'
]);

// Provider-specific configurations
const PROVIDER_CONFIGS: Record<string, ProviderConfig> = {
  openai: {
    handlePayload: (payload: ChatCompletionRequest, _provider: LLMProvider) => {
      const modelName = payload.model;
      
      // Handle reasoning models (o1, o3, o4 series)
      if (REASONING_MODEL_PREFIXES.some(prefix => modelName.startsWith(prefix))) {
        const { max_tokens, ...rest } = payload;
        return {
          ...rest,
          max_completion_tokens: max_tokens,
          max_tokens: undefined,
          frequency_penalty: 0,
          presence_penalty: 0,
          temperature: 1,
          top_p: 1,
          messages: payload.messages.map(message => ({
            ...message,
            role: message.role === 'system' 
              ? (SYSTEM_TO_USER_MODELS.has(modelName) ? 'user' : 'developer')
              : message.role
          })) as ChatMessage[]
        };
      }
      
      return payload;
    },
    
    buildHeaders: (provider: LLMProvider) => {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json'
      };
      
      if (provider.config.apiKey) {
        headers['Authorization'] = `Bearer ${String(provider.config.apiKey)}`;
      }
      
      if (provider.config.organization) {
        headers['OpenAI-Organization'] = String(provider.config.organization);
      }
      
      return headers;
    },
    
    getEndpoint: (provider: LLMProvider) => {
      const baseURL = (provider.config.baseURL as string) || getDefaultBaseURL(provider.id);
      return buildEndpointURL(baseURL, '/chat/completions');
    },
    
    handleToolNames: (tools: ToolDefinition[]) => {
      return tools.map(tool => ({
        ...tool,
        function: {
          ...tool.function,
          // OpenAI requires tool names to match ^[a-zA-Z0-9_-]+$ pattern
          name: tool.function.name.replace(/:/g, '_')
        }
      }));
    },
    
    restoreToolNames: (toolCalls: ToolCallData[], originalTools: AvailableTool[]) => {
      return toolCalls.map(toolCall => {
        const originalTool = originalTools.find(tool => 
          tool.name.replace(/:/g, '_') === toolCall.function.name
        );
        return {
          ...toolCall,
          function: {
            ...toolCall.function,
            name: originalTool ? originalTool.name : toolCall.function.name.replace(/_/g, ':')
          }
        };
      });
    }
  },

  anthropic: {
    handlePayload: (payload: ChatCompletionRequest, _provider: LLMProvider) => {
      const maxTokens = payload.max_completion_tokens || payload.max_tokens || 2048;
      
      return {
        model: payload.model,
        max_tokens: maxTokens,
        messages: payload.messages.filter(m => m.role !== 'system'),
        stream: payload.stream,
        temperature: payload.temperature,
        top_p: payload.top_p
      } as ChatCompletionRequest;
    },
    
    buildHeaders: (provider: LLMProvider) => {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json'
      };
      
      if (provider.config.apiKey) {
        headers['x-api-key'] = String(provider.config.apiKey);
        headers['anthropic-version'] = '2023-06-01';
      }
      
      return headers;
    },
    
    getEndpoint: (provider: LLMProvider) => {
      const baseURL = (provider.config.baseURL as string) || getDefaultBaseURL(provider.id);
      return buildEndpointURL(baseURL, '/v1/messages');
    },
    
    handleToolNames: (tools: ToolDefinition[]) => {
      // Anthropic might have different tool name requirements
      return tools;
    },
    
    restoreToolNames: (toolCalls: ToolCallData[], _originalTools: AvailableTool[]) => {
      return toolCalls;
    }
  },

  qwen: {
    handlePayload: (payload: ChatCompletionRequest, _provider: LLMProvider) => {
      // Qwen might have specific requirements
      return {
        ...payload,
        // Qwen supports reasoning_content in responses
        stream: true
      };
    },
    
    buildHeaders: (provider: LLMProvider) => {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json'
      };
      
      if (provider.config.apiKey) {
        headers['Authorization'] = `Bearer ${String(provider.config.apiKey)}`;
      }
      
      return headers;
    },
    
    getEndpoint: (provider: LLMProvider) => {
      const baseURL = (provider.config.baseURL as string) || getDefaultBaseURL(provider.id);
      return buildEndpointURL(baseURL, '/chat/completions');
    },
    
    handleToolNames: (tools: ToolDefinition[]) => {
      // Qwen might allow colons in tool names
      return tools;
    },
    
    restoreToolNames: (toolCalls: ToolCallData[], _originalTools: AvailableTool[]) => {
      return toolCalls;
    }
  },

  // Default configuration for other providers
  default: {
    handlePayload: (payload: ChatCompletionRequest, _provider: LLMProvider) => payload,
    
    buildHeaders: (provider: LLMProvider) => {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json'
      };
      
      if (provider.config.apiKey) {
        headers['Authorization'] = `Bearer ${String(provider.config.apiKey)}`;
      }
      
      return headers;
    },
    
    getEndpoint: (provider: LLMProvider) => {
      const baseURL = (provider.config.baseURL as string) || getDefaultBaseURL(provider.id);
      return buildEndpointURL(baseURL, '/chat/completions');
    },
    
    handleToolNames: (tools: ToolDefinition[]) => tools,
    
    restoreToolNames: (toolCalls: ToolCallData[], _originalTools: AvailableTool[]) => toolCalls
  }
};

export class LLMChatService {
  private abortController: AbortController | null = null;

  private getProviderConfig(providerId: string): ProviderConfig {
    return PROVIDER_CONFIGS[providerId] || PROVIDER_CONFIGS.default;
  }

  public cancelCurrentRequest() {
    if (this.abortController) {
      this.abortController.abort();
      this.abortController = null;
    }
  }

  public async sendMessage(
    provider: LLMProvider,
    messages: Message[],
    modelId?: string,
    availableTools: AvailableTool[] = [],
    onChunk?: (chunk: string) => void,
    onReasoningChunk?: (reasoningChunk: string) => void,
    onToolCall?: (toolCall: ToolCallData[]) => void,
    onComplete?: (message: string) => void,
    onError?: (error: Error) => void
  ): Promise<void> {
    try {
      this.cancelCurrentRequest();
      this.abortController = new AbortController();

      const openAIMessages = this.convertToOpenAIFormat(messages);
      const openAITools = availableTools.length > 0 ? this.convertToolsToOpenAIFormat(availableTools) : undefined;

      const providerConfig = this.getProviderConfig(provider.id);
      const processedTools = openAITools ? providerConfig.handleToolNames(openAITools) : undefined;

      let body: ChatCompletionRequest = {
        model: modelId || provider.models[0]?.id || 'gpt-3.5-turbo',
        messages: openAIMessages,
        tools: processedTools,
        temperature: 0.7,
        top_p: 1,
        max_tokens: 4096,
        stream: true
      };

      body = providerConfig.handlePayload(body, provider);

      const response = await this.makeRequest(provider, body, this.abortController.signal);

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`HTTP ${response.status}: ${errorText}`);
      }

      await this.handleStreamResponse(
        response,
        provider.id,
        availableTools,
        onChunk,
        onReasoningChunk,
        onToolCall,
        onComplete,
        onError
      );

    } catch (error) {
      if (error instanceof Error && error.name !== 'AbortError') {
        onError?.(error);
      }
    } finally {
      this.abortController = null;
    }
  }

  public async callTool(
    toolName: string,
    parameters: Record<string, unknown>
  ): Promise<string> {
    try {
      // Parse tool name format: serverName:toolName
      const [serverName, actualToolName] = toolName.split(':');
      
      const { mcpService } = await import('./mcp');
      const result = await mcpService.callTool(serverName, actualToolName, parameters);
      
      return JSON.stringify(result);
    } catch (error) {
      return JSON.stringify({
        error: error instanceof Error ? error.message : 'Tool call failed'
      });
    }
  }

  private convertToOpenAIFormat(messages: Message[]): ChatMessage[] {
    const converted: ChatMessage[] = [];

    for (const message of messages) {
      if (message.toolResult) {
        converted.push({
          role: 'tool',
          content: String(message.toolResult.result),
          tool_call_id: message.toolResult.toolCallId
        });
      } else if (message.sender === 'user') {
        if (message.content && message.content.trim()) {
          converted.push({
            role: 'user',
            content: message.content
          });
        }
      } else if (message.sender === 'bot') {
        const assistantMessage: ChatMessage = {
          role: 'assistant',
          content: message.content || ''
        };

        if (message.toolCalls && message.toolCalls.length > 0) {
          assistantMessage.tool_calls = message.toolCalls.map(tc => ({
            id: tc.id,
            type: 'function' as const,
            function: {
              name: tc.function.name,
              arguments: tc.function.arguments
            }
          }));
        }

        converted.push(assistantMessage);
      }
    }

    return converted;
  }

  private convertToolsToOpenAIFormat(tools: AvailableTool[]): ToolDefinition[] {
    return tools.map(tool => ({
      type: 'function' as const,
      function: {
        name: tool.name,
        description: tool.description,
        parameters: {
          type: 'object',
          properties: (tool.parameters.properties as Record<string, unknown>) || {},
          required: (tool.parameters.required as string[]) || []
        }
      }
    }));
  }

  private async makeRequest(
    provider: LLMProvider,
    body: ChatCompletionRequest,
    signal: AbortSignal
  ): Promise<Response> {
    const providerConfig = this.getProviderConfig(provider.id);
    
    const headers = providerConfig.buildHeaders(provider);
    const endpoint = providerConfig.getEndpoint(provider);

    return fetch(endpoint, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
      signal
    });
  }

  private async handleStreamResponse(
    response: Response,
    providerId: string,
    originalTools: AvailableTool[],
    onChunk?: (chunk: string) => void,
    onReasoningChunk?: (reasoningChunk: string) => void,
    onToolCall?: (toolCall: ToolCallData[]) => void,
    onComplete?: (message: string) => void,
    onError?: (error: Error) => void
  ): Promise<void> {
    const reader = response.body?.getReader();
    if (!reader) {
      throw new Error('No response body');
    }

    const decoder = new TextDecoder();
    let buffer = '';
    let completeMessage = '';
    let toolCallsAccumulator: Record<number, ToolCallData> = {};
    let hasFinished = false;

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          if (line.startsWith('data: ')) {
            const data = line.slice(6);
            if (data === '[DONE]') {
              if (!hasFinished) {
                hasFinished = true;
                this.finishStream(toolCallsAccumulator, originalTools, completeMessage, providerId, onToolCall, onComplete);
              }
              return;
            }

            try {
              const parsed = JSON.parse(data) as ChatCompletionResponse;
              const choice = parsed.choices[0];
              
              if (!choice) continue;

              if (choice.delta?.reasoning_content) {
                const reasoningChunk = choice.delta.reasoning_content;
                onReasoningChunk?.(reasoningChunk);
              }

              if (choice.delta?.content) {
                const chunk = choice.delta.content;
                completeMessage += chunk;
                onChunk?.(chunk);
              }

              if (choice.delta?.tool_calls) {
                for (const toolCall of choice.delta.tool_calls) {
                  const index = toolCall.index ?? 0;
                  
                  if (!toolCallsAccumulator[index]) {
                    toolCallsAccumulator[index] = {
                      id: toolCall.id || `call_${index}`,
                      type: toolCall.type || 'function',
                      function: {
                        name: toolCall.function?.name || '',
                        arguments: toolCall.function?.arguments || ''
                      }
                    };
                  } else {
                    if (toolCall.function?.arguments) {
                      toolCallsAccumulator[index].function.arguments += toolCall.function.arguments;
                    }
                    if (toolCall.function?.name) {
                      toolCallsAccumulator[index].function.name = toolCall.function.name;
                    }
                    if (toolCall.id) {
                      toolCallsAccumulator[index].id = toolCall.id;
                    }
                  }
                }
              }

              if (choice.finish_reason === 'stop' || choice.finish_reason === 'tool_calls') {
                continue;
              }
            } catch (e) {
              console.warn('Failed to parse SSE data:', data, e);
            }
          }
        }
      }
    } catch (e) {
      console.error('Stream processing failed:', e);
      onError?.(new Error('Stream processing failed'));
    } finally {
      reader.releaseLock();
    }
  }

  private finishStream(
    toolCallsAccumulator: Record<number, ToolCallData>,
    originalTools: AvailableTool[],
    completeMessage: string,
    providerId: string,
    onToolCall?: (toolCall: ToolCallData[]) => void,
    onComplete?: (message: string) => void
  ) {
    const finalToolCalls = Object.values(toolCallsAccumulator);
    if (finalToolCalls.length > 0) {
      const providerConfig = this.getProviderConfig(providerId);
      const restoredToolCalls = providerConfig.restoreToolNames(finalToolCalls, originalTools);
      onToolCall?.(restoredToolCalls);
    }
    
    onComplete?.(completeMessage);
  }

}

export const llmChatService = new LLMChatService();