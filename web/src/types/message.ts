export interface Message {
  id: string;
  session_id: string;
  content: string;
  sender: 'user' | 'bot' | 'system';
  timestamp: string;
  isStreaming?: boolean;
  toolCalls?: ToolCall[];
  toolResult?: ToolResult;
  reasoning_content?: string;
}

export interface BackendMessage {
  id: string;
  content: string;
  sender: string;
  timestamp: string;
  reasoning_content?: string;
  toolCalls?: string;
  toolResult?: string;
}

export interface ToolCall {
  id: string;
  type: string;
  function: {
    name: string;
    arguments: string;
    originalName?: string;
  };
}

export interface ToolResult {
  toolCallId: string;
  name: string;
  result: string;
}
