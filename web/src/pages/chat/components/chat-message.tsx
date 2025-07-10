import { Avatar, Button, Accordion, AccordionItem } from "@heroui/react";
import { useTranslation } from "react-i18next";
import ReactMarkdown from 'react-markdown';
import rehypeHighlight from "rehype-highlight";
import rehypeKatex from 'rehype-katex';
import remarkGfm from 'remark-gfm';
import remarkMath from 'remark-math';
import 'katex/dist/katex.min.css';
import 'highlight.js/styles/github.css';

import LocalIcon from '@/components/LocalIcon';
import { mcpService } from "@/services/mcp.ts";
import {Message, ToolCall, ToolResult} from "@/types/message.ts";
import { toast } from '@/utils/toast.ts';

interface ChatMessageProps {
  message: Message;
  messages: Message[];
  onToolCall?: (toolCall: ToolCall, result: string) => void;
}

export function ChatMessage({ message, messages, onToolCall }: ChatMessageProps) {
  const { t } = useTranslation();
  const isBot = message.sender === 'bot';

  if (!message.content && !message.reasoning_content && (!message.toolCalls || message.toolCalls.length === 0)) {
    return null;
  }

  const findToolResult = (toolId: string): ToolResult | undefined => {
    return messages.find((m: Message) => m.toolResult?.toolCallId === toolId)?.toolResult;
  };

  const handleRunTool = async (tool: ToolCall) => {
    try {
      // Use originalName if present, else fallback
      const toolNameForParsing = tool?.function?.originalName || tool?.function?.name;
      if (!toolNameForParsing) {
        toast.error(t('errors.invalid_tool_name'), {
          duration: 3000,
        });
        return;
      }

      // Parse serverName:toolName format
      const [serverName, toolName] = toolNameForParsing.split(':');
      if (!serverName || !toolName) {
        toast.error(t('errors.invalid_tool_name'), {
          duration: 3000,
        });
        return;
      }

      const sessionId = mcpService.getSessionId(serverName);

      if (!sessionId) {
        toast.error(t('errors.server_not_connected', { server: serverName }), {
          duration: 3000,
        });
        return;
      }

      // Parse arguments string to object
      let args;
      try {
        args = JSON.parse(tool.function.arguments);
      } catch {
        toast.error(t('errors.invalid_tool_arguments'), {
          duration: 3000,
        });
        return;
      }
      const result = await mcpService.callTool(serverName, toolName, args);

      // Display tool call result
      toast.success(t('chat.tool_call_success', { result }), {
        duration: 3000,
      });

      if (onToolCall) {
        onToolCall(tool, result);
      }
    } catch (error) {
      toast.error(t('errors.tool_call_failed', { error: (error as Error).message }), {
        duration: 3000,
      });
    }
  };

  return (
    <div className={`flex gap-3 mb-4 ${isBot ? 'flex-row' : 'flex-row-reverse'}`}>
      <Avatar
        size="sm"
        src={isBot ? "/logo.png" : undefined}
        name={isBot ? "MCP" : t('chat.you')}
      />
      <div
        className={`px-4 py-2 rounded-lg max-w-[80%] ${
          isBot ? 'bg-secondary' : 'bg-primary text-primary-foreground'
        }`}
      >
        {message.reasoning_content && (
          <div className="mb-3">
            {message.isStreaming ? (
              <div className="bg-orange-50 dark:bg-orange-950/20 border border-orange-200 dark:border-orange-800 rounded-lg p-3">
                <div className="flex items-center gap-2 mb-2">
                  <div className="w-3 h-3 bg-orange-400 rounded-full animate-pulse"></div>
                  <span className="text-sm font-medium text-orange-700 dark:text-orange-300">
                    {t('chat.thinking')}
                  </span>
                </div>
                <div className="prose prose-sm dark:prose-invert max-w-none text-orange-900 dark:text-orange-100">
                  <ReactMarkdown
                    remarkPlugins={[remarkGfm, remarkMath]}
                    rehypePlugins={[rehypeHighlight, rehypeKatex]}
                  >
                    {message.reasoning_content}
                  </ReactMarkdown>
                </div>
              </div>
            ) : (
              <Accordion selectionMode="multiple">
                <AccordionItem
                  key="reasoning"
                  title={
                    <div className="flex items-center gap-2">
                      <LocalIcon icon="lucide:brain" className="w-4 h-4 text-orange-600 dark:text-orange-400" />
                      <span className="text-sm text-default-600">{t('chat.reasoning_process')}</span>
                    </div>
                  }
                  textValue={t('chat.reasoning_process')}
                  className="px-0"
                >
                  <div className="prose prose-sm dark:prose-invert max-w-none">
                    <ReactMarkdown
                      remarkPlugins={[remarkGfm, remarkMath]}
                      rehypePlugins={[rehypeHighlight, rehypeKatex]}
                    >
                      {message.reasoning_content}
                    </ReactMarkdown>
                  </div>
                </AccordionItem>
              </Accordion>
            )}
          </div>
        )}
        {message.content && (
          <div className="prose prose-sm dark:prose-invert max-w-none">
            <ReactMarkdown
              remarkPlugins={[remarkGfm, remarkMath]}
              rehypePlugins={[rehypeHighlight, rehypeKatex]}
              components={{
                code({className, children, ...props}) {
                  const match = /language-(\w+)/.exec(className || '');
                  return match ? (
                    <code className={className} {...props}>
                      {children}
                    </code>
                  ) : (
                    <code className="bg-gray-100 dark:bg-gray-800 rounded px-1" {...props}>
                      {children}
                    </code>
                  );
                }
              }}
            >
              {message.content}
            </ReactMarkdown>
          </div>
        )}
        {message.isStreaming && (
          <span className="inline-block w-2 h-4 ml-1 bg-current animate-pulse" />
        )}
        {message.toolCalls?.filter(tool => tool?.function?.name).map((tool, index) => {
          const toolResult = findToolResult(tool.id);
          const toolDisplayName = tool.function.originalName || tool.function.name;
          return (
            <div key={index} className="mt-3 border border-blue-200 dark:border-blue-800 rounded-lg bg-blue-50/50 dark:bg-blue-950/20 overflow-hidden">
              <div className="flex items-center justify-between p-3 bg-blue-100/70 dark:bg-blue-900/30 border-b border-blue-200 dark:border-blue-800">
                <div className="flex items-center gap-2">
                  <div className="w-6 h-6 bg-blue-500 rounded-full flex items-center justify-center">
                    <LocalIcon icon="lucide:wrench" className="w-3 h-3 text-white" />
                  </div>
                  <span className="font-medium text-blue-900 dark:text-blue-100 text-sm">
                    {toolDisplayName}
                  </span>
                </div>
                {toolResult ? (
                  <div className="flex items-center gap-1 text-green-600 dark:text-green-400">
                    <LocalIcon icon="lucide:check" className="w-4 h-4" />
                    <span className="text-xs font-medium">{t('chat.tool_completed')}</span>
                  </div>
                ) : (
                  <div className="flex items-center gap-1 text-orange-600 dark:text-orange-400">
                    <LocalIcon icon="lucide:loader-2" className="w-4 h-4" />
                    <span className="text-xs font-medium">{t('chat.tool_pending')}</span>
                  </div>
                )}
              </div>
              
              <div className="p-3">
                <Accordion selectionMode="multiple">
                  <AccordionItem
                    key={`${tool.id}-args`}
                    title={
                      <div className="flex items-center gap-2">
                        <LocalIcon icon="lucide:key" className="w-4 h-4 text-blue-600 dark:text-blue-400" />
                        <span className="text-sm">{t('chat.arguments')}</span>
                      </div>
                    }
                    textValue={t('chat.arguments')}
                    className="px-0"
                  >
                    <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-md p-3">
                      <pre className="text-xs text-gray-700 dark:text-gray-300 overflow-auto">
                        {(() => {
                          try {
                            return JSON.stringify(JSON.parse(tool.function.arguments), null, 2);
                          } catch {
                            return tool.function.arguments;
                          }
                        })()}
                      </pre>
                    </div>
                  </AccordionItem>
                  {toolResult ? (
                    <AccordionItem
                      key={`${tool.id}-result`}
                      title={
                        <div className="flex items-center gap-2">
                          <LocalIcon icon="lucide:download" className="w-4 h-4 text-green-600 dark:text-green-400" />
                          <span className="text-sm">{t('chat.result')}</span>
                        </div>
                      }
                      textValue={t('chat.result')}
                      className="px-0"
                    >
                      <div className="bg-green-50 dark:bg-green-950/30 border border-green-200 dark:border-green-800 rounded-md p-3">
                        <pre className="text-xs text-green-800 dark:text-green-200 overflow-auto">
                          {(() => {
                            try {
                              return JSON.stringify(JSON.parse(toolResult.result), null, 2);
                            } catch {
                              return toolResult.result;
                            }
                          })()}
                        </pre>
                      </div>
                    </AccordionItem>
                  ) : null}
                </Accordion>
                
                {/* 执行按钮 */}
                {!toolResult && (
                  <div className="mt-3 pt-3 border-t border-blue-200 dark:border-blue-800">
                    <Button
                      size="sm"
                      className="bg-blue-600 hover:bg-blue-700 text-white font-medium shadow-sm"
                      startContent={<LocalIcon icon="lucide:play" className="w-3 h-3" />}
                      onPress={() => handleRunTool(tool)}
                    >
                      {t('chat.run_tool')}
                    </Button>
                  </div>
                )}
              </div>
            </div>
          );
        })}
        {/* 不再单独显示tool result消息，它们会关联到对应的tool call */}
      </div>
    </div>
  );
}
