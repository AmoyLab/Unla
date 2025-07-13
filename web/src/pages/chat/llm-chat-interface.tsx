import {
  Card,
  CardBody,
  Button,
  Input,
  Select,
  SelectItem,
  Chip,
  Tooltip,
  Selection
} from '@heroui/react';
import { Send, Settings, Square, Zap, ChevronDown, ChevronUp, X } from 'lucide-react';
import React, { useState, useEffect, useRef, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate, useParams } from 'react-router-dom';
import { v4 as uuidv4 } from 'uuid';

import { ChatHistory } from './components/chat-history';
import { ChatMessage } from './components/chat-message';

import LocalIcon from '@/components/LocalIcon';
import { useLLMConfig } from '@/hooks/useLLMConfig';
import { getMCPServers, getChatMessages, saveChatMessage, getCurrentUser } from '@/services/api';
import { llmChatService } from '@/services/llm-chat';
import { mcpService } from '@/services/mcp';
import { getSystemPrompt, saveSystemPrompt } from '@/services/systemprompt';
import { Gateway } from '@/types/gateway';
import { LLMProvider, LLMModel } from '@/types/llm';
import { Tool } from '@/types/mcp';
import { Message, ToolCall, ToolResult } from '@/types/message';
import { toast } from '@/utils/toast';


export function LLMChatInterface() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { sessionId } = useParams();
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const messagesContainerRef = useRef<HTMLDivElement>(null);

  const { providers, getEnabledProviders } = useLLMConfig();
  const [selectedProvider, setSelectedProvider] = useState<LLMProvider | null>(null);
  const [selectedModel, setSelectedModel] = useState<string>('');

  const enabledProviders = getEnabledProviders();

  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [isGenerating, setIsGenerating] = useState(false);
  const [selectedChat, setSelectedChat] = useState<string | null>(null);

  const [activeServices, setActiveServices] = useState<string[]>([]);
  const [mcpServers, setMcpServers] = useState<Gateway[]>([]);
  const [tools, setTools] = useState<Record<string, Tool[]>>({});

  const [isHistoryCollapsed, setIsHistoryCollapsed] = useState(false);
  const [isToolsExpanded, setIsToolsExpanded] = useState(false);

  const [userInfo, setUserInfo] = useState<{ username: string; role: string } | null>(null);
  const [systemPrompt, setSystemPrompt] = useState('');
  const [isSystemPromptModalOpen, setIsSystemPromptModalOpen] = useState(false);
  const [systemPromptDraft, setSystemPromptDraft] = useState('');
  const [authToken, setAuthToken] = useState(''); // Authorization token state

  // Redirect to new session if no sessionId provided
  useEffect(() => {
    if (!sessionId) {
      const newSessionId = uuidv4();
      navigate(`/chat/${newSessionId}`, { replace: true });
    }
  }, [sessionId, navigate]);

  // Initialize provider and model selection with localStorage persistence
  useEffect(() => {
    const enabledProviders = getEnabledProviders();
    if (enabledProviders.length === 0) return;

    // Fix all arrow function parameters and .filter/.map/.flatMap types
    // Provider/model selection
    const savedProviderId = localStorage.getItem('chat-selected-provider');
    const savedModelId = localStorage.getItem('chat-selected-model');

    let targetProvider: LLMProvider | undefined = undefined;
    let targetModelId = '';

    if (savedProviderId) {
      targetProvider = enabledProviders.find((p: LLMProvider) => p.id === savedProviderId);
      if (targetProvider && savedModelId) {
        const hasModel = targetProvider.models.find((m: LLMModel) => m.id === savedModelId);
        if (hasModel) {
          targetModelId = savedModelId;
        }
      }
    }

    // Fallback to default selection if no valid saved selection
    if (!targetProvider) {
      targetProvider = enabledProviders[0];
      const enabledModel = targetProvider.models.find((m: LLMModel) => m.enabled);
      const defaultModel = enabledModel || targetProvider.models[0];
      if (defaultModel) {
        targetModelId = defaultModel.id;
      }
    }

    if (targetProvider && !selectedProvider) {
      setSelectedProvider(targetProvider);
      if (!savedProviderId) {
        localStorage.setItem('chat-selected-provider', targetProvider.id);
      }
      if (targetModelId) {
        setSelectedModel(targetModelId);
        if (!savedModelId) {
          localStorage.setItem('chat-selected-model', targetModelId);
        }
      }
    }
  }, [providers, selectedProvider, getEnabledProviders]);

  // Reset model selection when provider changes (only if model doesn't belong to new provider)
  useEffect(() => {
    if (selectedProvider && selectedModel) {
      const hasModel = selectedProvider.models.find((m: LLMModel) => m.id === selectedModel);
      if (!hasModel) {
        const enabledModel = selectedProvider.models.find((m: LLMModel) => m.enabled);
        const defaultModel = enabledModel || selectedProvider.models[0];
        if (defaultModel) {
          setSelectedModel(defaultModel.id);
          localStorage.setItem('chat-selected-model', defaultModel.id);
        } else {
          setSelectedModel('');
          localStorage.removeItem('chat-selected-model');
        }
      }
    }
  }, [selectedProvider, selectedModel]);

  useEffect(() => {
    const fetchMCPServers = async () => {
      try {
        const servers = await getMCPServers();
        setMcpServers(servers);
      } catch {
        toast.error(t('errors.fetch_mcp_servers'));
      }
    };
    fetchMCPServers();
  }, [t]);

  useEffect(() => {
    const loadToolsForActiveServers = async () => {
      for (const serverName of activeServices) {
        const server = mcpServers.find((s: Gateway) => s.name === serverName);
        if (!server) continue;

        for (const router of server.routers || []) {
          try {
            // Pass authToken as the second argument to connect
            await mcpService.connect({
              name: serverName,
              prefix: router.prefix,
              onError: (error) => {
                toast.error(t('errors.mcp_server_error', { server: serverName, error: error.message }));
              },
              onNotification: (notification) => {
                toast.success(t('chat.notification_received', { server: serverName, message: notification }));
              }
            }, authToken); // <-- pass token here

            const toolsList = await mcpService.getTools(serverName);
            setTools((prev: Record<string, Tool[]>) => ({
              ...prev,
              [serverName]: toolsList
            }));
          } catch (error) {
            toast.error(t('errors.fetch_tools', { error }));
          }
        }
      }
    };

    if (activeServices.length > 0) {
      loadToolsForActiveServers();
    }
  }, [activeServices, mcpServers, t, authToken]);

  const loadMessages = useCallback(async (sessionId: string) => {
    try {
      const data = await getChatMessages(sessionId);

      if (!data || data.length === 0) {
        const welcomeMessage: Message = {
          id: uuidv4(),
          session_id: sessionId,
          content: t('chat.welcome_message'),
          sender: 'bot',
          timestamp: new Date().toISOString(),
        };
        setMessages([welcomeMessage]);
        return;
      }

      const convertedMessages = data.map((msg: {
        id: string;
        content: string;
        sender: 'user' | 'bot';
        timestamp: string;
        reasoning_content?: string;
        toolCalls?: string;
        toolResult?: string;
      }) => ({
        id: msg.id,
        session_id: sessionId,
        content: msg.content,
        sender: msg.sender as 'user' | 'bot',
        timestamp: msg.timestamp,
        reasoning_content: msg.reasoning_content,
        toolCalls: msg.toolCalls ? JSON.parse(msg.toolCalls) : undefined,
        toolResult: msg.toolResult ? JSON.parse(msg.toolResult) : undefined,
      }));

      setMessages(convertedMessages);
      setSelectedChat(sessionId);
    } catch (error) {
      toast.error(t('errors.load_messages', { error: error instanceof Error ? error.message : 'Unknown error' }));
      setMessages([]);
    }
  }, [t]);

  useEffect(() => {
    if (sessionId) {
      loadMessages(sessionId);
    }
  }, [sessionId, loadMessages]);

  // Handle tool call results and continue LLM conversation
  const handleToolCallResult = async (toolCall: ToolCall, result: string) => {
    if (!sessionId) return;

    try {
      const toolResultMessage: Message = {
        id: uuidv4(),
        session_id: sessionId,
        content: '',
        sender: 'user',
        timestamp: new Date().toISOString(),
        toolResult: {
          toolCallId: toolCall.id,
          name: toolCall.function.name,
          result: result
        }
      };

      setMessages((prev: Message[]) => [...prev, toolResultMessage]);

      try {
        await saveChatMessage(toolResultMessage);
      } catch (error) {
        console.warn('Failed to save tool result message:', error);
      }

      if (!selectedProvider || !selectedModel) return;

      const updatedMessages = [...messages, toolResultMessage];

      // For availableTools in handleToolCallResult (tool name only)
      const availableTools = (Object.entries(tools) as [string, Tool[]][])
        .filter(([serverName]) => activeServices.includes(serverName))
        .flatMap(([serverName, serverTools]) =>
          serverTools.map((tool) => ({
            name: sanitizeToolName(`${serverName}:${tool.name}`),
            description: tool.description || tool.name,
            parameters: tool.inputSchema,
            originalName: `${serverName}:${tool.name}` // Optionally keep original for mapping
          }))
        );
      // Build sanitized->original map
      const sanitizedNameMap = getSanitizedToolNameMap(tools, activeServices);

      const assistantMessage: Message = {
        id: uuidv4(),
        session_id: sessionId,
        content: '',
        sender: 'bot',
        timestamp: new Date().toISOString(),
        isStreaming: true
      };

      setMessages((prev: Message[]) => [...prev, assistantMessage]);
      setIsGenerating(true);

      await llmChatService.sendMessage(
        selectedProvider,
        updatedMessages,
        selectedModel,
        availableTools,
        (chunk: string) => {
          setMessages((prev: Message[]) => {
            const updated = [...prev];
            const lastMessage = updated[updated.length - 1];
            if (lastMessage && lastMessage.sender === 'bot') {
              lastMessage.content += chunk;
              lastMessage.isStreaming = true;
            }
            return updated;
          });
        },
        (reasoningChunk: string) => {
          setMessages((prev: Message[]) => {
            const updated = [...prev];
            const lastMessage = updated[updated.length - 1];
            if (lastMessage && lastMessage.sender === 'bot') {
              lastMessage.reasoning_content = (lastMessage.reasoning_content || '') + reasoningChunk;
              lastMessage.isStreaming = true;
            }
            return updated;
          });
        },
        async (newToolCalls) => {
          // Patch tool calls to always have originalName
          const patchedToolCalls = newToolCalls.map((tc: ToolCall) => ({
            ...tc,
            function: {
              ...tc.function,
              originalName: sanitizedNameMap[tc.function.name] || tc.function.name
            }
          }));
          setMessages((prev: Message[]) => {
            const updated = [...prev];
            const lastMessage = updated[updated.length - 1];
            if (lastMessage && lastMessage.sender === 'bot') {
              lastMessage.toolCalls = patchedToolCalls;
              lastMessage.isStreaming = false;
              if (!lastMessage.content.trim() && lastMessage.toolCalls.length > 0) {
                lastMessage.content = '';
              }
            }
            return updated;
          });
        },
        async (finalMessage: string) => {
          const messageToBeSaved = {
            id: assistantMessage.id,
            session_id: sessionId,
            content: finalMessage,
            sender: 'bot' as const,
            timestamp: assistantMessage.timestamp,
            reasoning_content: undefined as string | undefined,
            toolCalls: undefined as ToolCall[] | undefined,
            toolResult: undefined as ToolResult | undefined
          };

          setMessages((prev: Message[]) => {
            const updated = [...prev];
            const lastMessage = updated[updated.length - 1];
            if (lastMessage && lastMessage.sender === 'bot') {
              lastMessage.content = finalMessage;
              lastMessage.isStreaming = false;

              messageToBeSaved.reasoning_content = lastMessage.reasoning_content || undefined;
              messageToBeSaved.toolCalls = lastMessage.toolCalls || undefined;
              messageToBeSaved.toolResult = lastMessage.toolResult || undefined;
            }
            return updated;
          });

          try {
            await saveChatMessage(messageToBeSaved);
          } catch (error) {
            console.warn('Failed to save assistant message:', error);
          }

          setIsGenerating(false);
        },
        (error: Error) => {
          toast.error(t('errors.llm_request_failed', { error: error.message }));
          setIsGenerating(false);
          setMessages((prev: Message[]) => prev.filter((msg: Message) => !(msg.sender === 'bot' && !msg.content && !msg.toolCalls)));
        }
      );

    } catch (error) {
      toast.error(t('errors.tool_call_failed', { error: error instanceof Error ? error.message : 'Unknown error' }));
    }
  };

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // Helper to build LLM messages array with system prompt
  const buildLLMMessages = (userMessages: Message[]) => {
    if (!systemPrompt) return userMessages;
    // System prompt as a special message (not shown in chat)
    const sysMsg: Message = {
      id: 'system-prompt',
      session_id: sessionId!,
      content: systemPrompt,
      sender: 'system' as const,
      timestamp: new Date().toISOString(),
    };
    return [sysMsg, ...userMessages];
  };

  const handleSend = async () => {
    if (!input.trim() || !selectedProvider || !selectedModel || isGenerating) return;
    if (!sessionId) return;
    const currentSessionId = sessionId;
    const userMessage: Message = {
      id: uuidv4(),
      session_id: currentSessionId,
      content: input,
      sender: 'user',
      timestamp: new Date().toISOString(),
    };
    setMessages((prev: Message[]) => [...prev, userMessage]);
    setInput('');
    setIsGenerating(true);
    try {
      await saveChatMessage(userMessage);
    } catch (error) {
      console.warn('Failed to save user message:', error);
    }
    // For availableTools in handleSend (serverName:toolName)
    const availableTools = (Object.entries(tools) as [string, Tool[]][])
      .filter(([serverName]) => activeServices.includes(serverName))
      .flatMap(([serverName, serverTools]) =>
        serverTools.map((tool) => ({
          name: sanitizeToolName(`${serverName}:${tool.name}`),
          description: tool.description || tool.name,
          parameters: tool.inputSchema,
          originalName: `${serverName}:${tool.name}` // Optionally keep original for mapping
        }))
      );
    // Build sanitized->original map
    const sanitizedNameMap = getSanitizedToolNameMap(tools, activeServices);
    const assistantMessage: Message = {
      id: uuidv4(),
      session_id: currentSessionId,
      content: '',
      sender: 'bot',
      timestamp: new Date().toISOString(),
      isStreaming: true
    };
    setMessages((prev: Message[]) => [...prev, assistantMessage]);
    try {
      await llmChatService.sendMessage(
        selectedProvider,
        buildLLMMessages([...messages, userMessage]),
        selectedModel,
        availableTools,
        (chunk: string) => {
          setMessages((prev: Message[]) => {
            const updated = [...prev];
            const lastMessage = updated[updated.length - 1];
            if (lastMessage && lastMessage.sender === 'bot') {
              lastMessage.content += chunk;
              lastMessage.isStreaming = true;
            }
            return updated;
          });
        },
        (reasoningChunk: string) => {
          setMessages((prev: Message[]) => {
            const updated = [...prev];
            const lastMessage = updated[updated.length - 1];
            if (lastMessage && lastMessage.sender === 'bot') {
              lastMessage.reasoning_content = (lastMessage.reasoning_content || '') + reasoningChunk;
              lastMessage.isStreaming = true;
            }
            return updated;
          });
        },
        async (toolCalls: Array<{
          id: string;
          type: string;
          function: {
            name: string;
            arguments: string;
          };
        }>) => {
          if (!toolCalls || toolCalls.length === 0) return;
          // Patch tool calls to always have originalName
          const patchedToolCalls = toolCalls.map(tc => ({
            ...tc,
            function: {
              ...tc.function,
              originalName: sanitizedNameMap[tc.function.name] || tc.function.name
            }
          }));
          setMessages((prev: Message[]) => {
            const updated = [...prev];
            const lastMessage = updated[updated.length - 1];
            if (lastMessage && lastMessage.sender === 'bot') {
              lastMessage.toolCalls = patchedToolCalls;
              lastMessage.isStreaming = false;
              // Set empty content for messages with tool calls, let UI handle display
              if (!lastMessage.content.trim() && lastMessage.toolCalls.length > 0) {
                lastMessage.content = '';
              }
            }
            return updated;
          });
          // Note: Don't save message here, wait for onComplete to save uniformly
        },
        async (message: string) => {
          let finalMessageData: Message | null = null;
          setMessages((prev: Message[]) => {
            const updated = [...prev];
            const lastMessage = updated[updated.length - 1];
            if (lastMessage && lastMessage.sender === 'bot') {
              lastMessage.content = message;
              lastMessage.isStreaming = false;

              finalMessageData = {
                id: assistantMessage.id,
                session_id: currentSessionId,
                content: message,
                sender: 'bot' as const,
                timestamp: assistantMessage.timestamp,
                reasoning_content: lastMessage.reasoning_content || undefined,
                toolCalls: lastMessage.toolCalls || undefined,
                toolResult: lastMessage.toolResult || undefined
              };
            }
            return updated;
          });

          // Use setTimeout to ensure state update completes before saving
          setTimeout(async () => {
            if (finalMessageData) {
              try {
                await saveChatMessage(finalMessageData);
              } catch (error) {
                console.warn('Failed to save assistant message:', error);
              }
            }
          }, 0);

          setIsGenerating(false);
        },
        (error: Error) => {
          toast.error(t('errors.llm_request_failed', { error: error.message }));
          setIsGenerating(false);

          setMessages((prev: Message[]) => prev.filter((msg: Message) => !(msg.sender === 'bot' && !msg.content && !msg.toolCalls)));
        }
      );
    } catch {
      toast.error(t('errors.llm_request_failed', { error: 'Unknown error' }));
      setIsGenerating(false);
      setMessages((prev: Message[]) => prev.filter((msg: Message) => !(msg.sender === 'bot' && !msg.content && !msg.toolCalls)));
    }
  };

  const handleStop = () => {
    llmChatService.cancelCurrentRequest();
    setIsGenerating(false);
    setMessages((prev: Message[]) => {
      const updated = [...prev];
      const lastMessage = updated[updated.length - 1];
      if (lastMessage && lastMessage.sender === 'bot' && lastMessage.isStreaming) {
        lastMessage.isStreaming = false;
      }
      return updated;
    });
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  useEffect(() => {
    const fetchUserInfo = async () => {
      try {
        const response = await getCurrentUser();
        setUserInfo(response.data);
      } catch {
        // Optionally handle error
      }
    };
    fetchUserInfo();
  }, []);

  const llmConfigAdminOnly = window.RUNTIME_CONFIG?.LLM_CONFIG_ADMIN_ONLY;
  const canShowLLM =
    llmConfigAdminOnly === false ||
    (llmConfigAdminOnly === true && userInfo?.role === 'admin');

  // Load system prompt on mount (user-level, not session-level)
  useEffect(() => {
    (async () => {
      try {
        const prompt = await getSystemPrompt();
        setSystemPrompt(prompt);
      } catch {
        setSystemPrompt('');
      }
    })();
  }, []);

  // Utility to sanitize tool names for VertexAI/Gemini
  function sanitizeToolName(name: string): string {
    // Only allow [a-zA-Z0-9_], must start with a letter or underscore
    let sanitized = name.replace(/[^a-zA-Z0-9_]/g, '_');
    if (!/^[a-zA-Z_]/.test(sanitized)) {
      sanitized = '_' + sanitized;
    }
    return sanitized;
  }

  // Build a mapping from sanitized tool names to original names
  function getSanitizedToolNameMap(tools: Record<string, Tool[]>, activeServices: string[]): Record<string, string> {
    const map: Record<string, string> = {};
    (Object.entries(tools) as [string, Tool[]][]) // serverName, Tool[]
      .filter(([serverName]) => activeServices.includes(serverName))
      .forEach(([serverName, serverTools]) => {
        serverTools.forEach((tool) => {
          const original = `${serverName}:${tool.name}`;
          const sanitized = sanitizeToolName(original);
          map[sanitized] = original;
        });
      });
    return map;
  }

  return (
    <div className="flex h-[calc(100vh-8rem)]">
      <ChatHistory
        selectedChat={selectedChat}
        onSelectChat={(id) => {
          setSelectedChat(id);
          navigate(`/chat/${id}`);
        }}
        isCollapsed={isHistoryCollapsed}
      />

      <div className={`flex-1 ${isHistoryCollapsed ? 'ml-2' : 'ml-4'}`}>
        <Card className="h-full bg-card">
          <CardBody className="p-0 h-full flex flex-col">
            <div className="flex items-center justify-between p-4 border-b border-border">
              <div className="flex items-center gap-3">
                <Button
                  size="sm"
                  variant="light"
                  isIconOnly
                  onPress={() => setIsHistoryCollapsed(!isHistoryCollapsed)}
                >
                  <LocalIcon icon="lucide:chevron-left" />
                </Button>

                <Select
                  label={t('llm.provider')}
                  placeholder={t('llm.selectProvider')}
                  selectedKeys={selectedProvider ? [selectedProvider.id] : []}
                  onSelectionChange={(keys) => {
                    const providerId = Array.from(keys)[0] as string;
                    const provider = enabledProviders.find(p => p.id === providerId);
                    setSelectedProvider(provider || null);
                    if (provider) {
                      localStorage.setItem('chat-selected-provider', provider.id);
                    } else {
                      localStorage.removeItem('chat-selected-provider');
                    }
                  }}
                  className="w-40"
                  size="sm"
                >
                  {enabledProviders.map((provider: LLMProvider) => (
                    <SelectItem key={provider.id} textValue={provider.name}>
                      {provider.name}
                    </SelectItem>
                  ))}
                </Select>

                {selectedProvider && (
                  <Select
                    label={t('llm.model')}
                    placeholder={t('llm.selectModel')}
                    selectedKeys={selectedModel ? [selectedModel] : []}
                    onSelectionChange={(keys) => {
                      const modelId = Array.from(keys)[0] as string;
                      setSelectedModel(modelId);
                      if (modelId) {
                        localStorage.setItem('chat-selected-model', modelId);
                      } else {
                        localStorage.removeItem('chat-selected-model');
                      }
                    }}
                    className="w-48"
                    size="sm"
                    isDisabled={!selectedProvider.models.length}
                  >
                    {selectedProvider.models
                      .filter((model: LLMModel) => model.enabled || model.id === selectedModel)
                      .map((model: LLMModel) => (
                        <SelectItem key={model.id} textValue={model.name || model.id}>
                          <div className="flex items-center justify-between w-full">
                            <span className="truncate">{model.name || model.id}</span>
                            {model.capabilities?.vision && (
                              <Chip size="sm" color="warning" variant="dot" className="ml-2">
                                Vision
                              </Chip>
                            )}
                          </div>
                        </SelectItem>
                      ))}
                  </Select>
                )}

                {/* System prompt only here, reduced width */}
                <div className="flex items-center gap-2 ml-4 max-w-xs" style={{ minWidth: 0 }}>
                  <label className="block text-xs font-medium mb-0" htmlFor="system-prompt-input">
                    {t('chat.systemPrompt')}
                  </label>
                  <button
                    type="button"
                    className="truncate bg-transparent border-none p-0 m-0 text-sm text-muted-foreground hover:underline max-w-[100px]"
                    onClick={() => {
                      setSystemPromptDraft(systemPrompt);
                      setIsSystemPromptModalOpen(true);
                    }}
                    title={systemPrompt}
                    style={{ cursor: 'pointer' }}
                    disabled={isGenerating}
                  >
                    {systemPrompt ? systemPrompt : t('chat.systemPromptPlaceholder')}
                  </button>
                  <Button
                    size="sm"
                    variant="flat"
                    onPress={() => {
                      setSystemPromptDraft(systemPrompt);
                      setIsSystemPromptModalOpen(true);
                    }}
                    isIconOnly
                    disabled={isGenerating}
                    aria-label={t('chat.editSystemPrompt')}
                    className="mr-2"
                  >
                    <LocalIcon icon="lucide:pencil" className="w-4 h-4 text-muted-foreground" />
                  </Button>
                </div>
              </div>

              <div className="flex items-center gap-2">
                {/* Authorization token textbox moved here, left of MCP Server dropdown */}
                <Input
                  id="auth-token-input"
                  className="w-64 mr-2"
                  size="sm"
                  type="text"
                  value={authToken}
                  onChange={e => setAuthToken(e.target.value)}
                  placeholder={t('chat.authTokenPlaceholder') || 'Auth Token'}
                  disabled={isGenerating}
                  aria-label={t('chat.authToken') || 'Authorization Token'}
                />
                <Select
                  label={t('chat.mcpServers')}
                  placeholder={t('chat.selectMCPServers')}
                  selectionMode="multiple"
                  selectedKeys={activeServices}
                  onSelectionChange={(keys: Selection) => setActiveServices(Array.from(keys) as string[])}
                  className="w-48"
                  size="sm"
                >
                  {mcpServers.map((server: Gateway) => (
                    <SelectItem key={server.name} textValue={server.name}>
                      {server.name}
                    </SelectItem>
                  ))}
                </Select>

                {canShowLLM && (
                  <Tooltip content={t('llm.openSettings')}>
                    <Button
                      size="sm"
                      variant="light"
                      isIconOnly
                      onPress={() => navigate('/llm')}
                    >
                      <Settings className="w-4 h-4" />
                    </Button>
                  </Tooltip>
                )}
              </div>
            </div>

            {/* System Prompt Modal */}
            {isSystemPromptModalOpen && (
              <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
                <div className="bg-background rounded-lg shadow-lg w-full max-w-lg p-6 relative">
                  <button
                    className="absolute top-2 right-2 text-muted-foreground hover:text-foreground"
                    onClick={() => setIsSystemPromptModalOpen(false)}
                    aria-label={t('common.close')}
                  >
                    <X className="w-5 h-5" />
                  </button>
                  <h2 className="text-lg font-semibold mb-2">{t('chat.systemPrompt')}</h2>
                  <textarea
                    id="system-prompt-modal-input"
                    className="w-full border rounded p-2 text-sm mb-4 bg-background/50"
                    rows={8}
                    value={systemPromptDraft}
                    onChange={e => setSystemPromptDraft(e.target.value)}
                    placeholder={t('chat.systemPromptPlaceholder')}
                    disabled={isGenerating}
                    style={{ resize: 'vertical' }}
                  />
                  <div className="flex justify-end gap-2">
                    <Button
                      variant="flat"
                      onPress={() => setIsSystemPromptModalOpen(false)}
                      disabled={isGenerating}
                    >
                      {t('common.cancel')}
                    </Button>
                    <Button
                      color="primary"
                      onPress={async () => {
                        setSystemPrompt(systemPromptDraft);
                        setIsSystemPromptModalOpen(false);
                        try {
                          await saveSystemPrompt(systemPromptDraft);
                        } catch {
                          // Ignore save errors
                        }
                      }}
                      disabled={isGenerating}
                    >
                      {t('common.save')}
                    </Button>
                  </div>
                </div>
              </div>
            )}

            {/* Experimental warning */}
            <div className="px-4 py-3 bg-warning-50 border-b border-warning-200">
              <div className="flex items-start gap-2 text-sm text-warning-700">
                <LocalIcon icon="lucide:alert-triangle" className="w-4 h-4 mt-0.5 flex-shrink-0" />
                <div>
                  <p className="font-medium">{t('chat.experimentalWarning.title')}</p>
                  <p className="text-xs mt-1">
                    {t('chat.experimentalWarning.description')}
                    <a 
                      href="https://github.com/amoylab/unla/issues" 
                      target="_blank" 
                      rel="noopener noreferrer"
                      className="underline ml-1 hover:text-warning-800"
                    >
                      {t('chat.experimentalWarning.reportIssue')}
                    </a>
                    {t('chat.experimentalWarning.or')}
                    <a 
                      href="https://github.com/amoylab/unla/pulls" 
                      target="_blank" 
                      rel="noopener noreferrer"
                      className="underline ml-1 hover:text-warning-800"
                    >
                      {t('chat.experimentalWarning.submitPR')}
                    </a>
                    {t('chat.experimentalWarning.helpImprove')}
                  </p>
                </div>
              </div>
            </div>

            <div
              ref={messagesContainerRef}
              className="flex-1 overflow-auto p-4 space-y-4"
            >
              {messages.map((message) => (
                <ChatMessage
                  key={message.id}
                  message={message}
                  messages={messages}
                  onToolCall={handleToolCallResult}
                />
              ))}

              {isGenerating && (
                <div className="flex items-center gap-2 text-muted-foreground">
                  <div className="w-2 h-2 bg-current rounded-full animate-pulse" />
                  <span>{t('chat.generating')}</span>
                </div>
              )}

              <div ref={messagesEndRef} />
            </div>

            <div className="p-4 border-t border-border">
              {activeServices.length > 0 && (
                <div className="mb-3">
                  <div className="border border-border rounded-lg bg-background/50">
                    <div className="flex items-center justify-between p-3 border-b border-border">
                      <div className="flex items-center gap-2">
                        <LocalIcon icon="lucide:wrench" className="w-4 h-4 text-muted-foreground" />
                        <span className="text-sm font-medium">{t('chat.available_tools')}</span>
                        <span className="text-xs text-muted-foreground">
                          ({Object.entries(tools)
                            .filter(([serverName]) => activeServices.includes(serverName))
                            .reduce((total, [, serverTools]) => total + serverTools.length, 0)})
                        </span>
                      </div>
                      <Button
                        size="sm"
                        variant="light"
                        isIconOnly
                        onPress={() => setIsToolsExpanded(!isToolsExpanded)}
                      >
                        {isToolsExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                      </Button>
                    </div>

                    {isToolsExpanded ? (
                      <div className="p-3 space-y-3">
                        {Object.entries(tools)
                          .filter(([serverName]) => activeServices.includes(serverName))
                          .map(([serverName, serverTools]) => (
                            <div key={serverName} className="space-y-2">
                              <div className="flex items-center gap-2">
                                <LocalIcon icon="lucide:server" className="w-3 h-3 text-blue-600" />
                                <span className="text-xs font-medium text-blue-600">{serverName}</span>
                              </div>
                              <div className="grid gap-2">
                                {serverTools.map(tool => (
                                  <div key={tool.name} className="p-2 border border-border rounded-md bg-secondary/30">
                                    <div className="flex items-start justify-between gap-2">
                                      <div className="flex-1 min-w-0">
                                        <div className="flex items-center gap-2">
                                          <span className="text-sm font-medium">{tool.name}</span>
                                        </div>
                                        {tool.description && (
                                          <p className="text-xs text-muted-foreground mt-1 line-clamp-2">
                                            {tool.description}
                                          </p>
                                        )}
                                        {tool.inputSchema?.properties && (
                                          <div className="mt-2">
                                            <span className="text-xs text-muted-foreground">
                                              {t('chat.arguments')}: {Object.keys(tool.inputSchema.properties).join(', ')}
                                            </span>
                                          </div>
                                        )}
                                      </div>
                                    </div>
                                  </div>
                                ))}
                              </div>
                            </div>
                          ))}
                      </div>
                    ) : (
                      <div className="p-3">
                        <div className="flex flex-wrap gap-1">
                          {Object.entries(tools)
                            .filter(([serverName]) => activeServices.includes(serverName))
                            .flatMap(([serverName, serverTools]) =>
                              serverTools.map(tool => (
                                <Chip
                                  key={`${serverName}:${tool.name}`}
                                  size="sm"
                                  color="secondary"
                                  variant="flat"
                                  startContent={<Zap className="w-3 h-3" />}
                                >
                                  {tool.name}
                                </Chip>
                              ))
                            )}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )}

              <div className="flex gap-2">
                <Input
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  onKeyDown={handleKeyPress}
                  placeholder={
                    selectedProvider && selectedModel
                      ? t('chat.typeMessage')
                      : t('llm.selectProviderAndModel')
                  }
                  disabled={!selectedProvider || !selectedModel || isGenerating}
                  className="flex-1"
                />

                {isGenerating ? (
                  <Button
                    color="danger"
                    variant="flat"
                    onPress={handleStop}
                    startContent={<Square className="w-4 h-4" />}
                  >
                    {t('chat.stop')}
                  </Button>
                ) : (
                  <Button
                    color="primary"
                    onPress={handleSend}
                    isDisabled={!input.trim() || !selectedProvider || !selectedModel}
                    startContent={<Send className="w-4 h-4" />}
                  >
                    {t('chat.send')}
                  </Button>
                )}
              </div>
            </div>
          </CardBody>
        </Card>
      </div>

    </div>
  );
}
