import {
  Card,
  CardBody,
  Button,
  Chip,
  Divider,
  Switch,
  Input,
  Modal,
  ModalContent,
  ModalHeader,
  ModalBody,
  ModalFooter,
  useDisclosure,
  Spinner,
  Tooltip
} from '@heroui/react';
import { 
  Plus, 
  RefreshCw, 
  Save, 
  Eye, 
  EyeOff,
  CheckCircle,
  XCircle,
  Trash2,
  Search
} from 'lucide-react';
import React, { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';

import AddProviderModal from './components/AddProviderModal';

import ProviderIcon from '@/components/ProviderIcon';
import { findModel } from '@/config/ai-models';
import { BUILTIN_PROVIDERS, getProviderDefaultConfig, getDefaultBaseURL, buildEndpointURL, getProviderDescription as getI18nProviderDescription, getModelDescription as getI18nModelDescription } from '@/config/llm-providers-adapter';
import { useLLMConfig } from '@/hooks/useLLMConfig';
import { LLMProvider, LLMModel, FetchedModel } from '@/types/llm';
import { toast } from '@/utils/toast';


const LLMSettings: React.FC = () => {
  const { t } = useTranslation();
  const {
    providers,
    loading,
    updateProvider,
    testProvider,
    addProvider
  } = useLLMConfig();

  // 左侧选中的提供商
  const [selectedProviderId, setSelectedProviderId] = useState<string | null>(null);
  const [selectedProvider, setSelectedProvider] = useState<LLMProvider | null>(null);

  // 右侧配置状态
  const [config, setConfig] = useState<Record<string, unknown>>({});
  const [models, setModels] = useState<LLMModel[]>([]);
  const [showApiKey, setShowApiKey] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ success: boolean; error?: string } | null>(null);

  // 模型获取状态
  const [fetchingModels, setFetchingModels] = useState(false);

  // 自定义模型弹窗
  const { isOpen: isAddModelOpen, onOpen: onAddModelOpen, onClose: onAddModelClose } = useDisclosure();
  const [customModel, setCustomModel] = useState({
    id: '',
    name: '',
    description: '',
    contextWindow: 4096,
    maxTokens: 2048
  });

  // 搜索相关
  const [searchQuery, setSearchQuery] = useState('');
  const [modelSearchQuery, setModelSearchQuery] = useState('');
  // 搜索过滤后的 provider，启用的在前
  const filteredProviders = providers
    .filter((provider: LLMProvider) => {
      // Exclude the default provider from the list
      if (provider.id === 'custom_default') return false;
      
      // Then apply search filter
      if (!searchQuery.trim()) return true;
      const query = searchQuery.toLowerCase();
      return (
        provider.name.toLowerCase().includes(query) ||
        (provider.description && provider.description.toLowerCase().includes(query))
      );
    })
    .sort((a: LLMProvider, b: LLMProvider) => {
      // 启用的排在前面
      if (a.enabled && !b.enabled) return -1;
      if (!a.enabled && b.enabled) return 1;
      return 0;
    });

  // 添加 Provider 弹窗
  const { isOpen: isAddModalOpen, onOpen: onAddModalOpen, onClose: onAddModalClose } = useDisclosure();

  // 初始化选中第一个提供商
  useEffect(() => {
    if (providers.length > 0 && !selectedProviderId) {
      const firstProvider = providers[0];
      setSelectedProviderId(firstProvider.id);
      setSelectedProvider(firstProvider);
      
      // 合并provider配置和默认配置
      const defaultConfig = getProviderDefaultConfig(firstProvider.id);
      const mergedConfig = {
        ...defaultConfig,
        ...firstProvider.config
      };
      setConfig(mergedConfig);
      setModels(firstProvider.models);
    }
  }, [providers, selectedProviderId]);

  // 切换提供商
  const handleProviderSelect = (providerId: string) => {
    const provider = providers.find(p => p.id === providerId);
    if (provider) {
      setSelectedProviderId(providerId);
      setSelectedProvider(provider);
      
      // 合并provider配置和默认配置
      const defaultConfig = getProviderDefaultConfig(providerId);
      const mergedConfig = {
        ...defaultConfig,
        ...provider.config
      };
      setConfig(mergedConfig);
      setModels(provider.models);
      setTestResult(null);
    }
  };

  // 保存配置
  const handleSave = async () => {
    if (!selectedProvider) return;

    try {
      await updateProvider(selectedProvider.id, {
        config,
        models
      });
      toast.success(t('llm.updateSuccess'));
    } catch {
      toast.error(t('llm.updateFailed'));
    }
  };

  // 测试连接
  const handleTest = async () => {
    if (!selectedProvider) return;

    setTesting(true);
    setTestResult(null);

    try {
      const result = await testProvider(selectedProvider.id);
      setTestResult(result);

      if (result.success) {
        toast.success(t('llm.testSuccess'));
      } else {
        toast.error(t('llm.testFailed', { error: result.error }));
      }
    } catch {
      const result = { 
        success: false, 
        error: 'Unknown error'
      };
      setTestResult(result);
      toast.error(t('llm.testError', { error: result.error }));
    } finally {
      setTesting(false);
    }
  };

  // 获取模型列表
  const handleFetchModels = async () => {
    if (!selectedProvider) {
      return;
    }
    
    // Ollama 不需要 API 密钥，其他提供商需要
    if (selectedProvider.id !== 'ollama' && !config.apiKey) {
      toast.error(t('llm.apiKeyRequired'));
      return;
    }

    setFetchingModels(true);

    try {
      const fetchedModels = await fetchModelsFromProvider(selectedProvider, config);
      
      // 合并现有模型和新获取的模型
      const existingModelIds = models.map(m => m.id);
      const uniqueNewModels = fetchedModels.filter(m => !existingModelIds.includes(m.id));
      
      setModels(prev => [...prev, ...uniqueNewModels]);
      toast.success(t('llm.fetchModelsSuccess', { count: uniqueNewModels.length }));
    } catch {
      toast.error(t('llm.fetchModelsFailed', { error: 'Unknown error' }));
    } finally {
      setFetchingModels(false);
    }
  };

  // 从提供商获取模型列表 - 类似lobe-chat的实现
  const fetchModelsFromProvider = async (provider: LLMProvider, config: Record<string, unknown>): Promise<LLMModel[]> => {
    const headers = buildAuthHeaders(provider, config);
    const endpoint = getModelsEndpoint(provider, config);
    
    // 添加超时和重试机制
    const response = await fetchWithTimeout(endpoint, { headers }, 10000);

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const data = await response.json();
    return normalizeModels(data, provider.id);
  };

  // 构建认证头 - 支持更多提供商
  const buildAuthHeaders = (provider: LLMProvider, config: Record<string, unknown>): Record<string, string> => {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json'
    };

    switch (provider.id) {
      case 'openai':
        headers['Authorization'] = `Bearer ${String(config.apiKey)}`;
        if (config.organization) {
          headers['OpenAI-Organization'] = String(config.organization);
        }
        break;
      case 'anthropic':
        headers['x-api-key'] = String(config.apiKey);
        headers['anthropic-version'] = '2023-06-01';
        break;
      case 'deepseek':
        headers['Authorization'] = `Bearer ${String(config.apiKey)}`;
        break;
      case 'ollama':
        // Ollama 通常不需要认证
        break;
      default:
        // 默认使用 Bearer token
        headers['Authorization'] = `Bearer ${String(config.apiKey)}`;
    }

    return headers;
  };

  // 获取模型端点
  const getModelsEndpoint = (provider: LLMProvider, config: Record<string, unknown>): string => {
    const baseURL = (config.baseURL as string) || getDefaultBaseURL(provider.id);
    
    switch (provider.id) {
      case 'ollama':
        return buildEndpointURL(baseURL, '/api/tags');
      default:
        return buildEndpointURL(baseURL, '/v1/models');
    }
  };

  // 规范化模型数据 - 根据不同提供商处理不同的响应格式
  const normalizeModels = (data: Record<string, unknown>, providerId: string): LLMModel[] => {
    let rawModels: unknown[] = [];

    switch (providerId) {
      case 'ollama':
        rawModels = (data.models as unknown[]) || [];
        return rawModels.map((model: unknown) => {
          const ollamaModel = model as { 
            name: string; 
            details?: { family?: string }; 
          };
          return {
            id: ollamaModel.name,
            name: ollamaModel.name,
            description: ollamaModel.details?.family || `Ollama ${ollamaModel.name}`,
            contextWindow: getContextWindowForModel(ollamaModel.name, providerId),
            maxTokens: 2048,
            pricing: { input: 0, output: 0, unit: 'per_1k_tokens' as const },
            capabilities: getCapabilitiesForModel(ollamaModel.name, providerId),
            enabled: false,
            ownedBy: 'ollama'
          };
        });
      default:
        rawModels = (data.data as unknown[]) || [];
        return rawModels.map((model: unknown) => {
          const fetchedModel = model as FetchedModel;
          return {
            id: fetchedModel.id,
            name: fetchedModel.id,
            description: getModelDescription(fetchedModel.id, providerId),
            contextWindow: getContextWindowForModel(fetchedModel.id, providerId),
            maxTokens: getMaxTokensForModel(fetchedModel.id, providerId),
            pricing: getPricingForModel(fetchedModel.id, providerId),
            capabilities: getCapabilitiesForModel(fetchedModel.id, providerId),
            enabled: false,
            ownedBy: fetchedModel.owned_by || providerId
          };
        });
    }
  };

  // 带超时的fetch
  const fetchWithTimeout = async (url: string, options: RequestInit, timeout: number): Promise<Response> => {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    try {
      const response = await fetch(url, {
        ...options,
        signal: controller.signal
      });
      clearTimeout(timeoutId);
      return response;
    } catch {
      throw new Error('Request timed out');
    }
  };

  // 获取模型描述 - 使用 lobe-chat 的模型信息
  const getModelDescription = (modelId: string, providerId: string): string => {
    const aiModel = findModel(modelId, providerId);
    return aiModel?.description || `${providerId} ${modelId}`;
  };

  // 获取最大输出token数 - 使用 lobe-chat 的模型信息
  const getMaxTokensForModel = (modelId: string, providerId: string): number => {
    const aiModel = findModel(modelId, providerId);
    return (aiModel as unknown as { maxOutput?: number })?.maxOutput || 2048;
  };

  // 获取模型的上下文窗口大小
  const getContextWindowForModel = (modelId: string, providerId: string): number => {
    // 首先尝试从 lobe-chat 的模型配置获取
    const aiModel = findModel(modelId, providerId);
    if (aiModel?.contextWindowTokens) {
      return aiModel.contextWindowTokens;
    }
    // 根据已知的模型规格返回上下文窗口大小
    const contextWindows: Record<string, number> = {
      'gpt-4o': 128000,
      'gpt-4o-mini': 128000,
      'gpt-4': 8192,
      'gpt-3.5-turbo': 16385,
      'claude-3-5-sonnet-20241022': 200000,
      'claude-3-opus-20240229': 200000,
      'deepseek-chat': 32768,
      'deepseek-coder': 16384,
    };

    return contextWindows[modelId] || 4096;
  };

  // 获取模型的能力
  const getCapabilitiesForModel = (modelId: string, providerId: string) => {
    // 首先尝试从 lobe-chat 的模型配置获取
    const aiModel = findModel(modelId, providerId);
    if (aiModel && (aiModel as unknown as Record<string, unknown>).abilities) {
      const abilities = (aiModel as unknown as Record<string, unknown>).abilities as Record<string, unknown>;
      return {
        vision: Boolean(abilities.vision) || false,
        toolCalls: Boolean(abilities.functionCall) || true,
        streaming: true, // 假设都支持流式
        reasoning: Boolean(abilities.reasoning) || false
      };
    }

    // 回退到基于模型名称的推断
    const hasVision = modelId.includes('vision') || 
                     modelId.includes('gpt-4o') || 
                     modelId.includes('claude-3');
    
    const hasReasoning = modelId.includes('o1') || 
                        modelId.includes('o3') ||
                        modelId.includes('reasoning') ||
                        modelId.includes('-r1');

    return {
      vision: hasVision,
      toolCalls: true,
      streaming: true,
      reasoning: hasReasoning
    };
  };

  // 获取模型定价
  const getPricingForModel = (modelId: string, providerId: string) => {
    // 首先尝试从 lobe-chat 的模型配置获取
    const aiModel = findModel(modelId, providerId);
    if (aiModel && (aiModel as unknown as Record<string, unknown>).pricing) {
      const pricing = (aiModel as unknown as Record<string, unknown>).pricing as Record<string, unknown>;
      return {
        input: Number(pricing.input) || 0,
        output: Number(pricing.output) || 0,
        unit: (pricing.input && Number(pricing.input) < 1) ? 'per_1k_tokens' as const : 'per_1m_tokens' as const
      };
    }

    // 回退到基于已知模型的定价信息
    const pricing: Record<string, { input: number; output: number; unit: 'per_1k_tokens' | 'per_1m_tokens' }> = {
      'gpt-4o': { input: 5, output: 15, unit: 'per_1m_tokens' },
      'gpt-4o-mini': { input: 0.15, output: 0.6, unit: 'per_1m_tokens' },
      'claude-3-5-sonnet-20241022': { input: 3, output: 15, unit: 'per_1m_tokens' },
    };

    return pricing[modelId] || { input: 0, output: 0, unit: 'per_1k_tokens' as const };
  };


  // 切换模型启用状态
  const toggleModel = async (modelId: string) => {
    if (!selectedProvider) {
      return;
    }

    const originalModels = models;
    const updatedModels = models.map(model => 
      model.id === modelId 
        ? { ...model, enabled: !model.enabled }
        : model
    );
    
    // 先更新本地状态
    setModels(updatedModels);

    // 保存到后端
    try {
      await updateProvider(selectedProvider.id, {
        models: updatedModels
      });
    } catch {
      // 如果保存失败，回滚本地状态
      setModels(originalModels);
      toast.error(t('llm.updateFailed'));
    }
  };

  // 删除自定义模型
  const deleteModel = async (modelId: string) => {
    if (!selectedProvider) {
      return;
    }

    const updatedModels = models.filter(model => model.id !== modelId);
    const originalModels = models;
    
    // 先更新本地状态
    setModels(updatedModels);

    // 保存到后端
    try {
      await updateProvider(selectedProvider.id, {
        models: updatedModels
      });
      toast.success(t('llm.deleteModelSuccess'));
    } catch {
      // 如果保存失败，回滚本地状态
      setModels(originalModels);
      toast.error(t('llm.updateFailed'));
    }
  };

  // 添加自定义模型
  const handleAddCustomModel = async () => {
    if (!customModel.id || !customModel.name) {
      toast.error(t('llm.modelNameRequired'));
      return;
    }

    if (!selectedProvider) {
      return;
    }

    const newModel: LLMModel = {
      id: customModel.id,
      name: customModel.name,
      description: customModel.description,
      contextWindow: customModel.contextWindow,
      maxTokens: customModel.maxTokens,
      pricing: {
        input: 0,
        output: 0,
        unit: 'per_1k_tokens'
      },
      capabilities: {
        vision: false,
        toolCalls: true,
        streaming: true,
        reasoning: false
      },
      enabled: true,
      isCustom: true
    };

    const updatedModels = [...models, newModel];
    setModels(updatedModels);

    // 保存到后端
    try {
      await updateProvider(selectedProvider.id, {
        models: updatedModels
      });
      toast.success(t('llm.addModelSuccess'));
    } catch {
      // 如果保存失败，回滚本地状态
      setModels(models);
      toast.error(t('llm.updateFailed'));
      return;
    }

    setCustomModel({
      id: '',
      name: '',
      description: '',
      contextWindow: 4096,
      maxTokens: 2048
    });
    onAddModelClose();
  };

  if (loading) {
    return (
      <div className="flex justify-center items-center h-64">
        <Spinner size="lg" />
      </div>
    );
  }

  return (
    <div className="flex h-full w-full">
      {/* 左侧提供商列表 */}
      <div className="w-80 border-r border-border p-4 overflow-y-auto flex-shrink-0">
        <div className="mb-4">
          <div className="mb-3">
            <h2 className="text-lg font-semibold mb-1">{t('llm.providers')}</h2>
            <p className="text-sm text-muted-foreground">
              {t('llm.selectProviderToConfig')}
            </p>
          </div>
          {/* 搜索框和添加按钮 */}
          <div className="flex items-center gap-2">
            <Input
              type="text"
              placeholder={t('llm.searchProvidersPlaceholder')}
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              startContent={<Search className="w-4 h-4 text-gray-400" />}
              className="flex-1"
              size="sm"
              autoComplete="off"
            />
            <Button
              color="primary"
              size="sm"
              isIconOnly
              onPress={onAddModalOpen}
              className="flex-shrink-0"
            >
              <Plus className="w-4 h-4" />
            </Button>
          </div>
        </div>
        <div className="space-y-2">
          {filteredProviders.map((provider) => {
            const template = BUILTIN_PROVIDERS.find(t => t.id === provider.id);
            const isSelected = selectedProviderId === provider.id;
            
            return (
              <Card
                key={provider.id}
                isPressable
                isHoverable
                className={`w-full cursor-pointer transition-all ${
                  isSelected ? 'ring-2 ring-primary bg-primary/5' : ''
                }`}
                onPress={() => handleProviderSelect(provider.id)}
              >
                <CardBody className="p-3">
                  <div className="flex items-center gap-3">
                    <ProviderIcon
                      providerId={provider.id}
                      name={provider.name}
                      size={28}
                      fallbackUrl={provider.logo || template?.logo}
                    />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <h3 className="font-medium text-sm truncate">{provider.name}</h3>
                        {provider.enabled && (
                          <Chip size="sm" color="success" variant="flat">
                            {t('llm.enabled')}
                          </Chip>
                        )}
                      </div>
                      <p className="text-xs text-muted-foreground mt-1">
                        {provider.models.filter(m => m.enabled).length} {t('llm.modelsEnabled')}
                      </p>
                    </div>
                  </div>
                </CardBody>
              </Card>
            );
          })}
        </div>
        {/* 添加 Provider 弹窗 */}
        <AddProviderModal
          isOpen={isAddModalOpen}
          onClose={onAddModalClose}
          onAdd={addProvider}
        />
      </div>

      {/* 右侧配置区域 */}
      <div className="flex-1 p-6 overflow-y-auto w-full">
        {selectedProvider ? (
          <div className="w-full space-y-6">
            {/* 提供商标题 */}
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <ProviderIcon
                  providerId={selectedProvider.id}
                  name={selectedProvider.name}
                  size={40}
                  fallbackUrl={selectedProvider.logo}
                />
                <div>
                  <h1 className="text-xl font-bold">{selectedProvider.name}</h1>
                  <p className="text-sm text-muted-foreground">
                    {getI18nProviderDescription(
                      selectedProvider.id,
                      selectedProvider.description || selectedProvider.name
                    )}
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2">
                {testResult && (
                  <Tooltip content={testResult.success ? t('llm.connected') : testResult.error}>
                    {testResult.success ? (
                      <CheckCircle className="w-5 h-5 text-success" />
                    ) : (
                      <XCircle className="w-5 h-5 text-danger" />
                    )}
                  </Tooltip>
                )}

                <Switch
                  isSelected={selectedProvider.enabled}
                  onValueChange={(enabled) => {
                    updateProvider(selectedProvider.id, { enabled });
                    setSelectedProvider((prev: LLMProvider | null) => prev ? { ...prev, enabled } : null);
                  }}
                  color="success"
                />
              </div>
            </div>

            <Divider />

            {/* 配置表单 */}
            <div className="space-y-4">
              <h2 className="text-lg font-semibold">{t('llm.configuration')}</h2>

              {/* API密钥 */}
              {selectedProvider.settings.showApiKey && (
                <div>
                  <Input
                    label={t('llm.apiKey')}
                    placeholder={t('llm.apiKeyPlaceholder')}
                    value={String(config.apiKey || '')}
                    onChange={(e) => setConfig((prev: Record<string, unknown>) => ({ ...prev, apiKey: e.target.value }))}
                    type={showApiKey ? 'text' : 'password'}
                    isRequired={selectedProvider.settings.apiKeyRequired}
                    autoComplete="new-password"
                    endContent={
                      <Button
                        size="sm"
                        variant="light"
                        isIconOnly
                        onPress={() => setShowApiKey(!showApiKey)}
                      >
                        {showApiKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                      </Button>
                    }
                  />
                </div>
              )}

              {/* Base URL */}
              {selectedProvider.settings.showBaseURL && (
                <div>
                  <Input
                    label={t('llm.baseURL')}
                    placeholder={getDefaultBaseURL(selectedProvider.id)}
                    value={String(config.baseURL || '')}
                    onChange={(e) => setConfig((prev: Record<string, unknown>) => ({ ...prev, baseURL: e.target.value }))}
                    isRequired={selectedProvider.settings.baseURLRequired}
                  />
                </div>
              )}

              {/* 操作按钮 */}
              <div className="flex gap-2">
                <Button
                  color="primary"
                  variant="flat"
                  onPress={handleTest}
                  isLoading={testing}
                  startContent={!testing && <CheckCircle className="w-4 h-4" />}
                  isDisabled={!selectedProvider.enabled}
                >
                  {testing ? t('llm.testing') : t('llm.test')}
                </Button>

                <Button
                  color="default"
                  variant="flat"
                  onPress={handleSave}
                  startContent={<Save className="w-4 h-4" />}
                >
                  {t('common.save')}
                </Button>
              </div>
            </div>

            <Divider />

            {/* 模型管理 */}
            <div className="space-y-4">
              <div className="flex items-center gap-4">
                <div className="flex items-center gap-2 flex-shrink-0">
                  <h2 className="text-lg font-semibold">{t('llm.models')}</h2>
                  <div className="flex items-center gap-1 text-xs text-default-500">
                    <span className="bg-primary/10 text-primary px-2 py-1 rounded-md font-medium">
                      {models.filter(m => m.enabled).length}
                    </span>
                    <span>/</span>
                    <span className="text-default-400">
                      {models.length}
                    </span>
                  </div>
                </div>
                
                <Input
                  type="text"
                  placeholder={t('llm.searchModels')}
                  value={modelSearchQuery}
                  onChange={(e) => setModelSearchQuery(e.target.value)}
                  startContent={<Search className="w-4 h-4 text-gray-400" />}
                  className="flex-1"
                  size="sm"
                />

                <div className="flex gap-2 flex-shrink-0">
                  <Button
                    size="sm"
                    variant="flat"
                    onPress={handleFetchModels}
                    isLoading={fetchingModels}
                    startContent={!fetchingModels && <RefreshCw className="w-4 h-4" />}
                    isDisabled={selectedProvider.id !== 'ollama' && !config.apiKey}
                  >
                    {fetchingModels ? t('llm.fetching') : t('llm.fetchModels')}
                  </Button>

                  <Button
                    size="sm"
                    color="primary"
                    variant="flat"
                    onPress={onAddModelOpen}
                    startContent={<Plus className="w-4 h-4" />}
                  >
                    {t('llm.addCustomModel')}
                  </Button>
                </div>
              </div>

              {/* 模型列表 */}
              <div className="space-y-2">
                  {models
                    .filter(model => {
                      if (!modelSearchQuery.trim()) return true;
                      const query = modelSearchQuery.toLowerCase();
                      return (
                        model.name.toLowerCase().includes(query) ||
                        model.id.toLowerCase().includes(query) ||
                        (model.description && model.description.toLowerCase().includes(query)) ||
                        (model.ownedBy && model.ownedBy.toLowerCase().includes(query))
                      );
                    })
                    .sort((a, b) => {
                      // 启用的排在前面
                      if (a.enabled && !b.enabled) return -1;
                      if (!a.enabled && b.enabled) return 1;
                      return 0;
                    })
                    .map((model) => (
                    <div 
                      key={model.id} 
                      className="p-3 rounded-lg border border-default-200 bg-background hover:bg-default-50 transition-colors"
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-1">
                            <h4 className="font-medium text-sm text-foreground truncate">{model.name}</h4>
                            {model.isCustom && (
                              <Chip size="sm" color="secondary" variant="flat" className="text-xs">
                                {t('llm.custom')}
                              </Chip>
                            )}
                            {model.capabilities.vision && (
                              <Chip size="sm" color="warning" variant="flat" className="text-xs">
                                Vision
                              </Chip>
                            )}
                            {model.capabilities.reasoning && (
                              <Chip size="sm" color="success" variant="flat" className="text-xs">
                                Reasoning
                              </Chip>
                            )}
                          </div>
                          
                          {model.description && (
                            <p className="text-xs text-default-500 mb-2 line-clamp-2 leading-relaxed">
                              {getI18nModelDescription(
                                selectedProvider.id,
                                model.id,
                                model.description || model.name
                              )}
                            </p>
                          )}
                          
                          <div className="flex items-center gap-3 text-xs text-default-400">
                            {model.contextWindow && (
                              <span>Context: {model.contextWindow.toLocaleString()}</span>
                            )}
                            {model.maxTokens && (
                              <span>Max: {model.maxTokens.toLocaleString()}</span>
                            )}
                            {model.ownedBy && (
                              <span>By: {model.ownedBy}</span>
                            )}
                          </div>
                        </div>
                        
                        <div className="flex items-center gap-2 flex-shrink-0">
                          {model.isCustom && (
                            <Button
                              size="sm"
                              color="danger"
                              variant="light"
                              isIconOnly
                              onPress={() => deleteModel(model.id)}
                              className="min-w-unit-8 w-8 h-8"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </Button>
                          )}
                          
                          <Switch
                            isSelected={model.enabled}
                            onValueChange={() => toggleModel(model.id)}
                            size="sm"
                            color="primary"
                          />
                        </div>
                      </div>
                    </div>
                  ))}
                  
                  {(() => {
                    const filteredModels = models.filter(model => {
                      if (!modelSearchQuery.trim()) return true;
                      const query = modelSearchQuery.toLowerCase();
                      return (
                        model.name.toLowerCase().includes(query) ||
                        model.id.toLowerCase().includes(query) ||
                        (model.description && model.description.toLowerCase().includes(query)) ||
                        (model.ownedBy && model.ownedBy.toLowerCase().includes(query))
                      );
                    });
                    
                    if (models.length === 0) {
                      return (
                        <div className="text-center py-12 text-default-400">
                          <p className="text-sm">{t('llm.noModelsAvailable')}</p>
                          <p className="text-xs mt-1 text-default-300">{t('llm.useClientFetchToLoadModels')}</p>
                        </div>
                      );
                    }
                    
                    if (filteredModels.length === 0 && modelSearchQuery.trim()) {
                      return (
                        <div className="text-center py-12 text-default-400">
                          <p className="text-sm">{t('common.no_results')}</p>
                          <p className="text-xs mt-1 text-default-300">{t('llm.tryOtherSearchTerms')}</p>
                        </div>
                      );
                    }
                    
                    return null;
                  })()}
              </div>
            </div>
          </div>
        ) : (
          <div className="flex items-center justify-center h-64">
            <p className="text-muted-foreground">{t('llm.selectProviderToStart')}</p>
          </div>
        )}
      </div>

      {/* 添加自定义模型弹窗 */}
      <Modal isOpen={isAddModelOpen} onClose={onAddModelClose}>
        <ModalContent>
          <ModalHeader>{t('llm.addCustomModel')}</ModalHeader>
          <ModalBody>
            <div className="space-y-4">
              <Input
                label={t('llm.modelId')}
                placeholder="gpt-4-custom"
                value={customModel.id}
                onChange={(e) => setCustomModel(prev => ({ ...prev, id: e.target.value }))}
                isRequired
              />
              
              <Input
                label={t('llm.modelName')}
                placeholder="GPT-4 Custom"
                value={customModel.name}
                onChange={(e) => setCustomModel(prev => ({ ...prev, name: e.target.value }))}
                isRequired
              />
              
              <Input
                label={t('llm.description')}
                placeholder={t('llm.descriptionPlaceholder')}
                value={customModel.description}
                onChange={(e) => setCustomModel(prev => ({ ...prev, description: e.target.value }))}
              />
              
              <div className="grid grid-cols-2 gap-2">
                <Input
                  type="number"
                  label={t('llm.contextWindow')}
                  value={customModel.contextWindow.toString()}
                  onChange={(e) => setCustomModel(prev => ({ 
                    ...prev, 
                    contextWindow: parseInt(e.target.value) || 4096 
                  }))}
                />
                
                <Input
                  type="number"
                  label={t('llm.maxTokens')}
                  value={customModel.maxTokens.toString()}
                  onChange={(e) => setCustomModel(prev => ({ 
                    ...prev, 
                    maxTokens: parseInt(e.target.value) || 2048 
                  }))}
                />
              </div>
            </div>
          </ModalBody>
          <ModalFooter>
            <Button variant="flat" onPress={onAddModelClose}>
              {t('common.cancel')}
            </Button>
            <Button color="primary" onPress={handleAddCustomModel}>
              {t('llm.add')}
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>
    </div>
  );
};

export default LLMSettings;