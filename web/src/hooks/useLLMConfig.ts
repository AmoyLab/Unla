import { useState, useEffect, useCallback } from 'react';

import { BUILTIN_PROVIDERS, getProviderDefaultConfig, getProviderModels, getDefaultBaseURL, buildEndpointURL } from '../config/llm-providers-adapter';
import api from '../services/api';
import { LLMProvider, LLMModel, CreateLLMProviderForm, UpdateLLMProviderForm } from '../types/llm';

const LLM_STORAGE_KEY = 'unla_llm_providers';

// 获取默认LLM配置的函数
const getDefaultProviders = (): LLMProvider[] => BUILTIN_PROVIDERS.map(template => ({
  id: template.id,
  name: template.name,
  logo: template.logo,
  description: template.description,
  enabled: false,
  config: getProviderDefaultConfig(template.id),
  models: getProviderModels(template.id), // 动态生成模型
  settings: template.settings
}));

export const useLLMConfig = () => {
  const [providers, setProviders] = useState<LLMProvider[]>([]);
  const [loading, setLoading] = useState(true);
  const [defaultProvider, setDefaultProvider] = useState<LLMProvider | null>(null);

  // Fetch default provider from backend on mount
  useEffect(() => {
    async function fetchDefaultProvider() {
      try {
        const response = await api.get('/defaultllmprovider');
        const arr = response.data?.configs || response.data?.data || response.data;
        if (Array.isArray(arr) && arr.length > 0) {
          setDefaultProvider(arr[0]);
        } else {
          setDefaultProvider(null);
        }
      } catch {
        setDefaultProvider(null);
      }
    }
    fetchDefaultProvider();
  }, []);

  // 加载配置
  const loadConfig = useCallback(() => {
    setLoading(true);
    try {
      const saved = localStorage.getItem(LLM_STORAGE_KEY);
      if (saved) {
        const savedProviders = JSON.parse(saved) as LLMProvider[];
        
        // 合并内置提供商和保存的配置
        const merged = BUILTIN_PROVIDERS.map(template => {
          const saved = savedProviders.find(p => p.id === template.id);
          if (saved) {
            // 如果有保存的配置，但要确保模型是最新的
            // 强制使用最新的内置模型，但保留用户的自定义模型
            const builtinModels = getProviderModels(template.id);
            const customModels = saved.models.filter(m => m.isCustom);
            return {
              ...saved,
              models: [...builtinModels, ...customModels]
            };
          }
          // 如果没有保存的配置，使用默认配置
          return {
            id: template.id,
            name: template.name,
            logo: template.logo,
            description: template.description,
            enabled: false,
            config: getProviderDefaultConfig(template.id),
            models: getProviderModels(template.id), // 动态生成模型
            settings: template.settings
          };
        });
        
        // 添加自定义提供商（始终将 custom_default 视为自定义提供商）
        const customProviders = savedProviders.filter(p => 
          !BUILTIN_PROVIDERS.some(template => template.id === p.id) ||
          p.id === 'custom_default'
        );
        
        // 如果有来自 API 的默认提供商，确保它被包含并且是最新的
        if (defaultProvider && defaultProvider.id === 'custom_default') {
          const existingDefault = customProviders.findIndex(p => p.id === 'custom_default');
          if (existingDefault >= 0) {
            // 更新现有的默认提供商，同时保留启用状态
            customProviders[existingDefault] = {
              ...defaultProvider,
              enabled: customProviders[existingDefault].enabled
            };
          } else {
            // 添加新的默认提供商
            customProviders.push(defaultProvider);
          }
        }

        setProviders([...merged, ...customProviders]);
      } else {
        // 如果没有保存的配置，使用内置提供商并在可用时添加默认提供商
        const initial = getDefaultProviders();
        if (defaultProvider && defaultProvider.id === 'custom_default') {
          initial.push(defaultProvider);
        }
        setProviders(initial);
      }
    } catch (error) {
      console.error('Failed to load LLM config:', error);
      const initial = getDefaultProviders();
      if (defaultProvider && defaultProvider.id === 'custom_default') {
        initial.push(defaultProvider);
      }
      setProviders(initial);
    } finally {
      setLoading(false);
    }
  }, [defaultProvider]);

  // 保存配置
  const saveConfig = useCallback((newProviders: LLMProvider[]) => {
    try {
      localStorage.setItem(LLM_STORAGE_KEY, JSON.stringify(newProviders));
      setProviders(newProviders);
    } catch (error) {
      console.error('Failed to save LLM config:', error);
      throw new Error('Failed to save configuration');
    }
  }, []);

  // 添加提供商
  const addProvider = useCallback((data: CreateLLMProviderForm) => {
    const newProvider: LLMProvider = {
      id: `custom_${Date.now()}`,
      name: data.name,
      description: data.description || '',
      enabled: true,
      config: {
        temperature: 0.7,
        topP: 1.0,
        maxTokens: 2048,
        timeout: 30000,
        fetchOnClient: false,
        ...data.config
      },
      models: data.models || [],
      settings: {
        showApiKey: true,
        showBaseURL: true,
        showOrganization: false,
        showTemperature: true,
        showTopP: true,
        showMaxTokens: true,
        showTimeout: true,
        allowClientFetch: true,
        defaultClientFetch: false,
        apiKeyRequired: true,
        baseURLRequired: false
      }
    };

    const newProviders = [...providers, newProvider];
    saveConfig(newProviders);
    return newProvider;
  }, [providers, saveConfig]);

  // 更新提供商
  const updateProvider = useCallback((id: string, data: UpdateLLMProviderForm) => {
    const newProviders = providers.map((provider: LLMProvider) => 
      provider.id === id 
        ? {
            ...provider,
            ...data,
            config: data.config ? { ...provider.config, ...data.config } : provider.config
          }
        : provider
    );
    saveConfig(newProviders);
  }, [providers, saveConfig]);

  // 删除提供商
  const deleteProvider = useCallback((id: string) => {
    const newProviders = providers.filter((provider: LLMProvider) => provider.id !== id);
    saveConfig(newProviders);
  }, [providers, saveConfig]);

  // 切换提供商启用状态
  const toggleProvider = useCallback((id: string, enabled: boolean) => {
    updateProvider(id, { enabled });
  }, [updateProvider]);

  // 测试提供商连接
  const testProvider = useCallback(async (id: string): Promise<{ success: boolean; error?: string }> => {
    const provider = providers.find((p: LLMProvider) => p.id === id);
    if (!provider) {
      return { success: false, error: 'Provider not found' };
    }

    try {
      const { config, settings } = provider;
      const checkModel = settings.checkModel || 'gpt-3.5-turbo';

      // 基本配置检查
      if (settings.apiKeyRequired && !config.apiKey) {
        return { success: false, error: 'API key is required' };
      }

      if (settings.baseURLRequired && !config.baseURL) {
        return { success: false, error: 'Base URL is required' };
      }

      // 发送测试请求
      const testPayload = {
        model: checkModel,
        messages: [{ role: 'user', content: 'Hello' }],
        max_tokens: 10
      };

      const headers: Record<string, string> = {
        'Content-Type': 'application/json'
      };

      if (config.apiKey) {
        if (provider.id === 'anthropic') {
          headers['x-api-key'] = config.apiKey as string;
          headers['anthropic-version'] = '2023-06-01';
        } else {
          headers['Authorization'] = `Bearer ${config.apiKey}`;
        }
      }

      if (config.organization) {
        headers['OpenAI-Organization'] = config.organization as string;
      }

      const baseURL = (config.baseURL as string) || getDefaultBaseURL(provider.id);
      
      const endpoint = provider.id === 'anthropic' 
        ? buildEndpointURL(baseURL, '/v1/messages')
        : buildEndpointURL(baseURL, '/chat/completions');
      const response = await fetch(endpoint, {
        method: 'POST',
        headers,
        body: JSON.stringify(testPayload)
      });

      if (response.ok) {
        return { success: true };
      } else {
        const error = await response.text();
        return { success: false, error: `HTTP ${response.status}: ${error}` };
      }
    } catch (error) {
      return { 
        success: false, 
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }, [providers]);

  // 获取启用的提供商
  const getEnabledProviders = useCallback(() => {
    const enabled = providers.filter((provider: LLMProvider) => provider?.enabled);
    
    // Include defaultProvider if it exists and is not already included
    if (defaultProvider && defaultProvider.enabled !== false) {
      try {

        // Find if this provider already exists in the enabled list
        const existingIndex = enabled.findIndex((p: LLMProvider) => p?.id === defaultProvider.id);
        
        if (existingIndex >= 0) {
          // If it exists, merge its config with the default provider's config
          enabled[existingIndex] = {
            ...defaultProvider,
            ...enabled[existingIndex],
            config: {
              ...(defaultProvider.config || {}),
              ...(enabled[existingIndex].config || {})
            },
            models: [
              ...(defaultProvider.models || []),
              ...((enabled[existingIndex].models || []).filter((m: LLMModel & { isCustom?: boolean }) => m?.isCustom))
            ].filter((m, i, arr) => arr.findIndex(item => item.id === m.id) === i), // Remove duplicates
            settings: {
              ...(defaultProvider.settings || {}),
              ...(enabled[existingIndex].settings || {})
            }
          };
          return enabled;
        } else {
          // If it doesn't exist, add it to the start of the array
          const completeDefaultProvider = {
            ...defaultProvider,
            config: defaultProvider.config || {},
            models: defaultProvider.models || [],
            settings: defaultProvider.settings || {}
          };
          return [completeDefaultProvider, ...enabled];
        }
      } catch (err) {
        console.error('[useLLMConfig] Error merging defaultProvider:', err);
        return enabled;
      }
    }
    
    return enabled;
  }, [providers, defaultProvider]);

  // 获取单个提供商
  const getProvider = useCallback((id: string) => {
    return providers.find((provider: LLMProvider) => provider.id === id);
  }, [providers]);

  // 重置为默认配置
  const resetToDefault = useCallback(() => {
    localStorage.removeItem(LLM_STORAGE_KEY);
    setProviders(getDefaultProviders());
  }, []);

  // 导出配置
  const exportConfig = useCallback(() => {
    const config = {
      version: '1.0.0',
      providers: providers,
      exportedAt: new Date().toISOString()
    };
    
    const blob = new Blob([JSON.stringify(config, null, 2)], { 
      type: 'application/json' 
    });
    
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `unla-llm-config-${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, [providers]);

  // 导入配置
  const importConfig = useCallback((file: File): Promise<void> => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        try {
          const config = JSON.parse(e.target?.result as string);
          if (config.version && config.providers && Array.isArray(config.providers)) {
            saveConfig(config.providers);
            resolve();
          } else {
            reject(new Error('Invalid configuration file format'));
          }
        } catch {
          reject(new Error('Failed to parse configuration file'));
        }
      };
      reader.onerror = () => reject(new Error('Failed to read file'));
      reader.readAsText(file);
    });
  }, [saveConfig]);

  // 初始化加载
  useEffect(() => {
    loadConfig();
  }, [loadConfig]);

  return {
    providers,
    loading,
    addProvider,
    updateProvider,
    deleteProvider,
    toggleProvider,
    testProvider,
    getEnabledProviders,
    getProvider,
    resetToDefault,
    exportConfig,
    importConfig,
    reload: loadConfig,
    defaultProvider
  };
};