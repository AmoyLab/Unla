// Adapter functions to bridge old LLM provider system with new lobe-chat structure

import i18next from 'i18next';

import { AIChatModelCard } from '../types/ai-model';
import { BuiltinProviderTemplate, LLMModel, convertToLLMModel } from '../types/llm-legacy';

import { getModelsByProvider } from './ai-models';
import { DEFAULT_MODEL_PROVIDER_LIST } from './llm-providers/index';

// Convert lobe-chat providers to old BuiltinProviderTemplate format
const convertLobeProviderToTemplate = (lobeProvider: {
  id: string;
  name: string;
  description?: string;
  url?: string;
  showApiKey?: boolean;
  checkModel?: string;
}): BuiltinProviderTemplate => {
  return {
    id: lobeProvider.id,
    name: lobeProvider.name,
    logo: undefined, // Using lobehub/icons instead
    description: lobeProvider.description || `${lobeProvider.name} AI models`,
    website: lobeProvider.url,
    documentation: lobeProvider.url,
    settings: {
      showApiKey: lobeProvider.showApiKey !== false,
      showBaseURL: true,
      showOrganization: lobeProvider.id === 'openai',
      showTemperature: true,
      showTopP: true,
      showMaxTokens: true,
      showTimeout: true,
      allowClientFetch: true,
      defaultClientFetch: lobeProvider.id === 'ollama' || lobeProvider.id === 'lmstudio' || lobeProvider.id === 'vllm',
      apiKeyRequired: lobeProvider.showApiKey !== false && lobeProvider.id !== 'ollama',
      baseURLRequired: lobeProvider.id === 'azure' || lobeProvider.id === 'ollama' || lobeProvider.id === 'lmstudio' || lobeProvider.id === 'vllm',
      checkModel: lobeProvider.checkModel || getDefaultCheckModel(lobeProvider.id)
    },
    defaultModels: []
  };
};

const getDefaultCheckModel = (providerId: string): string => {
  const checkModels: Record<string, string> = {
    'openai': 'gpt-4o-mini',
    'anthropic': 'claude-3-5-haiku-20241022',
    'google': 'gemini-1.5-flash',
    'azure': 'gpt-4o-mini',
    'bedrock': 'anthropic.claude-3-5-sonnet-20241022-v2:0',
    'deepseek': 'deepseek-chat',
    'qwen': 'qwen-plus',
    'moonshot': 'moonshot-v1-8k',
    'zhipu': 'glm-4',
    'baichuan': 'Baichuan2-Turbo',
    'minimax': 'abab6.5s-chat',
    'openrouter': 'openrouter/auto',
    'atlascloud': 'openai/gpt-4.1-mini',
    'huggingface': 'mistralai/Mistral-7B-Instruct-v0.3',
    'groq': 'llama3-8b-8192',
    'perplexity': 'llama-3.1-sonar-small-128k-online',
    'ollama': 'llama3.1:8b',
    'lmstudio': 'local-model',
    'vllm': 'local-model',
    'mistral': 'mistral-large-latest',
    'cohere': 'command-r-plus',
    'ai21': 'jamba-1.5-large',
    'xai': 'grok-beta'
  };
  return checkModels[providerId] || 'gpt-3.5-turbo';
};

// Build BUILTIN_PROVIDERS from lobe-chat providers
export const BUILTIN_PROVIDERS: BuiltinProviderTemplate[] = DEFAULT_MODEL_PROVIDER_LIST.map(convertLobeProviderToTemplate);

// Generate models from lobe-chat AI model configuration
export const getProviderModels = (providerId: string): LLMModel[] => {
  const aiModels = getModelsByProvider(providerId).filter(model => model.type === 'chat') as AIChatModelCard[];
  return aiModels.map(model => convertToLLMModel(model, providerId));
};

// Get provider template
export const getProviderTemplate = (providerId: string): BuiltinProviderTemplate | undefined => {
  return BUILTIN_PROVIDERS.find(provider => provider.id === providerId);
};

// Get all provider IDs
export const getAllProviderIds = (): string[] => {
  return BUILTIN_PROVIDERS.map(provider => provider.id);
};

// Get provider default configuration
export const getProviderDefaultConfig = (providerId: string) => {
  const template = getProviderTemplate(providerId);
  if (!template) return {};

  return {
    baseURL: getDefaultBaseURL(providerId),
    temperature: 0.7,
    topP: 1.0,
    maxTokens: 2048,
    timeout: 30000,
    fetchOnClient: template.settings.defaultClientFetch
  };
};

export const getDefaultBaseURL = (providerId: string): string => {
  const baseURLs: Record<string, string> = {
    // OpenAI and compatible providers
    'openai': 'https://api.openai.com/v1',
    
    // Anthropic
    'anthropic': 'https://api.anthropic.com',
    
    // Google providers
    'google': 'https://generativelanguage.googleapis.com',
    
    // DeepSeek
    'deepseek': 'https://api.deepseek.com',
    
    // Groq
    'groq': 'https://api.groq.com/openai/v1',
    
    // Mistral
    'mistral': 'https://api.mistral.ai',
    
    // Perplexity
    'perplexity': 'https://api.perplexity.ai',
    
    // OpenRouter
    'openrouter': 'https://openrouter.ai/api/v1',

    // Atlas Cloud
    'atlascloud': 'https://api.atlascloud.ai/v1',
    
    // Cohere
    'cohere': 'https://api.cohere.ai/compatibility/v1',
    
    // Nvidia
    'nvidia': 'https://integrate.api.nvidia.com/v1',
    
    // Local/self-hosted providers
    'ollama': 'http://localhost:11434',
    'lmstudio': 'http://localhost:1234/v1',
    'vllm': 'http://localhost:8000/v1',
    
    // Chinese providers
    'qwen': 'https://dashscope.aliyuncs.com/compatible-mode/v1',
    'moonshot': 'https://api.moonshot.cn/v1',
    'siliconcloud': 'https://api.siliconflow.cn/v1',
    'spark': 'https://spark-api-open.xf-yun.com/v1',
    'qiniu': 'https://api.qnaigc.com/v1',
    'search1api': 'https://api.search1api.com/v1',
    'infiniai': 'https://cloud.infini-ai.com/maas/v1',
    'sambanova': 'https://api.sambanova.ai/v1',
    'jina': 'https://deepsearch.jina.ai/v1',
    'xai': 'https://api.x.ai/v1',
    'higress': 'https://127.0.0.1:8080/v1',
    'xinference': 'http://localhost:9997/v1',
    
    // Additional Chinese providers (may need custom configuration)
    'zhipu': '', // Users need to configure custom endpoint
    'baichuan': '', // Users need to configure custom endpoint  
    'minimax': '', // Users need to configure custom endpoint
    
    // Providers requiring custom setup
    'azure': '', // Will be set by user (custom endpoint)
    'bedrock': '', // AWS Bedrock doesn't use standard base URL
    'vertexai': '', // GCP Vertex AI doesn't use standard base URL
    'huggingface': '', // HuggingFace uses model-specific URLs
  };
  return baseURLs[providerId] || '';
};

// Helper function to properly construct URLs without duplicate path segments
export const buildEndpointURL = (baseURL: string, path: string): string => {
  // Remove trailing slash from baseURL and leading slash from path
  const cleanBaseURL = baseURL.replace(/\/$/, '');
  const cleanPath = path.replace(/^\//, '');
  
  // Check if baseURL already ends with the path or part of it
  if (cleanBaseURL.endsWith(cleanPath)) {
    return cleanBaseURL;
  }
  
  // Check for partial overlaps (like /v1 in baseURL and /v1/chat/completions in path)
  const baseURLParts = cleanBaseURL.split('/');
  const pathParts = cleanPath.split('/');
  
  // Find overlapping segments from the end of baseURL and start of path
  let overlapIndex = 0;
  for (let i = 1; i <= Math.min(baseURLParts.length, pathParts.length); i++) {
    const baseEnd = baseURLParts.slice(-i).join('/');
    const pathStart = pathParts.slice(0, i).join('/');
    if (baseEnd === pathStart) {
      overlapIndex = i;
    }
  }
  
  if (overlapIndex > 0) {
    const remainingPath = pathParts.slice(overlapIndex).join('/');
    return remainingPath ? `${cleanBaseURL}/${remainingPath}` : cleanBaseURL;
  }
  
  return `${cleanBaseURL}/${cleanPath}`;
};

/**
 * Get a provider or model description with i18n support
 * @param key The i18n key to look up
 * @param fallback The fallback text to use if translation is not available
 * @param lng The language to use (optional)
 * @returns The translated text or fallback
 */
function getI18nDescription(key: string, fallback: string, lng?: string): string {
  try {
    const translated = i18next.t(key, { lng });
    return translated === key ? fallback : translated;
  } catch {
    return fallback;
  }
}

/**
 * Get a provider description with i18n support
 * @param providerId The ID of the provider (e.g., 'openai', 'google', etc.)
 * @param fallback The fallback text to use if translation is not available
 * @param lng The language to use (optional)
 * @returns The translated text or fallback
 */
export const getProviderDescription = (providerId: string, fallback: string, lng?: string): string => {
  return getI18nDescription(`llm.providerDescriptions.${providerId}`, fallback, lng);
};

/**
 * Get a model description with i18n support
 * @param providerId The ID of the provider (e.g., 'openai', 'google', etc.)
 * @param modelId The ID of the model (e.g., 'gpt-4', 'palm', etc.)
 * @param fallback The fallback text to use if translation is not available
 * @param lng The language to use (optional)
 * @returns The translated text or fallback
 */
export const getModelDescription = (providerId: string, modelId: string, fallback: string, lng?: string): string => {
  // Try llm.modelDescriptions.{providerId}.{modelId} first, then llm.modelDescriptions.{modelId}
  const keyWithProvider = `llm.modelDescriptions.${providerId}.${modelId}`;
  const keyWithoutProvider = `llm.modelDescriptions.${modelId}`;
  const descWithProvider = getI18nDescription(keyWithProvider, '', lng);
  if (descWithProvider) return descWithProvider;
  return getI18nDescription(keyWithoutProvider, fallback, lng);
};