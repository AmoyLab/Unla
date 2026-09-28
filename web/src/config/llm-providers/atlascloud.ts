import { ModelProviderCard } from '@/types/llm';

// ref https://www.atlascloud.ai/
const AtlasCloud: ModelProviderCard = {
  chatModels: [
    {
      contextWindowTokens: 1_047_576,
      description: 'OpenAI GPT-4.1 Mini，通过 Atlas Cloud 网关提供。',
      displayName: 'GPT-4.1 Mini (Atlas Cloud)',
      enabled: true,
      functionCall: true,
      id: 'openai/gpt-4.1-mini',
    },
    {
      contextWindowTokens: 400_000,
      description: 'OpenAI GPT-5.4 Mini，通过 Atlas Cloud 网关提供。',
      displayName: 'GPT-5.4 Mini (Atlas Cloud)',
      enabled: true,
      functionCall: true,
      id: 'openai/gpt-5.4-mini',
    },
    {
      contextWindowTokens: 200_000,
      description: 'Anthropic Claude Sonnet 4.6，通过 Atlas Cloud 网关提供。',
      displayName: 'Claude Sonnet 4.6 (Atlas Cloud)',
      enabled: true,
      functionCall: true,
      id: 'anthropic/claude-sonnet-4.6',
      vision: true,
    },
    {
      contextWindowTokens: 163_840,
      description: 'DeepSeek V3.2，通过 Atlas Cloud 网关提供。',
      displayName: 'DeepSeek V3.2 (Atlas Cloud)',
      enabled: true,
      functionCall: true,
      id: 'deepseek-ai/deepseek-v3.2',
    },
    {
      contextWindowTokens: 131_072,
      description: 'Qwen3-235B-A22B-Instruct，通过 Atlas Cloud 网关提供。',
      displayName: 'Qwen3 235B Instruct (Atlas Cloud)',
      enabled: true,
      functionCall: true,
      id: 'Qwen/Qwen3-235B-A22B-Instruct-2507',
    },
    {
      contextWindowTokens: 262_144,
      description: 'Qwen3.5 35B A3B，通过 Atlas Cloud 网关提供。',
      displayName: 'Qwen3.5 35B A3B (Atlas Cloud)',
      enabled: true,
      functionCall: true,
      id: 'qwen/qwen3.5-35b-a3b',
    },
    {
      contextWindowTokens: 202_752,
      description: 'Z.AI GLM-4.6，通过 Atlas Cloud 网关提供。',
      displayName: 'GLM-4.6 (Atlas Cloud)',
      enabled: true,
      functionCall: true,
      id: 'zai-org/GLM-4.6',
    },
    {
      contextWindowTokens: 262_144,
      description: 'Moonshot Kimi K2.5，通过 Atlas Cloud 网关提供。',
      displayName: 'Kimi K2.5 (Atlas Cloud)',
      enabled: true,
      functionCall: true,
      id: 'moonshotai/kimi-k2.5',
    },
    {
      contextWindowTokens: 196_608,
      description: 'MiniMax M2.5，通过 Atlas Cloud 网关提供。',
      displayName: 'MiniMax M2.5 (Atlas Cloud)',
      enabled: true,
      functionCall: true,
      id: 'minimaxai/minimax-m2.5',
    },
  ],
  checkModel: 'openai/gpt-4.1-mini',
  description:
    'Atlas Cloud 是一个 OpenAI 兼容的统一网关，通过单一 API 接入 100+ 大语言模型，涵盖 OpenAI、Anthropic、DeepSeek、Qwen、Z.AI、Moonshot、MiniMax 等厂商，模型 ID 采用 `vendor/model` 格式。',
  id: 'atlascloud',
  modelList: { showModelFetcher: true },
  modelsUrl: 'https://www.atlascloud.ai/',
  name: 'Atlas Cloud',
  proxyUrl: {
    placeholder: 'https://api.atlascloud.ai/v1',
  },
  settings: {
    proxyUrl: {
      placeholder: 'https://api.atlascloud.ai/v1',
    },
    sdkType: 'openai',
    showModelFetcher: true,
  },
  url: 'https://www.atlascloud.ai/',
};

export default AtlasCloud;
