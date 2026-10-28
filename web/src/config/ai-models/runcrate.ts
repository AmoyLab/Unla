import { AIChatModelCard } from '@/types/ai-model';

// https://www.runcrate.ai/inference/pricing
// Context, output and pricing (USD per 1M tokens) from https://api.runcrate.ai/v1/models
const runcrateChatModels: AIChatModelCard[] = [
  {
    abilities: {
      functionCall: true,
      reasoning: true,
      vision: true,
    },
    contextWindowTokens: 1_048_576,
    displayName: 'DeepSeek V4.1 Flash',
    enabled: true,
    id: 'deepseek-ai/DeepSeek-V4.1-Flash',
    maxOutput: 1_048_576,
    pricing: {
      input: 0.147,
      output: 0.441,
    },
    type: 'chat',
  },
  {
    abilities: {
      functionCall: true,
      reasoning: true,
      vision: true,
    },
    contextWindowTokens: 1_048_576,
    displayName: 'GLM 5.3 Flash',
    enabled: true,
    id: 'zai-org/GLM-5.3-Flash',
    maxOutput: 1_048_576,
    pricing: {
      input: 0.1575,
      output: 0.525,
    },
    type: 'chat',
  },
  {
    abilities: {
      functionCall: true,
      reasoning: true,
    },
    contextWindowTokens: 1_048_576,
    displayName: 'GLM 5.3',
    enabled: true,
    id: 'zai-org/GLM-5.3',
    maxOutput: 1_048_576,
    pricing: {
      input: 0.590625,
      output: 2.625,
    },
    type: 'chat',
  },
  {
    abilities: {
      functionCall: true,
      reasoning: true,
    },
    contextWindowTokens: 1_000_000,
    displayName: 'Qwen3.8 Flash',
    enabled: true,
    id: 'Qwen/Qwen3.8-Flash',
    maxOutput: 1_000_000,
    pricing: {
      input: 0.11865,
      output: 0.4011,
    },
    type: 'chat',
  },
  {
    abilities: {
      functionCall: true,
      reasoning: true,
    },
    contextWindowTokens: 131_072,
    displayName: 'gpt-oss 120B',
    enabled: true,
    id: 'openai/gpt-oss-120b',
    maxOutput: 117_964,
    pricing: {
      input: 0.03885,
      output: 0.1785,
    },
    type: 'chat',
  },
  {
    abilities: {
      functionCall: true,
      reasoning: true,
      vision: true,
    },
    contextWindowTokens: 262_144,
    displayName: 'Kimi K2.6',
    enabled: true,
    id: 'moonshotai/Kimi-K2.6',
    maxOutput: 16_384,
    pricing: {
      input: 0.7875,
      output: 3.675,
    },
    type: 'chat',
  },
];

export const allModels = [...runcrateChatModels];

export default allModels;
