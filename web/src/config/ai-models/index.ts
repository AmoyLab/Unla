
import { default as ai21 } from './ai21';
import { default as ai360 } from './ai360';
import { default as anthropic } from './anthropic';
import { default as azure } from './azure';
import { default as azureai } from './azureai';
import { default as baichuan } from './baichuan';
import { default as bedrock } from './bedrock';
import { default as cloudflare } from './cloudflare';
import { default as cohere } from './cohere';
import { default as deepseek } from './deepseek';
import { default as fireworksai } from './fireworksai';
import { default as giteeai } from './giteeai';
import { default as github } from './github';
import { default as google } from './google';
import { default as groq } from './groq';
import { default as higress } from './higress';
import { default as huggingface } from './huggingface';
import { default as hunyuan } from './hunyuan';
import { default as infiniai } from './infiniai';
import { default as internlm } from './internlm';
import { default as jina } from './jina';
import { default as lmstudio } from './lmstudio';
import { default as minimax } from './minimax';
import { default as mistral } from './mistral';
import { default as moonshot } from './moonshot';
import { default as novita } from './novita';
import { default as nvidia } from './nvidia';
import { default as ollama } from './ollama';
import { default as openai } from './openai';
import { default as openrouter } from './openrouter';
import { default as perplexity } from './perplexity';
import { default as ppio } from './ppio';
import { default as qiniu } from './qiniu';
import { default as qwen } from './qwen';
import { default as sambanova } from './sambanova';
import { default as search1api } from './search1api';
import { default as sensenova } from './sensenova';
import { default as siliconcloud } from './siliconcloud';
import { default as spark } from './spark';
import { default as stepfun } from './stepfun';
import { default as taichu } from './taichu';
import { default as tencentcloud } from './tencentcloud';
import { default as togetherai } from './togetherai';
import { default as upstage } from './upstage';
import { default as vertexai } from './vertexai';
import { default as vllm } from './vllm';
import { default as volcengine } from './volcengine';
import { default as wenxin } from './wenxin';
import { default as xai } from './xai';
import { default as xinference } from './xinference';
import { default as zeroone } from './zeroone';
import { default as zhipu } from './zhipu';

import { AIChatModelCard, AIEmbeddingModelCard, AITTSModelCard, AISTTModelCard, AIText2ImageModelCard, AIRealtimeModelCard } from '@/types/ai-model';

export type AllAIModelCard = AIChatModelCard | AIEmbeddingModelCard | AITTSModelCard | AISTTModelCard | AIText2ImageModelCard | AIRealtimeModelCard;

type ModelsMap = Record<string, AllAIModelCard[]>;

// Helper function to get models by provider
export const getModelsByProvider = (providerId: string): AllAIModelCard[] => {
  const providerMap: ModelsMap = {
    ai21,
    ai360,
    anthropic,
    azure,
    azureai,
    baichuan,
    bedrock,
    cloudflare,
    cohere,
    deepseek,
    fireworksai,
    giteeai,
    github,
    google,
    groq,
    higress,
    huggingface,
    hunyuan,
    infiniai,
    internlm,
    jina,
    lmstudio,
    minimax,
    mistral,
    moonshot,
    novita,
    nvidia,
    ollama,
    openai,
    openrouter,
    perplexity,
    ppio,
    qiniu,
    qwen,
    sambanova,
    search1api,
    sensenova,
    siliconcloud,
    spark,
    stepfun,
    taichu,
    tencentcloud,
    togetherai,
    upstage,
    vertexai,
    vllm,
    volcengine,
    wenxin,
    xai,
    xinference,
    zeroone,
    zhipu,
  };
  
  return providerMap[providerId] || [];
};

// Get all available provider IDs
export const getAllProviderIds = (): string[] => {
  return [
    'ai21',
    'ai360',
    'anthropic',
    'azure',
    'azureai',
    'baichuan',
    'bedrock',
    'cloudflare',
    'cohere',
    'deepseek',
    'fireworksai',
    'giteeai',
    'github',
    'google',
    'groq',
    'higress',
    'huggingface',
    'hunyuan',
    'infiniai',
    'internlm',
    'jina',
    'lmstudio',
    'minimax',
    'mistral',
    'moonshot',
    'novita',
    'nvidia',
    'ollama',
    'openai',
    'openrouter',
    'perplexity',
    'ppio',
    'qiniu',
    'qwen',
    'sambanova',
    'search1api',
    'sensenova',
    'siliconcloud',
    'spark',
    'stepfun',
    'taichu',
    'tencentcloud',
    'togetherai',
    'upstage',
    'vertexai',
    'vllm',
    'volcengine',
    'wenxin',
    'xai',
    'xinference',
    'zeroone',
    'zhipu',
  ];
};

// Get all models from all providers
export const getAllModels = (): AllAIModelCard[] => {
  const allProviders = getAllProviderIds();
  let allModels: AllAIModelCard[] = [];
  
  allProviders.forEach(providerId => {
    const providerModels = getModelsByProvider(providerId);
    allModels = allModels.concat(providerModels);
  });
  
  return allModels;
};

// Find a specific model by ID across all providers
export const findModel = (modelId: string, providerId?: string): AllAIModelCard | undefined => {
  if (providerId) {
    // Search within specific provider
    const providerModels = getModelsByProvider(providerId);
    return providerModels.find(model => model.id === modelId);
  } else {
    // Search across all providers
    const allModels = getAllModels();
    return allModels.find(model => model.id === modelId);
  }
};

// Legacy export for compatibility
export const LOBE_DEFAULT_MODEL_LIST = {
  ai21,
  ai360,
  anthropic,
  azure,
  azureai,
  baichuan,
  bedrock,
  cloudflare,
  cohere,
  deepseek,
  fireworksai,
  giteeai,
  github,
  google,
  groq,
  higress,
  huggingface,
  hunyuan,
  infiniai,
  internlm,
  jina,
  lmstudio,
  minimax,
  mistral,
  moonshot,
  novita,
  nvidia,
  ollama,
  openai,
  openrouter,
  perplexity,
  ppio,
  qiniu,
  qwen,
  sambanova,
  search1api,
  sensenova,
  siliconcloud,
  spark,
  stepfun,
  taichu,
  tencentcloud,
  togetherai,
  upstage,
  vertexai,
  vllm,
  volcengine,
  wenxin,
  xai,
  xinference,
  zeroone,
  zhipu,
};

export { default as ai21 } from './ai21';
export { default as ai360 } from './ai360';
export { default as anthropic } from './anthropic';
export { default as azure } from './azure';
export { default as azureai } from './azureai';
export { default as baichuan } from './baichuan';
export { default as bedrock } from './bedrock';
export { default as cloudflare } from './cloudflare';
export { default as cohere } from './cohere';
export { default as deepseek } from './deepseek';
export { default as fireworksai } from './fireworksai';
export { default as giteeai } from './giteeai';
export { default as github } from './github';
export { default as google } from './google';
export { default as groq } from './groq';
export { default as higress } from './higress';
export { default as huggingface } from './huggingface';
export { default as hunyuan } from './hunyuan';
export { default as infiniai } from './infiniai';
export { default as internlm } from './internlm';
export { default as jina } from './jina';
export { default as lmstudio } from './lmstudio';
export { default as minimax } from './minimax';
export { default as mistral } from './mistral';
export { default as moonshot } from './moonshot';
export { default as novita } from './novita';
export { default as nvidia } from './nvidia';
export { default as ollama } from './ollama';
export { default as openai } from './openai';
export { default as openrouter } from './openrouter';
export { default as perplexity } from './perplexity';
export { default as ppio } from './ppio';
export { default as qiniu } from './qiniu';
export { default as qwen } from './qwen';
export { default as sambanova } from './sambanova';
export { default as search1api } from './search1api';
export { default as sensenova } from './sensenova';
export { default as siliconcloud } from './siliconcloud';
export { default as spark } from './spark';
export { default as stepfun } from './stepfun';
export { default as taichu } from './taichu';
export { default as tencentcloud } from './tencentcloud';
export { default as togetherai } from './togetherai';
export { default as upstage } from './upstage';
export { default as vertexai } from './vertexai';
export { default as vllm } from './vllm';
export { default as volcengine } from './volcengine';
export { default as wenxin } from './wenxin';
export { default as xai } from './xai';
export { default as xinference } from './xinference';
export { default as zeroone } from './zeroone';
export { default as zhipu } from './zhipu';
