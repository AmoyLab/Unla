import { ModelProviderCard } from '@/types/llm';

// ref: https://www.runcrate.ai/inference/pricing
const Runcrate: ModelProviderCard = {
  chatModels: [],
  checkModel: 'deepseek-ai/DeepSeek-V4.1-Flash',
  description: 'Runcrate 提供兼容 OpenAI 的推理 API，可调用 DeepSeek、GLM、Qwen、Kimi、gpt-oss 等开放权重模型。',
  disableBrowserRequest: true,
  id: 'runcrate',
  modelList: { showModelFetcher: true },
  modelsUrl: 'https://www.runcrate.ai/inference/pricing',
  name: 'Runcrate',
  settings: {
    disableBrowserRequest: true,
    proxyUrl: {
      placeholder: 'https://api.runcrate.ai/v1',
    },
    sdkType: 'openai',
    showModelFetcher: true,
  },
  url: 'https://www.runcrate.ai',
};

export default Runcrate;
