import React from 'react';

import { IconType } from './types';

// SVG Icon component that loads SVG files from public directory
const createSVGIcon = (svgFileName: string) => {
  const IconComponent = React.memo<IconType>(({ size = 24, className, style }) => (
    <img
      src={`/icons/providers/${svgFileName}`}
      alt=""
      width={size}
      height={size}
      className={className}
      style={style}
    />
  ));
  IconComponent.displayName = `${svgFileName}Icon`;
  return IconComponent;
};

// Provider Icons using SVG files from public directory
export const OpenAI = createSVGIcon('openai.svg');
export const Azure = createSVGIcon('azure.svg');
export const AzureAI = createSVGIcon('azureai.svg');
export const Anthropic = createSVGIcon('anthropic.svg');
export const Google = createSVGIcon('google.svg');
export const Bedrock = createSVGIcon('bedrock.svg');
export const DeepSeek = createSVGIcon('deepseek.svg');
export const Groq = createSVGIcon('groq.svg');
export const GitHub = createSVGIcon('github.svg');
export const Minimax = createSVGIcon('minimax.svg');
export const Mistral = createSVGIcon('mistral.svg');
export const Moonshot = createSVGIcon('moonshot.svg');
export const Ollama = createSVGIcon('ollama.svg');
export const Perplexity = createSVGIcon('perplexity.svg');
export const OpenRouter = createSVGIcon('openrouter.svg');
export const ZeroOne = createSVGIcon('zeroone.svg');
export const Qiniu = createSVGIcon('qiniu.svg');
export const Qwen = createSVGIcon('qwen.svg');
export const Stepfun = createSVGIcon('stepfun.svg');
export const Spark = createSVGIcon('spark.svg');
export const Baichuan = createSVGIcon('baichuan.svg');
export const Ai360 = createSVGIcon('ai360.svg');
export const SiliconCloud = createSVGIcon('siliconcloud.svg');
export const Upstage = createSVGIcon('upstage.svg');
export const Ai21 = createSVGIcon('ai21.svg');
export const Hunyuan = createSVGIcon('hunyuan.svg');
export const Nvidia = createSVGIcon('nvidia.svg');
export const TencentCloud = createSVGIcon('tencentcloud.svg');
export const Wenxin = createSVGIcon('wenxin.svg');
export const SenseNova = createSVGIcon('sensenova.svg');
export const HuggingFace = createSVGIcon('huggingface.svg');
export const LmStudio = createSVGIcon('lmstudio.svg');
export const XAI = createSVGIcon('xai.svg');
export const Cloudflare = createSVGIcon('cloudflare.svg');
export const InternLM = createSVGIcon('internlm.svg');
export const Higress = createSVGIcon('higress.svg');
export const VLLM = createSVGIcon('vllm.svg');
export const GiteeAI = createSVGIcon('giteeai.svg');
export const VertexAI = createSVGIcon('vertexai.svg');
export const PPIO = createSVGIcon('ppio.svg');
export const Jina = createSVGIcon('jina.svg');
export const Volcengine = createSVGIcon('volcengine.svg');
export const SambaNova = createSVGIcon('sambanova.svg');
export const Runcrate = createSVGIcon('runcrate.svg');
export const Cohere = createSVGIcon('cohere.svg');
export const Search1API = createSVGIcon('search1api.svg');
export const Xinference = createSVGIcon('xinference.svg');
export const Novita = createSVGIcon('novita.svg');
export const Zhipu = createSVGIcon('zhipu.svg');
export const TogetherAI = createSVGIcon('togetherai.svg');
export const FireworksAI = createSVGIcon('fireworksai.svg');
export const Doubao = createSVGIcon('doubao.svg');
export const Taichu = createSVGIcon('taichu.svg');
export const InfiniAI = createSVGIcon('infiniai.svg');
export const ModelScope = createSVGIcon('modelscope.svg');