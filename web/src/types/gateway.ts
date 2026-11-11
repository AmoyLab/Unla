import type { PromptConfig } from './prompt';

export interface Tenant {
  id: number;
  name: string;
  prefix: string;
  description: string;
  isActive: boolean;
}

export interface ConfigEditorProps {
  config: string;
  onChange: (newConfig: string) => void;
  isDark: boolean;
  editorOptions: Record<string, unknown>;
  isEditing?: boolean;
}

export interface Gateway {
  name: string;
  tenant: string;
  mcpServers?: MCPServerConfig[];
  tools?: ToolConfig[];
  prompts?: PromptConfig[];
  servers?: ServerConfig[];
  routers?: RouterConfig[];
  createdAt: string;
  updatedAt: string;
}

export interface MCPServerConfig {
  type: string;
  name: string;
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
  headers?: Record<string, string>;
  policy: string;
  preinstalled: boolean;
}

export interface ToolConfig {
  name: string;
  description?: string;
  method: string;
  endpoint: string;
  proxy?: ProxyConfig;
  headers?: Record<string, string>;
  headersOrder?: string[];
  args?: ArgConfig[];
  requestBody: string;
  responseBody: string;
  inputSchema?: Record<string, unknown>;
}

export interface ServerConfig {
  name: string;
  description: string;
  allowedTools?: string[];
  config?: Record<string, string>;
}

export interface RouterConfig {
  server: string;
  prefix: string;
  ssePrefix?: string;
  cors?: CORSConfig;
  auth?: AuthConfig;
}

export interface AuthConfig {
  mode: string;
}

export interface CORSConfig {
  allowOrigins?: string[];
  allowMethods?: string[];
  allowHeaders?: string[];
  exposeHeaders?: string[];
  allowCredentials: boolean;
}

export interface ProxyConfig {
  host: string;
  port: number;
  type: string;
}

export interface ArgConfig {
  name: string;
  position: string;
  required: boolean;
  type: string;
  description: string;
  default: string;
  items?: ItemsConfig;
}

export interface PropertyConfig {
  type: string;
  description?: string;
  enum?: string[];
  items?: ItemsConfig;
  required?: string[];
}

export interface ItemsConfig {
  type: string;
  enum?: string[];
  properties?: Record<string, PropertyConfig>;
  items?: ItemsConfig;
  required?: string[];
}

export interface KeyValueItem {
  key: string;
  value: string;
  description?: string;
}

export interface HeadersFormState {
  [toolIndex: number]: KeyValueItem[];
}

export interface EnvFormState {
  [serverIndex: number]: KeyValueItem[];
}

export interface YAMLConfig {
  name?: string;
  mcpServers?: Record<string, unknown>;
  tools?: Record<string, unknown>;
  servers?: Record<string, unknown>;
  routers?: Record<string, unknown>;
  [key: string]: unknown;
}
