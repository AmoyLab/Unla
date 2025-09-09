import {z} from 'zod';

export const ToolSchema = z
  .object({
    name: z.string(),
    description: z.optional(z.string()),
    inputSchema: z
      .object({
        type: z.literal("object"),
        properties: z.optional(z.object({}).passthrough()),
      })
      .passthrough(),
  })
  .passthrough();

export type Tool = z.infer<typeof ToolSchema>;

export const ListToolsResultSchema = z.object({
  tools: z.array(ToolSchema),
});

export type ListToolsResult = z.infer<typeof ListToolsResultSchema>;

export interface MCPConfigVersion {
  version: number;
  created_by: string;
  created_at: string;
  action_type: 'Create' | 'Update' | 'Delete' | 'Revert';
  name: string;
  tenant: string;
  routers: string;
  servers: string;
  tools: string;
  mcp_servers: string;
  is_active: boolean;
  hash: string;
}

export interface MCPConfigVersionListResponse {
  data: MCPConfigVersion[];
}

// MCP Capabilities types
export const PromptSchema = z.object({
  name: z.string(),
  description: z.optional(z.string()),
  arguments: z.optional(z.array(z.object({
    name: z.string(),
    description: z.optional(z.string()),
    required: z.optional(z.boolean())
  })))
}).passthrough();

export type Prompt = z.infer<typeof PromptSchema>;

export const ResourceSchema = z.object({
  uri: z.string(),
  name: z.string(),
  description: z.optional(z.string()),
  mimeType: z.optional(z.string())
}).passthrough();

export type Resource = z.infer<typeof ResourceSchema>;

export const ResourceTemplateSchema = z.object({
  uriTemplate: z.string(),
  name: z.string(),
  description: z.optional(z.string()),
  mimeType: z.optional(z.string())
}).passthrough();

export type ResourceTemplate = z.infer<typeof ResourceTemplateSchema>;

export interface MCPCapabilities {
  tools?: Tool[];
  prompts?: Prompt[];
  resources?: Resource[];
  resourceTemplates?: ResourceTemplate[];
}

export type CapabilityType = 'tools' | 'prompts' | 'resources' | 'resourceTemplates';

export interface CapabilityItem {
  name: string;
  description?: string;
  type: CapabilityType;
  [key: string]: unknown;
}

export interface CapabilitiesState {
  loading: boolean;
  error: string | null;
  data: MCPCapabilities | null;
  filteredData: MCPCapabilities | null;
  searchTerm: string;
  selectedType: CapabilityType | 'all';
}