import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StreamableHTTPClientTransport} from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import {
  type CallToolRequest,
  CallToolResultSchema,
  type LoggingMessageNotification,
  LoggingMessageNotificationSchema
} from '@modelcontextprotocol/sdk/types.js';

import {Tool} from '../types/mcp';
import {t} from '../utils/i18n-utils';
import {toast} from '../utils/toast';


// Declare global constant injected by Vite
declare const __APP_VERSION__: string;

interface CallToolResult {
  content: Array<{
    type: string;
    text: string;
  }>;
  _meta?: {
    resumptionToken?: string;
  };
}

interface MCPClientConfig {
  name: string;
  prefix: string;
  onError?: (error: Error) => void;
  onNotification?: (notification: LoggingMessageNotification) => void;
}

class MCPService {
  private clients: Map<string, Client> = new Map();
  private transports: Map<string, StreamableHTTPClientTransport> = new Map();
  private sessionIds: Map<string, string> = new Map();
  private configs: Map<string, MCPClientConfig> = new Map();
  private lastEventIds: Map<string, string> = new Map();

  async connect(config: MCPClientConfig, authToken?: string, headerName: string = "Authorization"): Promise<Client> {
    const { name: serverName, prefix, onError, onNotification } = config;

    // If client exists, return it
    if (this.clients.has(serverName)) {
      return this.clients.get(serverName)!;
    }

    // Store config for reconnection
    this.configs.set(serverName, config);

    try {
      // Create transport and client
      const gatewayBaseUrl = window.RUNTIME_CONFIG?.VITE_MCP_GATEWAY_BASE_URL || '';
      const serverUrl = new URL(`${gatewayBaseUrl}${prefix}/mcp`, window.location.origin);

      // Build headers for auth
      let headers: Record<string, string> = {};
      if (authToken) {
        if (headerName.toLowerCase() !== "authorization") {
          headers[headerName] = authToken;
          headers["x-custom-auth-header"] = headerName;
        } else {
          headers["Authorization"] = `Bearer ${authToken}`;
        }
      }

      const transport = new StreamableHTTPClientTransport(
        serverUrl,
        {
          sessionId: this.sessionIds.get(serverName),
          requestInit: {
            headers: { ...headers },
          },
          reconnectionOptions: {
            maxReconnectionDelay: 30000,
            initialReconnectionDelay: 1000,
            reconnectionDelayGrowFactor: 1.5,
            maxRetries: 2,
          },
        }
      );

      const client = new Client({
        name: 'unla-web',
        version: __APP_VERSION__
      });

      // Set up error handler
      client.onerror = (error: unknown) => {
        onError?.(error as Error);
        toast.error(t('errors.mcp_server_error', { server: serverName, error: (error as Error).message }), {
          duration: 3000,
        });
      };

      // Set up notification handlers if provided
      if (onNotification) {
        client.setNotificationHandler(LoggingMessageNotificationSchema, onNotification);
      }

      // Connect client
      await client.connect(transport);

      // Store client, transport and session info
      this.clients.set(serverName, client);
      this.transports.set(serverName, transport);
      this.sessionIds.set(serverName, transport.sessionId!);

      return client;
    } catch (error) {
      toast.error(t('errors.connect_mcp_server', { server: serverName }), {
        duration: 3000,
      });
      throw error;
    }
  }

  async reconnect(serverName: string): Promise<Client | null> {
    const config = this.configs.get(serverName);
    if (!config) {
      toast.error(t('errors.no_server_config', { server: serverName }), {
        duration: 3000,
      });
      return null;
    }

    await this.disconnect(serverName);
    return this.connect(config);
  }

  async getTools(serverName: string): Promise<Tool[]> {
    const client = this.clients.get(serverName);
    if (!client) {
      throw new Error(`No client found for server ${serverName}`);
    }

    try {
      const result = await client.listTools();
      return result.tools;
    } catch (error) {
      toast.error(t('errors.get_tools_failed', { error: (error as Error).message }), {
        duration: 3000,
      });
      throw error;
    }
  }

  async callTool(
    serverName: string,
    toolName: string,
    args: Record<string, unknown>,
    onLastEventIdUpdate?: (eventId: string) => void
  ): Promise<string> {
    const client = this.clients.get(serverName);
    if (!client) {
      throw new Error(`No client found for server ${serverName}`);
    }

    try {
      const request: CallToolRequest = {
        method: 'tools/call',
        params: {
          name: toolName,
          arguments: args
        }
      };

      // Prepare options for request
      const options: { resumptionToken?: string } = this.lastEventIds.get(serverName)
        ? { resumptionToken: this.lastEventIds.get(serverName) }
        : {};

      const result = await client.request(
        request,
        CallToolResultSchema,
        options
      ) as CallToolResult;

      // Update last event ID if callback provided
      if (onLastEventIdUpdate && result._meta?.resumptionToken) {
        this.lastEventIds.set(serverName, result._meta.resumptionToken);
        onLastEventIdUpdate(result._meta.resumptionToken);
      }

      return result.content[0].text;
    } catch (error) {
      toast.error(t('errors.call_tool_failed', { toolName, error: (error as Error).message }), {
        duration: 3000,
      });
      throw error;
    }
  }

  async terminateSession(serverName: string): Promise<void> {
    const transport = this.transports.get(serverName);
    if (!transport) {
      return;
    }

    try {
      if (transport.sessionId) {
        await transport.terminateSession();
        this.sessionIds.delete(serverName);
        this.lastEventIds.delete(serverName);
      }
    } catch (error) {
      toast.error(t('errors.terminate_session', { error: (error as Error).message }), {
        duration: 3000,
      });
    }
  }

  async disconnect(serverName: string) {
    const client = this.clients.get(serverName);
    const transport = this.transports.get(serverName);

    if (client || transport) {
      try {
        // Try to terminate session first
        await this.terminateSession(serverName);

        // Then close transport
        if (transport) {
          await transport.close();
        }
      } catch (error) {
        toast.error(t('errors.disconnect_failed', { error: (error as Error).message }), {
          duration: 3000,
        });
      }

      // Clean up maps
      this.clients.delete(serverName);
      this.transports.delete(serverName);
    }
  }

  async disconnectAll() {
    const servers = Array.from(this.clients.keys());
    await Promise.all(servers.map(server => this.disconnect(server)));
  }

  getSessionId(serverName: string): string | undefined {
    return this.sessionIds.get(serverName);
  }
}

export const mcpService = new MCPService();

