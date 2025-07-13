import axios from 'axios';
import {t} from 'i18next';
import yaml from 'js-yaml';

import i18n from '../i18n';
import type {Gateway} from '../types/gateway';
import type {MCPConfigVersionListResponse} from '../types/mcp';
import {handleApiError} from '../utils/error-handler';
import {toast} from '../utils/toast';


// Create an axios instance with default config
const api = axios.create({
  baseURL: window.RUNTIME_CONFIG?.apiBaseUrl || '/api',
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor: add language and auth headers
api.interceptors.request.use(
  (config) => {
    // Add current language from i18n to X-Lang header
    config.headers['X-Lang'] = i18n.language || 'zh';

    // Add authorization token if available
    const token = window.localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Add response interceptor
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // Clear any existing token
      window.localStorage.removeItem('token');
      // Only redirect if not already on login page
      if (window.location.pathname !== '/login') {
        window.location.href = '/login';
      }
      // If already on login page, do not redirect, just clear token
    }
    return Promise.reject(error);
  }
);

// API endpoints
export const getMCPServers = async (tenantId?: number) => {
  try {
    const params = tenantId ? { tenantId } : {};
    const response = await api.get('/mcp/configs', { params });
    return response.data.data;
  } catch (error) {
    handleApiError(error, 'errors.fetch_mcp_servers');
    throw error;
  }
};

export const createMCPServer = async (config: string) => {
  try {
    const response = await api.post('/mcp/configs', config, {
      headers: {
        'Content-Type': 'application/yaml',
      },
    });
    return response.data;
  } catch (error) {
    handleApiError(error, 'errors.create_mcp_server');
    throw error;
  }
};

export const updateMCPServer = async (config: string) => {
  try {
    const response = await api.put(`/mcp/configs`, config, {
      headers: {
        'Content-Type': 'application/yaml',
      },
    });
    return response.data;
  } catch (error) {
    handleApiError(error, 'errors.update_mcp_server');
    throw error;
  }
};

export const deleteMCPServer = async (tenant: string, name: string) => {
  try {
    const response = await api.delete(`/mcp/configs/${tenant}/${name}`);
    return response.data;
  } catch (error) {
    handleApiError(error, 'errors.delete_mcp_server');
    throw error;
  }
};

export const exportMCPServer = async (server: Gateway) => {
  try {
    const name = server.name;
    const config = yaml.dump(server);

    const blob = new Blob([config], { type: 'application/yaml' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');

    toast.info(t('gateway.exporting'));
    a.href = url;
    a.download = `${name}.yaml`;
    a.click();
    window.URL.revokeObjectURL(url);
  } catch (error) {
    handleApiError(error, 'errors.export_mcp_server');
    throw error;
  }
};

export const syncMCPServers = async () => {
  try {
    const response = await api.post('/mcp/configs/sync');
    return response.data;
  } catch (error) {
    handleApiError(error, 'errors.sync_mcp_server');
    throw error;
  }
};

export const getChatMessages = async (sessionId: string, page: number = 1, pageSize: number = 20) => {
  try {
    const response = await api.get(`/chat/sessions/${sessionId}/messages`, {
      params: {
        page,
        pageSize,
      },
    });
    return response.data.data || response.data;
  } catch (error) {
    handleApiError(error, 'errors.fetch_chat_messages');
    throw error;
  }
};

export const getChatSessions = async () => {
  try {
    const response = await api.get('/chat/sessions');
    return response.data.data || response.data;
  } catch (error) {
    handleApiError(error, 'errors.fetch_chat_sessions');
    throw error;
  }
};

export const deleteChatSession = async (sessionId: string) => {
  try {
    const response = await api.delete(`/chat/sessions/${sessionId}`);
    return response.data.data || response.data;
  } catch (error) {
    handleApiError(error, 'errors.delete_chat_session');
    throw error;
  }
};

export const importOpenAPI = async (file: File, tenantName?: string, prefix?: string) => {
  try {
    const formData = new globalThis.FormData();
    formData.append('file', file);
    formData.append('tenantName', tenantName ?? '');
    formData.append('prefix', prefix ?? '');

    const response = await api.post('/openapi/import', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  } catch (error) {
    handleApiError(error, 'errors.import_openapi');
    throw error;
  }
};

// Tenant related API functions
export const getTenants = async () => {
  try {
    const response = await api.get('/auth/tenants');
    return response.data.data || response.data;
  } catch (error) {
    handleApiError(error, 'errors.fetch_tenants');
    throw error;
  }
};

export const getTenant = async (name: string) => {
  try {
    const response = await api.get(`/auth/tenants/${name}`);
    return response.data.data || response.data;
  } catch (error) {
    handleApiError(error, 'errors.fetch_tenant');
    throw error;
  }
};

interface Tenant {
  id: number;
  name: string;
  prefix: string;
  description: string;
  isActive: boolean;
}

export const createTenant = async (data: { name: string; prefix: string; description: string }) => {
  try {
    const { name, prefix, description } = data;

    // Check if prefix conflicts with existing ones
    const tenants = await getTenants();
    if (checkPrefixConflict(prefix, tenants.map((t: Tenant) => t.prefix))) {
      toast.error(t('errors.prefix_conflict'), {
        duration: 3000,
      });
      throw new Error('Prefix conflict');
    }

    // Ensure prefix starts with /
    let prefixed = prefix;
    if (prefixed && !prefixed.startsWith('/')) {
      prefixed = `/${prefixed}`;
    }

    // Check if it's a root level directory
    if (prefixed === '/') {
      toast.error(t('tenants.root_prefix_not_allowed'), {
        duration: 3000,
      });
      throw new Error('Root prefix not allowed');
    }

    // First get all tenants, check for prefix conflicts
    if (checkPrefixConflict(prefixed, tenants.map((t: Tenant) => t.prefix))) {
      toast.error(t('tenants.prefix_path_conflict'), {
        duration: 3000,
      });
      throw new Error('Prefix path conflict');
    }

    const response = await api.post('/auth/tenants', {
      name,
      prefix: prefixed,
      description,
    });
    toast.success(t('tenants.add_success'), {
      duration: 3000,
    });
    return response.data;
  } catch (error) {
    if (
      axios.isAxiosError(error) &&
      error.response?.data?.error &&
      !error.message.includes('Prefix')
    ) {
      toast.error(t('tenants.add_failed'), {
        duration: 3000,
      });
    }
    throw error;
  }
};

// Check if prefix conflicts with existing prefixes (same, parent path or child path)
const checkPrefixConflict = (prefix: string, existingPrefixes: string[], excludePrefix?: string): boolean => {
  for (const existingPrefix of existingPrefixes) {
    // Skip the prefix being edited (only used when updating)
    if (excludePrefix && existingPrefix === excludePrefix) {
      continue;
    }

    // Check if it's a parent path - e.g., /a is the parent path of /a/b
    if (prefix.startsWith(existingPrefix + '/') || existingPrefix === prefix) {
      return true;
    }

    // Check if it's a child path - e.g., /a/b is a child path of /a
    if (existingPrefix.startsWith(prefix + '/')) {
      return true;
    }
  }
  return false;
};

export const updateTenant = async (data: { name: string; prefix?: string; description?: string; isActive?: boolean }) => {
  try {
    const { name, prefix } = data;

    if (prefix) {
      // Get current tenant information
      const currentTenant = await getTenant(name);

      // Check for conflicts if prefix has changed
      if (currentTenant.prefix !== prefix) {
        const tenants = await getTenants();
        if (checkPrefixConflict(prefix, tenants.map((t: Tenant) => t.prefix), currentTenant.prefix)) {
          toast.error(t('errors.prefix_conflict'), {
            duration: 3000,
          });
          throw new Error('Prefix conflict');
        }
      }
    }

    const response = await api.put('/auth/tenants', data);
    toast.success(t('tenants.edit_success'), {
      duration: 3000,
    });
    return response.data;
  } catch (error) {
    if (axios.isAxiosError(error) && error.response?.status === 409) {
      // Check specific error message to distinguish between name conflict and prefix conflict
      const errorMessage = error.response.data?.error;
      if (errorMessage === "Tenant name already exists") {
        toast.error(t('tenants.name_conflict'), {
          duration: 3000,
        });
      } else {
        toast.error(t('tenants.prefix_conflict'), {
          duration: 3000,
        });
      }
    } else if (!(error instanceof Error &&
               (error.message === 'Root prefix not allowed' ||
                error.message === 'Prefix path conflict'))) {
      toast.error(t('errors.update_tenant'), {
        duration: 3000,
      });
    }
    throw error;
  }
};

export const deleteTenant = async (name: string) => {
  try {
    const response = await api.delete(`/auth/tenants/${name}`);
    toast.success(t('tenants.delete_success'), {
      duration: 3000,
    });
    return response.data;
  } catch (error) {
    if (axios.isAxiosError(error) && error.response?.data?.error) {
      toast.error(t('errors.delete_tenant'), {
        duration: 3000,
      });
    } else {
      toast.error(t('tenants.delete_failed'), {
        duration: 3000,
      });
    }
    throw error;
  }
};

// User related API functions
export const getUsers = async () => {
  try {
    const response = await api.get('/auth/users');
    return response.data.data || response.data;
  } catch (error) {
    toast.error(t('errors.fetch_users'), {
      duration: 3000,
    });
    throw error;
  }
};

export const getUser = async (username: string) => {
  try {
    const response = await api.get(`/auth/users/${username}`);
    return response.data.data || response.data;
  } catch (error) {
    toast.error(t('errors.fetch_user'), {
      duration: 3000,
    });
    throw error;
  }
};

export const createUser = async (data: {
  username: string;
  password: string;
  role: 'admin' | 'normal';
  tenantIds?: number[];
}) => {
  try {
    console.log('API: Creating user with payload:', JSON.stringify(data, null, 2));
    const response = await api.post('/auth/users', data);
    toast.success(t('users.add_success'), {
      duration: 3000,
    });
    return response.data;
  } catch (error) {
    console.error('API: User creation error:', error);
    if (axios.isAxiosError(error)) {
      console.error('API: Error response:', error.response?.data);
      console.error('API: Error status:', error.response?.status);
    }
    toast.error(t('users.add_failed'), {
      duration: 3000,
    });
    throw error;
  }
};

export const updateUser = async (data: {
  username: string;
  password?: string;
  role?: 'admin' | 'normal';
  isActive?: boolean;
  tenantIds?: number[];
}) => {
  try {
    const response = await api.put('/auth/users', data);
    toast.success(t('users.edit_success'), {
      duration: 3000,
    });
    return response.data;
  } catch (error) {
    toast.error(t('users.edit_failed'), {
      duration: 3000,
    });
    throw error;
  }
};

export const deleteUser = async (username: string) => {
  try {
    const response = await api.delete(`/auth/users/${username}`);
    toast.success(t('users.delete_success'), {
      duration: 3000,
    });
    return response.data;
  } catch (error) {
    toast.error(t('users.delete_failed'), {
      duration: 3000,
    });
    throw error;
  }
};

export const toggleUserStatus = async (username: string, isActive: boolean) => {
  try {
    const response = await api.put('/auth/users', {
      username,
      isActive,
    });
    toast.success(isActive ? t('users.enable_success') : t('users.disable_success'), {
      duration: 3000,
    });
    return response.data;
  } catch (error) {
    toast.error(isActive ? t('users.enable_failed') : t('users.disable_failed'), {
      duration: 3000,
    });
    throw error;
  }
};

// Get user details and associated tenants
export const getUserWithTenants = async (username: string) => {
  try {
    const response = await api.get(`/auth/users/${username}`);
    return response.data.data || response.data;
  } catch (error) {
    toast.error(t('errors.fetch_user'), {
      duration: 3000,
    });
    throw error;
  }
};

// Get current user's authorized tenants
export const getUserAuthorizedTenants = async () => {
  const response = await api.get('/auth/user');
  const data = response.data.data || response.data;
  return data.tenants || [];
};

// Update user tenant associations
export const updateUserTenants = async (userId: number, tenantIds: number[]) => {
  try {
    const response = await api.put('/auth/users/tenants', {
      userId,
      tenantIds
    });
    toast.success(t('users.update_tenants_success'), {
      duration: 3000,
    });
    return response.data;
  } catch (error) {
    toast.error(t('users.update_tenants_failed'), {
      duration: 3000,
    });
    throw error;
  }
};

// MCP Config Version APIs
export const getMCPConfigNames = async (tenant?: string): Promise<string[]> => {
  try {
    const response = await api.get('/mcp/configs/names', {
      params: {
        includeDeleted: true,
        tenant
      }
    });
    return response.data.data || [];
  } catch (error) {
    handleApiError(error, 'errors.fetch_config_names');
    throw error;
  }
};

export const getMCPConfigVersions = async (tenant?: string, name?: string): Promise<MCPConfigVersionListResponse> => {
  try {
    const params: Record<string, string> = {};
    if (tenant) {
      params.tenant = tenant;
    }
    if (name) {
      params.names = name;
    }
    const response = await api.get('/mcp/configs/versions', { params });
    return response.data;
  } catch (error) {
    handleApiError(error, 'errors.fetch_config_versions');
    throw error;
  }
};

export const setActiveVersion = async (tenant: string, name: string, version: number): Promise<void> => {
  try {
    await api.post(`/mcp/configs/${tenant}/${name}/versions/${version}/active`);
  } catch (error) {
    handleApiError(error, 'errors.set_active_version');
    throw error;
  }
};

export const getCurrentUser = async () => {
  return await api.get('/auth/user/info');
};

export const updateChatSessionTitle = async (sessionId: string, title: string) => {
  try {
    const response = await api.put(`/chat/sessions/${sessionId}/title`, { title });
    return response.data.data || response.data;
  } catch (error) {
    handleApiError(error, 'errors.rename_chat_session');
    throw error;
  }
};

export const saveChatMessage = async (message: {
  id: string;
  session_id: string;
  content: string;
  sender: 'user' | 'bot' | 'system';
  timestamp: string;
  reasoning_content?: string;
  toolCalls?: Array<{
    id: string;
    type: string;
    function: {
      name: string;
      arguments: string;
    };
  }>;
  toolResult?: {
    toolCallId: string;
    name: string;
    result: unknown;
  };
}) => {
  try {
    const response = await api.post('/chat/messages', {
      ...message,
      toolCalls: message.toolCalls ? JSON.stringify(message.toolCalls) : undefined,
      toolResult: message.toolResult ? JSON.stringify(message.toolResult) : undefined,
    });
    return response.data.data || response.data;
  } catch (error) {
    handleApiError(error, 'errors.save_chat_message');
    throw error;
  }
};

export default api;
