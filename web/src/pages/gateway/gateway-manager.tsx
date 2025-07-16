import {
  Button,
  Card,
  CardBody,
  Chip,
  Dropdown,
  DropdownItem,
  DropdownMenu,
  DropdownTrigger,
  Modal,
  ModalBody,
  ModalContent,
  ModalFooter,
  ModalHeader,
  Popover,
  PopoverContent,
  PopoverTrigger,
  Select,
  SelectItem,
  Tab,
  Table,
  TableBody,
  TableCell,
  TableColumn,
  TableHeader,
  TableRow,
  Tabs,
  useDisclosure
} from "@heroui/react";
import copy from 'copy-to-clipboard';
import yaml from 'js-yaml';
import {configureMonacoYaml} from 'monaco-yaml';
import React from 'react';
import {useTranslation} from 'react-i18next';
import {useNavigate} from 'react-router-dom';

import {ConfigEditor} from './components/ConfigEditor';
import OpenAPIImport from './components/OpenAPIImport';
import {defaultConfig} from './constants/defaultConfig';

import LocalIcon from '@/components/LocalIcon';
import {
  createMCPServer,
  deleteMCPServer,
  exportMCPServer,
  getMCPServers,
  getTenant,
  getUserAuthorizedTenants,
  syncMCPServers,
  updateMCPServer
} from '@/services/api';
import type {Gateway, ServerConfig, RouterConfig, Tenant, YAMLConfig} from '@/types/gateway';
import {toast} from '@/utils/toast';



declare global {
  interface Window {
    monaco: {
      languages: {
        yaml: {
          yamlDefaults: {
            setDiagnosticsOptions: (options: { enableSchemaRequest: boolean; schemas: Array<{ uri: string; fileMatch: string[] }> }) => void;
          };
        };
      };
    };
  }
}

const RUNTIME_CONFIG = (window.RUNTIME_CONFIG || {}) as Record<string, unknown>;

// Helper to get the gateway base URL
const getGatewayBaseUrl = () => {
  let base = RUNTIME_CONFIG.VITE_MCP_GATEWAY_BASE_URL as string;
  if (!base) return '';
  // Remove trailing slash if present
  base = base.replace(/\/+$/, '');
  if (base.startsWith('http')) {
    return base;
  }
  // Remove trailing slash from window.location.origin just in case
  const origin = window.location.origin.replace(/\/+$/, '');
  // Ensure base starts with a slash
  if (!base.startsWith('/')) {
    base = '/' + base;
  }
  return `${origin}${base}`;
};

// Helper to get direct gateway base URL using modifier
const getDirectGatewayBaseUrl = () => {
  let modifier = (window.RUNTIME_CONFIG?.VITE_DIRECT_MCP_GATEWAY_MODIFIER as string) || ':5235';
  const origin = window.location.origin.replace(/\/+$/, '');

  if (modifier.startsWith('http')) {
    return modifier.replace(/\/+$/, '');
  }

  if (!modifier.startsWith('/') && !modifier.startsWith(':')) {
    modifier = '/' + modifier;
  }

  const originWithoutPort = origin.replace(/:\d+$/, '');
  return `${originWithoutPort}${modifier}`.replace(/\/+$/, '');
};

export function GatewayManager() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const {isOpen, onOpen, onOpenChange} = useDisclosure();
  const {isOpen: isCreateOpen, onOpen: onCreateOpen, onOpenChange: onCreateOpenChange} = useDisclosure();
  const {isOpen: isImportOpen, onOpen: onImportOpen, onOpenChange: onImportOpenChange} = useDisclosure();
  const [mcpservers, setMCPServers] = React.useState<Gateway[]>([]);
  const [currentMCPServer, setCurrentMCPServer] = React.useState<Gateway | null>(null);
  const [editConfig, setEditConfig] = React.useState('');
  const [newConfig, setNewConfig] = React.useState('');
  const [isLoading, setIsLoading] = React.useState(true);
  const [tenants, setTenants] = React.useState<Tenant[]>([]);
  const [selectedTenant, setSelectedTenant] = React.useState<string | undefined>(undefined);
  const [viewMode, setViewMode] = React.useState<string>('table');
  const [isDark, setIsDark] = React.useState(() => {
    return document.documentElement.classList.contains('dark');
  });
  const [isRoutingModalOpen, setIsRoutingModalOpen] = React.useState(false);
  const [isToolsModalOpen, setIsToolsModalOpen] = React.useState(false);
  const [currentModalServer, setCurrentModalServer] = React.useState<Gateway | null>(null);
  const [isDeleteModalOpen, setIsDeleteModalOpen] = React.useState(false);
  const [serverToDelete, setServerToDelete] = React.useState<Gateway | null>(null);
  const [copiedStates, setCopiedStates] = React.useState<{ [key: string]: boolean }>({});

  // Listen for theme changes
  React.useEffect(() => {
    const observer = new globalThis.MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        if (mutation.attributeName === 'class') {
          setIsDark(document.documentElement.classList.contains('dark'));
        }
      });
    });

    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['class']
    });

    return () => observer.disconnect();
  }, []);

  // Configure Monaco YAML
  React.useEffect(() => {
    const monaco = window.monaco;
    if (monaco) {
      configureMonacoYaml(monaco, {
        enableSchemaRequest: true,
        schemas: [
          {
            uri: '',
            fileMatch: ['*.yml', '*.yaml'],
          },
        ],
      });
    }
  }, []);

  // Get MCP servers list
  React.useEffect(() => {
    const fetchMCPServers = async () => {
      try {
        setIsLoading(true);
        // Use the selected tenant for filtering if available
        const tenant = tenants.find(t => t.name === selectedTenant);
        const tenantId = tenant?.id;
        const servers = await getMCPServers(tenantId);
        setMCPServers(servers);
      } catch {
        toast.error(t('errors.fetch_mcp_servers'));
      } finally {
        setIsLoading(false);
      }
    };

    fetchMCPServers();
  }, [t, selectedTenant, tenants]);

  // Get user's authorized tenants
  React.useEffect(() => {
    const fetchAuthorizedTenants = async () => {
      try {
        const tenantsData = await getUserAuthorizedTenants();
        setTenants(tenantsData);
      } catch (error) {
        // Check if it's an authentication error
        if (error && typeof error === 'object' && 'response' in error) {
          const axiosError = error as { response: { status: number } };
          if (axiosError.response.status === 401) {
            toast.error(t('errors.authentication_required'));
          } else {
            toast.error(t('errors.fetch_authorized_tenants'));
          }
        } else {
          toast.error(t('errors.fetch_authorized_tenants'));
        }
      }
    };

    fetchAuthorizedTenants();
  }, [t]);

  const handleEdit = (server: Gateway) => {
    // Ensure all necessary fields exist with default values
    const completeConfig = {
      ...defaultConfig,
      ...server,
      mcpServers: server.mcpServers || [],
      tools: server.tools || [],
      servers: server.servers || [],
      routers: server.routers || []
    };
    setCurrentMCPServer(completeConfig);
    setEditConfig(yaml.dump(completeConfig));
    onOpen();
  };

  // Validate if router prefixes start with tenant prefix
  const validateRouterPrefixes = async (config: string): Promise<boolean> => {
    try {
      const parsedConfig = yaml.load(config) as { tenant: string, routers: Array<{ prefix: string }> };

      if (!parsedConfig.tenant || !parsedConfig.routers) {
        return true; // Skip validation if tenant or routers are missing
      }

      // Get tenant information
      const tenant = await getTenant(parsedConfig.tenant);
      if (!tenant) {
        return true; // Skip validation if tenant not found
      }

      // Normalize tenant prefix
      let tenantPrefix = tenant.prefix;
      if (!tenantPrefix.startsWith('/')) {
        tenantPrefix = '/' + tenantPrefix;
      }
      tenantPrefix = tenantPrefix.endsWith('/') ? tenantPrefix.slice(0, -1) : tenantPrefix;

      // Check if all router prefixes start with the tenant prefix
      for (const router of parsedConfig.routers) {
        // Normalize router prefix
        let routerPrefix = router.prefix;
        if (!routerPrefix.startsWith('/')) {
          routerPrefix = '/' + routerPrefix;
        }
        routerPrefix = routerPrefix.endsWith('/') ? routerPrefix.slice(0, -1) : routerPrefix;
        // Router prefix must start with tenant prefix followed by a slash and not be empty
        if (!routerPrefix.startsWith(tenantPrefix + '/')) {
          toast.error(t('errors.router_prefix_error'), {
            duration: 3000,
          });
          return false;
        }

        // Check if there is content after tenant prefix
        const remainingPath = routerPrefix.slice(tenantPrefix.length + 1);
        if (!remainingPath) {
          toast.error(t('errors.router_prefix_error'), {
            duration: 3000,
          });
          return false;
        }
      }

      return true;
    } catch {
      toast.error(t('errors.validate_router_prefix_failed'), {
        duration: 3000,
      });
      return false;
    }
  };

  const handleSave = async () => {
    try {
      // Parse YAML to check format and handle null values
      const parsedConfig = yaml.load(editConfig) as YAMLConfig;

      // Validate name length
      if (parsedConfig.name && typeof parsedConfig.name === 'string' && parsedConfig.name.length > 50) {
        toast.error(t('gateway.name_length_error'));
        return;
      }

      // Remove null fields from the config
      const fieldsToCheck = ['mcpServers', 'tools', 'servers', 'routers'];
      fieldsToCheck.forEach(field => {
        if (parsedConfig[field] === null) {
          delete parsedConfig[field];
        }
      });

      // Convert back to YAML string
      const cleanedConfig = yaml.dump(parsedConfig);

      // Validate router prefix
      const isValidPrefix = await validateRouterPrefixes(cleanedConfig);
      if (!isValidPrefix) {
        return;
      }

      if (currentMCPServer) {
        await updateMCPServer(cleanedConfig);
        const tenant = tenants.find(t => t.name === selectedTenant);
        const tenantId = tenant?.id;
        const servers = await getMCPServers(tenantId);
        setMCPServers(servers);
        toast.success(t('gateway.edit_success'));
      }
      onOpenChange();
    } catch {
      toast.error(t('gateway.edit_failed'));
    }
  };

  const handleDelete = async (server: Gateway) => {
    setServerToDelete(server);
    setIsDeleteModalOpen(true);
  };

  const confirmDelete = async () => {
    if (!serverToDelete) return;

    try {
      await deleteMCPServer(serverToDelete.tenant, serverToDelete.name);
      const tenant = tenants.find(t => t.name === selectedTenant);
      const tenantId = tenant?.id;
      const servers = await getMCPServers(tenantId);
      setMCPServers(servers);
      toast.success(t('gateway.delete_success'));
    } catch {
      toast.error(t('gateway.delete_failed'));
    } finally {
      setIsDeleteModalOpen(false);
      setServerToDelete(null);
    }
  };

   const handleExport = async (server: Gateway) => {
    try {
      toast.success(t('gateway.exporting'));
      await exportMCPServer(server);
      toast.success(t('gateway.export_success'));
    } catch {
      toast.error(t('gateway.export_failed'));
    }
  };

  const handleSync = async () => {
    try {
      setIsLoading(true);
      await syncMCPServers();
      const tenant = tenants.find(t => t.name === selectedTenant);
      const tenantId = tenant?.id;
      const servers = await getMCPServers(tenantId);
      setMCPServers(servers);
      toast.success(t('gateway.sync_success'));
    } catch {
      toast.error(t('gateway.sync_failed'));
    } finally {
      setIsLoading(false);
    }
  };

  const handleCopyToClipboard = (text: string) => {
    try {
      const success = copy(text);
      if (success) {
        toast.success(t('common.copied', { text }));
      } else {
        toast.error(t('common.copy_failed'));
      }
    } catch {
      toast.error(t('common.copy_failed'));
    }
  };

  const handleCreate = async () => {
    try {
      // Parse YAML to check format and handle null values
      const parsedConfig = yaml.load(newConfig) as YAMLConfig;

      // Validate name length
      if (parsedConfig.name && typeof parsedConfig.name === 'string' && parsedConfig.name.length > 50) {
        toast.error(t('gateway.name_length_error'));
        return;
      }

      // Remove null fields from the config
      const fieldsToCheck = ['mcpServers', 'tools', 'servers', 'routers'];
      fieldsToCheck.forEach(field => {
        if (parsedConfig[field] === null) {
          delete parsedConfig[field];
        }
      });

      // Convert back to YAML string
      const cleanedConfig = yaml.dump(parsedConfig);

      // Validate router prefix
      const isValidPrefix = await validateRouterPrefixes(cleanedConfig);
      if (!isValidPrefix) {
        return;
      }

      // If YAML is valid, proceed with creation
      await createMCPServer(cleanedConfig);
      const tenant = tenants.find(t => t.name === selectedTenant);
      const tenantId = tenant?.id;
      const servers = await getMCPServers(tenantId);
      setMCPServers(servers);
      onCreateOpenChange();
      setNewConfig('');
      toast.success(t('gateway.add_success'));
    } catch {
      toast.error(t('gateway.add_failed'));
    }
  };

  const handleImportSuccess = async () => {
    try {
      const tenant = tenants.find(t => t.name === selectedTenant);
      const tenantId = tenant?.id;
      const servers = await getMCPServers(tenantId);
      setMCPServers(servers);
      onImportOpenChange();
      toast.success(t('gateway.import_success'));
    } catch {
      toast.error(t('gateway.import_failed'));
    }
  };

  const editorOptions = {
    minimap: { enabled: false },
    fontSize: 14,
    lineNumbers: 'on',
    roundedSelection: false,
    scrollBeyondLastLine: false,
    readOnly: false,
    automaticLayout: true,
    ...(isDark ? {
      'editor.background': '#1E2228',
      'editor.foreground': '#E5E7EB',
      'editor.lineHighlightBackground': '#23272E',
      'editor.selectionBackground': '#4C6BCF40',
      'editor.inactiveSelectionBackground': '#4C6BCF20',
      'editor.lineHighlightBorder': '#2D3238',
      'editorCursor.foreground': '#4C6BCF',
      'editorWhitespace.foreground': '#4B5563',
    } : {
      'editor.background': '#F8F9FA',
      'editor.foreground': '#0B0F1A',
      'editor.lineHighlightBackground': '#F1F3F5',
      'editor.selectionBackground': '#4C6BCF40',
      'editor.inactiveSelectionBackground': '#4C6BCF20',
      'editor.lineHighlightBorder': '#E5E7EB',
      'editorCursor.foreground': '#4C6BCF',
      'editorWhitespace.foreground': '#A6B6E8',
    })
  };

  const handleTenantSelectionChange = (tenantName: string) => {
    setSelectedTenant(tenantName);
  };

  const handleCopyWithIcon = (text: string, key: string) => {
    handleCopyToClipboard(text);
    setCopiedStates(prev => ({ ...prev, [key]: true }));
    window.setTimeout(() => {
      setCopiedStates(prev => ({ ...prev, [key]: false }));
    }, 1000);
  };

  return (
    <div className="container mx-auto p-4 pb-10 h-[calc(100vh-5rem)] flex flex-col overflow-y-scroll scrollbar-hide">
      <div className="flex justify-between items-center mb-4">
        <h1 className="text-2xl font-bold">{t('gateway.title')}</h1>
        <div className="flex gap-2">
          <Button
            color="primary"
            onPress={onCreateOpen}
            startContent={<LocalIcon icon="material-symbols:add" />}
            aria-label={t('gateway.add')}
            isDisabled={isOpen || isCreateOpen || isImportOpen}
          >
            {t('gateway.add')}
          </Button>
          <Button
            color="secondary"
            variant="flat"
            onPress={onImportOpen}
            startContent={<LocalIcon icon="material-symbols:upload" />}
            className="bg-purple-500 hover:bg-purple-600 text-white"
            aria-label={t('gateway.import_openapi')}
            isDisabled={isOpen || isCreateOpen || isImportOpen}
          >
            {t('gateway.import_openapi')}
          </Button>
          <Button
            color="default"
            onPress={handleSync}
            isLoading={isLoading}
            startContent={<LocalIcon icon="material-symbols:sync" />}
            aria-label={t('gateway.sync')}
            isDisabled={isOpen || isCreateOpen || isImportOpen}
          >
            {t('gateway.sync')}
          </Button>
        </div>
      </div>

      <div className="flex justify-between items-center mb-4">
        <div className="max-w-lg">
          <Select
            label={t('gateway.select_tenant')}
            selectedKeys={selectedTenant ? [selectedTenant] : []}
            onSelectionChange={(keys) => {
              const selectedKey = Array.from(keys)[0] as string;
              if (selectedKey) {
                handleTenantSelectionChange(selectedKey);
              }
            }}
            className="w-full min-w-56"
          >
            {tenants.map((tenant) => (
              <SelectItem
                key={tenant.name}
                textValue={`${tenant.name}(${tenant.prefix})`}
              >
                {tenant.name}({tenant.prefix})
              </SelectItem>
            ))}
          </Select>
        </div>

        <Tabs
          aria-label={t('gateway.view_mode')}
          selectedKey={viewMode}
          onSelectionChange={(key) => setViewMode(key as string)}
          size="sm"
          classNames={{
            tabList: "bg-default-100 p-1 rounded-lg"
          }}
          isDisabled={isOpen || isCreateOpen || isImportOpen}
        >
          <Tab
            key="card"
            title={
              <div className="flex items-center gap-1">
                <LocalIcon icon="material-symbols:grid-view" className="text-lg" />
                <span>{t('gateway.card_view')}</span>
              </div>
            }
          />
          <Tab
            key="table"
            title={
              <div className="flex items-center gap-1">
                <LocalIcon icon="material-symbols:table-rows" className="text-lg" />
                <span>{t('gateway.table_view')}</span>
              </div>
            }
          />
        </Tabs>
      </div>

      <div className={`flex-1 ${isOpen || isCreateOpen || isImportOpen ? 'pointer-events-none opacity-50' : ''}`}>
        {isLoading ? (
          <div className="flex justify-center items-center h-32">
            <LocalIcon icon="lucide:loader-2" className="animate-spin text-2xl" />
          </div>
        ) : viewMode === 'card' ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
            {(mcpservers || []).map((server) => (
              <Card key={`${server.tenant}-${server.name}`} className="w-full hover:shadow-lg transition-shadow bg-card">
                <CardBody className="flex flex-col gap-3 p-4">
                  <div className="flex justify-between items-center">
                    <div className="flex flex-col gap-1">
                      <h3 className="text-lg font-semibold truncate">{server.name}</h3>
                      {server.tenant && (
                        <div className="flex items-center gap-1">
                          <LocalIcon icon="lucide:building" className="text-sm text-default-500" />
                          <span className="text-sm text-default-500">{t('gateway.tenant_name')}:</span>
                          <Chip
                            color="primary"
                            variant="flat"
                            size="sm"
                            className="cursor-pointer hover:opacity-80 select-none pr-2"
                            onClick={() => handleCopyToClipboard(server.tenant || '')}
                            aria-label={`${t('common.copy')} ${server.tenant}`}
                          >
                            {server.tenant}
                          </Chip>
                        </div>
                      )}
                    </div>
                    <div className="flex gap-2">
                      <Button
                        isIconOnly
                        color="primary"
                        variant="light"
                        size="sm"
                        onPress={() => handleEdit(server)}
                        aria-label={t('gateway.edit')}
                        isDisabled={isOpen || isCreateOpen || isImportOpen}
                      >
                        <LocalIcon icon="lucide:edit" className="text-lg" />
                      </Button>
                      <Dropdown>
                        <DropdownTrigger>
                          <Button
                            isIconOnly
                            color="danger"
                            variant="light"
                            size="sm"
                            aria-label={t('common.actions')}
                            isDisabled={isOpen || isCreateOpen || isImportOpen}
                          >
                            <LocalIcon icon="lucide:more-vertical" className="text-lg" />
                          </Button>
                        </DropdownTrigger>
                        <DropdownMenu aria-label={t('common.actions')}>
                          <DropdownItem
                            key="delete"
                            className="text-danger"
                            color="danger"
                            startContent={<LocalIcon icon="lucide:trash-2" />}
                            onPress={() => handleDelete(server)}
                          >
                            {t('gateway.delete')}
                          </DropdownItem>
                          <DropdownItem
                            key="export"
                            className="text-green-500"
                            color="primary"
                            startContent={<LocalIcon icon="lucide:download" />}
                            onPress={() => handleExport(server)}
                          >
                            {t('gateway.export')}
                          </DropdownItem>
                        </DropdownMenu>
                      </Dropdown>
                    </div>
                  </div>

                  {server && (
                    <div className="space-y-3">
                      {(server.servers || []).map((serverConfig) => {
                        const sc = serverConfig as ServerConfig;
                        return (
                          <div key={`${server.tenant}-${server.name}-config-${sc.name}`} className="space-y-3">
                            <div>
                              <h4 className="text-sm font-semibold truncate">{sc.name}</h4>
                              <p className="text-sm text-default-500 line-clamp-2">{sc.description}</p>
                            </div>

                            <div className="space-y-2">
                              <h4 className="text-sm font-semibold">{t('gateway.routing_config')}</h4>
                              <div className="flex flex-col gap-2">
                                {(server.routers || []).map((router: RouterConfig, idx: number) => (
                                  <div key={`${server.tenant}-${server.name}-router-${router.prefix}-${idx}`} className="flex items-center gap-2">
                                    <Popover placement="right">
                                      <PopoverTrigger>
                                        <Chip
                                          color="primary"
                                          variant="flat"
                                          size="sm"
                                          className="cursor-pointer hover:opacity-80 select-none"
                                          aria-label={`${t('common.copy')} ${router.prefix}`}
                                        >
                                          {router.prefix}
                                        </Chip>
                                      </PopoverTrigger>
                                      <PopoverContent className="max-w-[500px]">
                                        <div className="px-1 py-2 space-y-4">
                                          <div className="space-y-2">
                                            <h4 className="text-sm font-semibold">AllInOne - Nginx:</h4>
                                            <div className="space-y-1">
                                              <div className="flex items-center gap-2">
                                                <span className="text-xs text-default-500">SSE:</span>
                                                <code className="text-xs bg-default-100 px-1 py-1 rounded flex-1 break-all">
                                                  {`${getGatewayBaseUrl()}${router.prefix}/sse`}
                                                </code>
                                                <Button
                                                  isIconOnly
                                                  size="sm"
                                                  variant="light"
                                                  onPress={() => handleCopyWithIcon(
                                                    `${getGatewayBaseUrl()}${router.prefix}/sse`,
                                                    `nginx-sse-${server.name}-${idx}`
                                                  )}
                                                >
                                                  <LocalIcon icon={copiedStates[`nginx-sse-${server.name}-${idx}`] ? "lucide:check" : "lucide:copy"} className="text-sm" />
                                                </Button>
                                              </div>
                                              <div className="flex items-center gap-2">
                                                <span className="text-xs text-default-500">Streamable HTTP:</span>
                                                <code className="text-xs bg-default-100 px-1 py-1 rounded flex-1 break-all">
                                                  {`${getGatewayBaseUrl()}${router.prefix}/mcp`}
                                                </code>
                                                <Button
                                                  isIconOnly
                                                  size="sm"
                                                  variant="light"
                                                  onPress={() => handleCopyWithIcon(
                                                    `${getGatewayBaseUrl()}${router.prefix}/mcp`,
                                                    `nginx-mcp-${server.name}-${idx}`
                                                  )}
                                                >
                                                  <LocalIcon icon={copiedStates[`nginx-mcp-${server.name}-${idx}`] ? "lucide:check" : "lucide:copy"} className="text-sm" />
                                                </Button>
                                              </div>
                                            </div>
                                          </div>

                                          <div className="space-y-2">
                                            <h4 className="text-sm font-semibold">{t('gateway.direct_to_mcp_gateway')}</h4>
                                            <div className="space-y-1">
                                              <div className="flex items-center gap-2">
                                                <span className="text-xs text-default-500">SSE:</span>
                                                <code className="text-xs bg-default-100 px-1 py-1 rounded flex-1 break-all">
                                                  {`${getDirectGatewayBaseUrl()}${router.prefix}/sse`}
                                                </code>
                                                <Button
                                                  isIconOnly
                                                  size="sm"
                                                  variant="light"
                                                  onPress={() => handleCopyWithIcon(
                                                    `${getDirectGatewayBaseUrl()}${router.prefix}/sse`,
                                                    `direct-sse-${server.name}-${idx}`
                                                  )}
                                                >
                                                  <LocalIcon icon={copiedStates[`direct-sse-${server.name}-${idx}`] ? "lucide:check" : "lucide:copy"} className="text-sm" />
                                                </Button>
                                              </div>
                                              <div className="flex items-center gap-2">
                                                <span className="text-xs text-default-500">Streamable HTTP:</span>
                                                <code className="text-xs bg-default-100 px-1 py-1 rounded flex-1 break-all">
                                                  {`${getDirectGatewayBaseUrl()}${router.prefix}/mcp`}
                                                </code>
                                                <Button
                                                  isIconOnly
                                                  size="sm"
                                                  variant="light"
                                                  onPress={() => handleCopyWithIcon(
                                                    `${getDirectGatewayBaseUrl()}${router.prefix}/mcp`,
                                                    `direct-mcp-${server.name}-${idx}`
                                                  )}
                                                >
                                                  <LocalIcon icon={copiedStates[`direct-mcp-${server.name}-${idx}`] ? "lucide:check" : "lucide:copy"} className="text-sm" />
                                                </Button>
                                              </div>
                                            </div>
                                          </div>

                                          <div className="text-xs text-default-500 border-t pt-2">
                                            {t('gateway.url_access_note')}
                                          </div>
                                        </div>
                                      </PopoverContent>
                                    </Popover>
                                    <LocalIcon icon="lucide:arrow-right" className="text-sm" />
                                    <Chip
                                      variant="flat"
                                      size="sm"
                                      className="cursor-pointer hover:opacity-80 select-none"
                                      onClick={() => handleCopyToClipboard(router.server)}
                                      aria-label={`${t('common.copy')} ${router.server}`}
                                    >
                                      {router.server}
                                    </Chip>
                                  </div>
                                ))}
                              </div>
                            </div>

                            {server.mcpServers && server.mcpServers.length > 0 && (
                              <div className="space-y-2">
                                <h4 className="text-sm font-semibold">{t('gateway.backend_config')}</h4>
                                <div className="flex flex-col gap-2">
                                  {server.mcpServers.map((mcpServer, idx) => (
                                    <div key={`${server.tenant}-${server.name}-backend-${mcpServer.name}-${idx}`} className="flex flex-col gap-1 p-2 border border-default-200 rounded-md">
                                      <div className="flex items-center gap-2">
                                        <span className="text-sm font-medium">{mcpServer.name}</span>
                                        <Chip size="sm" variant="flat" color="warning" aria-label={`Type: ${mcpServer.type}`}>
                                          {mcpServer.type}
                                        </Chip>
                                      </div>
                                      {mcpServer.type === 'stdio' && (
                                        <div className="text-xs">
                                          <div className="flex items-center gap-1">
                                            <span className="font-medium">Command:</span>
                                            <code className="bg-default-100 px-1 rounded">{mcpServer.command} {mcpServer.args?.join(' ')}</code>
                                          </div>
                                          {mcpServer.env && Object.entries(mcpServer.env).map(([key, value]) => (
                                            <div key={key} className="text-xs truncate">
                                              <span className="text-default-500">{key}:</span> {String(value)}
                                            </div>
                                          ))}
                                        </div>
                                      )}
                                      {(mcpServer.type === 'sse' || mcpServer.type === 'streamable-http') && mcpServer.url && (
                                        <div className="text-xs">
                                          <div className="flex items-start gap-1">
                                            <span className="font-medium mt-1">URL:</span>
                                            <code className="bg-default-100 px-1 py-1 rounded break-all">{mcpServer.url}</code>
                                          </div>
                                        </div>
                                      )}
                                    </div>
                                  ))}
                                </div>
                              </div>
                            )}

                            <div className="space-y-3">
                              <div>
                                <h4 className="text-sm font-semibold mb-1">{t('gateway.enabled_tools')}:</h4>
                                <div className="flex flex-wrap gap-1">
                                  {(sc.allowedTools ?? []).map((tool: string) => (
                                    <Chip
                                      key={tool}
                                      variant="flat"
                                      color="success"
                                      size="sm"
                                      className="truncate cursor-pointer hover:opacity-80 select-none"
                                      onClick={() => handleCopyToClipboard(tool)}
                                      aria-label={`${t('common.copy')} ${tool}`}
                                    >
                                      {tool}
                                    </Chip>
                                  ))}
                                </div>
                              </div>

                              <div>
                                <h4 className="text-sm font-semibold mb-1">{t('gateway.all_tools')}:</h4>
                                <div className="flex flex-wrap gap-1">
                                  {(server.tools || []).map((tool) => {
                                    const toolConfig = tool as import('@/types/gateway').ToolConfig;
                                    return (
                                      <Chip
                                        key={toolConfig.name}
                                        variant="flat"
                                        color="default"
                                        size="sm"
                                        className="truncate cursor-pointer hover:opacity-80 select-none"
                                        onClick={() => handleCopyToClipboard(toolConfig.name)}
                                        aria-label={`${t('common.copy')} ${toolConfig.name}`}
                                      >
                                        {toolConfig.name}
                                      </Chip>
                                    );
                                  })}
                                </div>
                              </div>
                            </div>
                          </div>
                        );
                      })}

                      {(!server.servers || server.servers.length === 0) && (
                        <div className="space-y-3">
                          {server.routers && server.routers.length > 0 && (
                            <div className="space-y-2">
                              <h4 className="text-sm font-semibold">{t('gateway.routing_config')}</h4>
                              <div className="flex flex-col gap-2">
                                {server.routers.map((router: RouterConfig, idx: number) => (
                                  <div key={`${server.tenant}-${server.name}-router-list-${router.prefix}-${idx}`} className="flex items-center gap-2">
                                    <Popover placement="right">
                                      <PopoverTrigger>
                                        <Chip
                                          color="primary"
                                          variant="flat"
                                          size="sm"
                                          className="cursor-pointer hover:opacity-80 select-none"
                                          aria-label={`${t('common.copy')} ${router.prefix}`}
                                        >
                                          {router.prefix}
                                        </Chip>
                                      </PopoverTrigger>
                                      <PopoverContent className="max-w-[500px]">
                                        <div className="px-1 py-2 space-y-4">
                                          <div className="space-y-2">
                                            <h4 className="text-sm font-semibold">AllInOne - Nginx:</h4>
                                            <div className="space-y-1">
                                              <div className="flex items-center gap-2">
                                                <span className="text-xs text-default-500">SSE:</span>
                                                <code className="text-xs bg-default-100 px-1 py-1 rounded flex-1 break-all">
                                                  {`${getGatewayBaseUrl()}${router.prefix}/sse`}
                                                </code>
                                                <Button
                                                  isIconOnly
                                                  size="sm"
                                                  variant="light"
                                                  onPress={() => handleCopyWithIcon(
                                                    `${getGatewayBaseUrl()}${router.prefix}/sse`,
                                                    `nginx-sse-${server.name}-${idx}`
                                                  )}
                                                >
                                                  <LocalIcon icon={copiedStates[`nginx-sse-${server.name}-${idx}`] ? "lucide:check" : "lucide:copy"} className="text-sm" />
                                                </Button>
                                              </div>
                                              <div className="flex items-center gap-2">
                                                <span className="text-xs text-default-500">Streamable HTTP:</span>
                                                <code className="text-xs bg-default-100 px-1 py-1 rounded flex-1 break-all">
                                                  {`${getGatewayBaseUrl()}${router.prefix}/mcp`}
                                                </code>
                                                <Button
                                                  isIconOnly
                                                  size="sm"
                                                  variant="light"
                                                  onPress={() => handleCopyWithIcon(
                                                    `${getGatewayBaseUrl()}${router.prefix}/mcp`,
                                                    `nginx-mcp-${server.name}-${idx}`
                                                  )}
                                                >
                                                  <LocalIcon icon={copiedStates[`nginx-mcp-${server.name}-${idx}`] ? "lucide:check" : "lucide:copy"} className="text-sm" />
                                                </Button>
                                              </div>
                                            </div>
                                          </div>

                                          <div className="space-y-2">
                                            <h4 className="text-sm font-semibold">{t('gateway.direct_to_mcp_gateway')}</h4>
                                            <div className="space-y-1">
                                              <div className="flex items-center gap-2">
                                                <span className="text-xs text-default-500">SSE:</span>
                                                <code className="text-xs bg-default-100 px-1 py-1 rounded flex-1 break-all">
                                                  {`${getDirectGatewayBaseUrl()}${router.prefix}/sse`}
                                                </code>
                                                <Button
                                                  isIconOnly
                                                  size="sm"
                                                  variant="light"
                                                  onPress={() => handleCopyWithIcon(
                                                    `${getDirectGatewayBaseUrl()}${router.prefix}/sse`,
                                                    `direct-sse-${server.name}-${idx}`
                                                  )}
                                                >
                                                  <LocalIcon icon={copiedStates[`direct-sse-${server.name}-${idx}`] ? "lucide:check" : "lucide:copy"} className="text-sm" />
                                                </Button>
                                              </div>
                                              <div className="flex items-center gap-2">
                                                <span className="text-xs text-default-500">Streamable HTTP:</span>
                                                <code className="text-xs bg-default-100 px-1 py-1 rounded flex-1 break-all">
                                                  {`${getDirectGatewayBaseUrl()}${router.prefix}/mcp`}
                                                </code>
                                                <Button
                                                  isIconOnly
                                                  size="sm"
                                                  variant="light"
                                                  onPress={() => handleCopyWithIcon(
                                                    `${getDirectGatewayBaseUrl()}${router.prefix}/mcp`,
                                                    `direct-mcp-${server.name}-${idx}`
                                                  )}
                                                >
                                                  <LocalIcon icon={copiedStates[`direct-mcp-${server.name}-${idx}`] ? "lucide:check" : "lucide:copy"} className="text-sm" />
                                                </Button>
                                              </div>
                                            </div>
                                          </div>

                                          <div className="text-xs text-default-500 border-t pt-2">
                                            {t('gateway.url_access_note')}
                                          </div>
                                        </div>
                                      </PopoverContent>
                                    </Popover>
                                    <LocalIcon icon="lucide:arrow-right" className="text-sm" />
                                    <Chip
                                      variant="flat"
                                      size="sm"
                                      className="cursor-pointer hover:opacity-80 select-none"
                                      onClick={() => handleCopyToClipboard(router.server)}
                                      aria-label={`${t('common.copy')} ${router.server}`}
                                    >
                                      {router.server}
                                    </Chip>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}

                          {server.mcpServers && server.mcpServers.length > 0 && (
                            <div className="space-y-2">
                              <h4 className="text-sm font-semibold">{t('gateway.mcp_config')}</h4>
                              <div className="flex flex-col gap-2">
                                {server.mcpServers.map((mcpServer, idx) => (
                                  <div key={`${server.tenant}-${server.name}-mcp-${mcpServer.name}-${idx}`} className="flex flex-col gap-1 p-2 border border-default-200 rounded-md">
                                    <div className="flex items-center gap-2">
                                      <span className="text-sm font-medium">{mcpServer.name}</span>
                                      <Chip size="sm" variant="flat" color="warning" aria-label={`Type: ${mcpServer.type}`}>
                                        {mcpServer.type}
                                      </Chip>
                                    </div>
                                    {mcpServer.type === 'stdio' && (
                                      <div className="text-xs">
                                        <div className="flex items-center gap-1">
                                          <span className="font-medium">Command:</span>
                                          <code className="bg-default-100 px-1 rounded">{mcpServer.command} {mcpServer.args?.join(' ')}</code>
                                        </div>
                                        {mcpServer.env && Object.entries(mcpServer.env).map(([key, value]) => (
                                          <div key={key} className="text-xs truncate">
                                            <span className="text-default-500">{key}:</span> {String(value)}
                                          </div>
                                        ))}
                                      </div>
                                    )}
                                    {(mcpServer.type === 'sse' || mcpServer.type === 'streamable-http') && mcpServer.url && (
                                      <div className="text-xs">
                                        <div className="flex items-start gap-1">
                                          <span className="font-medium mt-1">URL:</span>
                                          <code className="bg-default-100 px-1 py-1 rounded break-all">{mcpServer.url}</code>
                                        </div>
                                      </div>
                                    )}
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  )}
                </CardBody>
              </Card>
            ))}
          </div>
        ) : (
          <Table aria-label={t('gateway.table_view')}>
            <TableHeader>
              <TableColumn width="25%">{t('gateway.name')}</TableColumn>
              <TableColumn width="15%">{t('gateway.description')}</TableColumn>
              <TableColumn width="25%">{t('gateway.routing')}</TableColumn>
              <TableColumn width="25%">{t('gateway.tools')}</TableColumn>
              <TableColumn width="10%">{t('common.actions')}</TableColumn>
            </TableHeader>
            <TableBody>
              {(mcpservers || []).map((server) => (
                <TableRow key={`${server.tenant}-${server.name}`}>
                  <TableCell className="font-medium truncate max-w-[15%]">{server.name}</TableCell>
                  <TableCell className="max-w-[25%]">
                    {server.servers && server.servers.length > 0 ? (
                      <div className="line-clamp-2 overflow-hidden overflow-ellipsis">
                        {server.servers[0].description}
                      </div>
                    ) : (
                      <span className="text-gray-400">{t('gateway.no_description')}</span>
                    )}
                  </TableCell>
                  <TableCell className="max-w-[25%] overflow-hidden">
                    <Button
                      variant="light"
                      size="sm"
                      className="w-full text-left justify-start"
                      endContent={<LocalIcon icon="lucide:external-link" className="text-sm" />}
                      onPress={() => {
                        setCurrentModalServer(server);
                        setIsRoutingModalOpen(true);
                      }}
                    >
                      {`${server.routers?.length || 0} ${t('gateway.routes')}`}
                    </Button>
                  </TableCell>
                  <TableCell className="max-w-[25%] overflow-hidden">
                    <Button
                      variant="light"
                      size="sm"
                      className="w-full text-left justify-start"
                      endContent={<LocalIcon icon="lucide:external-link" className="text-sm" />}
                      onPress={() => {
                        setCurrentModalServer(server);
                        setIsToolsModalOpen(true);
                      }}
                    >
                      {(() => {
                        const totalAllowedTools = (server.servers || []).reduce((sum, s) => sum + (s.allowedTools?.length || 0), 0);
                        const totalTools = server.tools?.length || 0;
                        return `${totalAllowedTools} ${t('gateway.enabled')} / ${totalTools} ${t('gateway.total')}`;
                      })()}
                    </Button>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <Button
                        variant="light"
                        size="sm"
                        startContent={<LocalIcon icon="lucide:history" />}
                        onPress={() => {
                          navigate(`/config-versions?name=${server.name}`);
                        }}
                      >
                        {t('mcp.configVersions.title')}
                      </Button>
                      <Button
                        isIconOnly
                        color="primary"
                        variant="light"
                        size="sm"
                        onPress={() => handleEdit(server)}
                        aria-label={t('gateway.edit')}
                      >
                        <LocalIcon icon="lucide:edit" className="text-lg" />
                      </Button>
                      <Button
                        isIconOnly
                        color="danger"
                        variant="light"
                        size="sm"
                        onPress={() => handleDelete(server)}
                        aria-label={t('gateway.delete')}
                      >
                        <LocalIcon icon="lucide:trash-2" className="text-lg" />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </div>

      <Modal
        isOpen={isOpen}
        onOpenChange={onOpenChange}
        size="3xl"
        className="w-[70%] h-[80%]"
        scrollBehavior="inside"
      >
        <ModalContent>
          {(onClose) => (
            <>
              <ModalHeader>{t('gateway.edit_config')}</ModalHeader>
              <ModalBody>
                <ConfigEditor
                  config={editConfig}
                  onChange={(value) => setEditConfig(value)}
                  isDark={isDark}
                  editorOptions={editorOptions}
                  isEditing={true}
                />
              </ModalBody>
              <ModalFooter>
                <Button color="danger" variant="light" onPress={onClose}>
                  {t('common.cancel')}
                </Button>
                <Button color="primary" onPress={handleSave}>
                  {t('common.save')}
                </Button>
              </ModalFooter>
            </>
          )}
        </ModalContent>
      </Modal>

      <Modal
        isOpen={isCreateOpen}
        onOpenChange={onCreateOpenChange}
        size="3xl"
        className="w-[70%] h-[80%]"
        scrollBehavior="inside"
      >
        <ModalContent>
          {(onClose) => (
            <>
              <ModalHeader>{t('gateway.add_config')}</ModalHeader>
              <ModalBody className="overflow-y-auto">
                <ConfigEditor
                  config={newConfig}
                  onChange={(value) => setNewConfig(value)}
                  isDark={isDark}
                  editorOptions={editorOptions}
                  isEditing={false}
                />
              </ModalBody>
              <ModalFooter>
                <Button color="danger" variant="light" onPress={onClose}>
                  {t('common.cancel')}
                </Button>
                <Button color="primary" onPress={handleCreate}>
                  {t('gateway.add')}
                </Button>
              </ModalFooter>
            </>
          )}
        </ModalContent>
      </Modal>

      <Modal isOpen={isImportOpen} onOpenChange={onImportOpenChange} size="3xl" scrollBehavior="inside">
        <ModalContent>
          <ModalHeader className="flex flex-col gap-1">
            <div className="flex items-center gap-2">
              <LocalIcon icon="lucide:file-plus" className="text-primary" />
              {t('gateway.import_openapi')}
            </div>
            <p className="text-sm text-default-500 font-normal">
              {t('gateway.import_openapi_description', 'Import OpenAPI specification to create MCP server configuration')}
            </p>
          </ModalHeader>
          <ModalBody className="py-6">
            <OpenAPIImport onSuccess={handleImportSuccess} selectedTenant={selectedTenant} />
          </ModalBody>
          <ModalFooter>
            <Button color="danger" variant="light" onPress={() => onImportOpenChange()}>
              {t('common.cancel')}
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>

      <Modal
        isOpen={isRoutingModalOpen}
        onClose={() => setIsRoutingModalOpen(false)}
        size="2xl"
        scrollBehavior="inside"
      >
        <ModalContent>
          {() => (
            <>
              <ModalHeader className="flex flex-col gap-1">
                {currentModalServer?.name} - {t('gateway.routing_config')}
              </ModalHeader>
              <ModalBody>
                <div className="space-y-3">
                  <div className="space-y-2">
                    <h4 className="text-sm font-semibold">{t('gateway.routing_config')}</h4>
                    <div className="space-y-2 w-full">
                      {(currentModalServer?.routers || []).map((router: RouterConfig, idx: number) => (
                        <div key={`${currentModalServer?.tenant}-${currentModalServer?.name}-modal-router-${router.prefix}-${idx}`} className="flex items-center gap-2 flex-wrap">
                          <Popover placement="right">
                            <PopoverTrigger>
                              <Chip
                                color="primary"
                                variant="flat"
                                size="sm"
                                className="cursor-pointer hover:opacity-80 select-none"
                                aria-label={`${t('common.copy')} ${router.prefix}`}
                              >
                                {router.prefix}
                              </Chip>
                            </PopoverTrigger>
                            <PopoverContent className="max-w-[500px]">
                              <div className="px-1 py-2 space-y-4">
                                <div className="space-y-2">
                                  <h4 className="text-sm font-semibold">AllInOne - Nginx:</h4>
                                  <div className="space-y-1">
                                    <div className="flex items-center gap-2">
                                      <span className="text-xs text-default-500">SSE:</span>
                                      <code className="text-xs bg-default-100 px-1 py-1 rounded flex-1 break-all">
                                        {`${getGatewayBaseUrl()}${router.prefix}/sse`}
                                      </code>
                                      <Button
                                        isIconOnly
                                        size="sm"
                                        variant="light"
                                        onPress={() => handleCopyWithIcon(
                                          `${getGatewayBaseUrl()}${router.prefix}/sse`,
                                          `nginx-sse-${currentModalServer?.name}-${idx}`
                                        )}
                                      >
                                        <LocalIcon icon={copiedStates[`nginx-sse-${currentModalServer?.name}-${idx}`] ? "lucide:check" : "lucide:copy"} className="text-sm" />
                                      </Button>
                                    </div>
                                    <div className="flex items-center gap-2">
                                      <span className="text-xs text-default-500">Streamable HTTP:</span>
                                      <code className="text-xs bg-default-100 px-1 py-1 rounded flex-1 break-all">
                                        {`${getGatewayBaseUrl()}${router.prefix}/mcp`}
                                      </code>
                                      <Button
                                        isIconOnly
                                        size="sm"
                                        variant="light"
                                        onPress={() => handleCopyWithIcon(
                                          `${getGatewayBaseUrl()}${router.prefix}/mcp`,
                                          `nginx-mcp-${currentModalServer?.name}-${idx}`
                                        )}
                                      >
                                        <LocalIcon icon={copiedStates[`nginx-mcp-${currentModalServer?.name}-${idx}`] ? "lucide:check" : "lucide:copy"} className="text-sm" />
                                      </Button>
                                    </div>
                                  </div>
                                </div>

                                <div className="space-y-2">
                                  <h4 className="text-sm font-semibold">{t('gateway.direct_to_mcp_gateway')}</h4>
                                  <div className="space-y-1">
                                    <div className="flex items-center gap-2">
                                      <span className="text-xs text-default-500">SSE:</span>
                                      <code className="text-xs bg-default-100 px-1 py-1 rounded flex-1 break-all">
                                        {`${getDirectGatewayBaseUrl()}${router.prefix}/sse`}
                                      </code>
                                      <Button
                                        isIconOnly
                                        size="sm"
                                        variant="light"
                                        onPress={() => handleCopyWithIcon(
                                          `${getDirectGatewayBaseUrl()}${router.prefix}/sse`,
                                          `direct-sse-${currentModalServer?.name}-${idx}`
                                        )}
                                      >
                                        <LocalIcon icon={copiedStates[`direct-sse-${currentModalServer?.name}-${idx}`] ? "lucide:check" : "lucide:copy"} className="text-sm" />
                                      </Button>
                                    </div>
                                    <div className="flex items-center gap-2">
                                      <span className="text-xs text-default-500">Streamable HTTP:</span>
                                      <code className="text-xs bg-default-100 px-1 py-1 rounded flex-1 break-all">
                                        {`${getDirectGatewayBaseUrl()}${router.prefix}/mcp`}
                                      </code>
                                      <Button
                                        isIconOnly
                                        size="sm"
                                        variant="light"
                                        onPress={() => handleCopyWithIcon(
                                          `${getDirectGatewayBaseUrl()}${router.prefix}/mcp`,
                                          `direct-mcp-${currentModalServer?.name}-${idx}`
                                        )}
                                      >
                                        <LocalIcon icon={copiedStates[`direct-mcp-${currentModalServer?.name}-${idx}`] ? "lucide:check" : "lucide:copy"} className="text-sm" />
                                      </Button>
                                    </div>
                                  </div>
                                </div>

                                <div className="text-xs text-default-500 border-t pt-2">
                                  {t('gateway.url_access_note')}
                                </div>
                              </div>
                            </PopoverContent>
                          </Popover>
                          <LocalIcon icon="lucide:arrow-right" className="text-sm" />
                          <Chip
                            variant="flat"
                            size="sm"
                            className="cursor-pointer hover:opacity-80 select-none"
                            onClick={() => handleCopyToClipboard(router.server)}
                            aria-label={`${t('common.copy')} ${router.server}`}
                          >
                            {router.server}
                          </Chip>
                        </div>
                      ))}
                    </div>
                  </div>

                  {currentModalServer?.mcpServers && currentModalServer.mcpServers.length > 0 && (
                    <div className="space-y-2 mt-4 pt-4 border-t">
                      <h4 className="text-sm font-semibold">{t('gateway.backend_config')}</h4>
                      <div className="space-y-2">
                        {currentModalServer.mcpServers.map((mcpServer, idx) => (
                          <div key={`${currentModalServer.tenant}-${currentModalServer.name}-modal-${mcpServer.name}-${idx}`} className="flex flex-col gap-1 p-2 border border-default-200 rounded-md">
                            <div className="flex items-center gap-2">
                              <span className="text-sm font-medium">{mcpServer.name}</span>
                              <Chip size="sm" variant="flat" color="warning" aria-label={`Type: ${mcpServer.type}`}>
                                {mcpServer.type}
                              </Chip>
                            </div>
                            {mcpServer.type === 'stdio' && (
                              <div className="text-xs">
                                <div className="flex items-center gap-1">
                                  <span className="font-medium">Command:</span>
                                  <code className="bg-default-100 px-1 rounded">{mcpServer.command} {mcpServer.args?.join(' ')}</code>
                                </div>
                                {mcpServer.env && Object.entries(mcpServer.env).map(([key, value]) => (
                                  <div key={key} className="text-xs truncate">
                                    <span className="text-default-500">{key}:</span> {String(value)}
                                  </div>
                                ))}
                              </div>
                            )}
                            {(mcpServer.type === 'sse' || mcpServer.type === 'streamable-http') && mcpServer.url && (
                              <div className="text-xs">
                                <div className="flex items-start gap-1">
                                  <span className="font-medium mt-1">URL:</span>
                                  <code className="bg-default-100 px-1 py-1 rounded break-all">{mcpServer.url}</code>
                                </div>
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </ModalBody>
              <ModalFooter>
                <Button color="primary" size="sm" onPress={() => setIsRoutingModalOpen(false)}>
                  {t('common.close')}
                </Button>
              </ModalFooter>
            </>
          )}
        </ModalContent>
      </Modal>

      <Modal
        isOpen={isToolsModalOpen}
        onClose={() => setIsToolsModalOpen(false)}
        size="2xl"
        scrollBehavior="inside"
      >
        <ModalContent>
          {() => (
            <>
              <ModalHeader className="flex flex-col gap-1">
                {currentModalServer?.name} - {t('gateway.tools')}
              </ModalHeader>
              <ModalBody>
                {currentModalServer?.servers && currentModalServer.servers.length > 0 && (
                  <div className="space-y-6">
                    <div>
                      <h4 className="text-sm font-semibold mb-2">{t('gateway.enabled_tools')}</h4>
                      <div className="flex flex-wrap gap-1">
                        {(currentModalServer.servers[0].allowedTools ?? []).map((tool: string) => (
                          <Chip
                            key={tool}
                            variant="flat"
                            color="success"
                            size="sm"
                            className="truncate cursor-pointer hover:opacity-80 select-none"
                            onClick={() => handleCopyToClipboard(tool)}
                            aria-label={`${t('common.copy')} ${tool}`}
                          >
                            {tool}
                          </Chip>
                        ))}
                      </div>
                    </div>

                    <div className="mt-4 pt-4 border-t">
                      <h4 className="text-sm font-semibold mb-2">{t('gateway.all_tools')}</h4>
                      <div className="flex flex-wrap gap-1">
                        {(currentModalServer.tools || []).map((tool) => {
                          const toolConfig = tool as import('@/types/gateway').ToolConfig;
                          return (
                            <Chip
                              key={toolConfig.name}
                              variant="flat"
                              color="default"
                              size="sm"
                              className="truncate cursor-pointer hover:opacity-80 select-none"
                              onClick={() => handleCopyToClipboard(toolConfig.name)}
                              aria-label={`${t('common.copy')} ${toolConfig.name}`}
                            >
                              {toolConfig.name}
                            </Chip>
                          );
                        })}
                      </div>
                    </div>
                  </div>
                )}
              </ModalBody>
              <ModalFooter>
                <Button color="primary" size="sm" onPress={() => setIsToolsModalOpen(false)}>
                  {t('common.close')}
                </Button>
              </ModalFooter>
            </>
          )}
        </ModalContent>
      </Modal>

      <Modal
        isOpen={isDeleteModalOpen}
        onOpenChange={() => {
          setIsDeleteModalOpen(false);
          setServerToDelete(null);
        }}
      >
        <ModalContent>
          {(onClose) => (
            <>
              <ModalHeader>{t('gateway.delete')}</ModalHeader>
              <ModalBody>
                <p>{t('gateway.confirm_delete', { name: serverToDelete?.name })}</p>
              </ModalBody>
              <ModalFooter>
                <Button color="danger" variant="light" onPress={onClose}>
                  {t('common.cancel')}
                </Button>
                <Button color="danger" onPress={confirmDelete}>
                  {t('common.confirm')}
                </Button>
              </ModalFooter>
            </>
          )}
        </ModalContent>
      </Modal>
    </div>
  );
}
