import { Table, TableHeader, TableColumn, TableBody, TableRow, TableCell, Button, Select, SelectItem, Modal, ModalContent, ModalHeader, ModalBody, ModalFooter, Tooltip } from '@heroui/react';
import dayjs from 'dayjs';
import yaml from 'js-yaml';
import { useEffect, useState, useCallback } from 'react';
import ReactDiffViewer from 'react-diff-viewer-continued';
import { useTranslation } from 'react-i18next';
import { useSearchParams } from 'react-router-dom';

import LocalIcon from '@/components/LocalIcon';
import { useTheme } from '@/hooks/useTheme';
import { getMCPConfigVersions, setActiveVersion, getMCPConfigNames, getTenants } from '@/services/api';
import type { MCPConfigVersion } from '@/types/mcp';
import {Tenant} from '@/types/user';

export function ConfigVersionsPage() {
  const { t } = useTranslation();
  const { isDark } = useTheme();
  const [searchParams, setSearchParams] = useSearchParams();
  const [versions, setVersions] = useState<MCPConfigVersion[]>([]);
  const [loading, setLoading] = useState(false);
  const [configNames, setConfigNames] = useState<string[]>([]);
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [selectedConfig, setSelectedConfig] = useState<string | undefined>(searchParams.get('name') || undefined);
  const [selectedTenant, setSelectedTenant] = useState<string | undefined>(searchParams.get('tenant') || undefined);
  const [compareModalVisible, setCompareModalVisible] = useState(false);
  const [selectedVersions, setSelectedVersions] = useState<{ old?: MCPConfigVersion; new?: MCPConfigVersion }>({});
  const [showDiffOnly, setShowDiffOnly] = useState(true);

  const fetchConfigNames = useCallback(async () => {
    try {
      const names = await getMCPConfigNames(selectedTenant);
      setConfigNames(names);
    } catch (error) {
      console.error('Failed to fetch config names:', error);
    }
  }, [selectedTenant]);

  const fetchTenants = useCallback(async () => {
    try {
      const data = await getTenants();
      setTenants(data);
    } catch (error) {
      console.error('Failed to fetch tenants:', error);
    }
  }, []);

  const fetchVersions = useCallback(async (name?: string) => {
    setLoading(true);
    try {
      const response = await getMCPConfigVersions(selectedTenant, name);
      setVersions(response.data || []);
    } catch (error) {
      console.error('Failed to fetch config versions:', error);
    } finally {
      setLoading(false);
    }
  }, [selectedTenant]);

  useEffect(() => {
    fetchTenants();
  }, [fetchTenants]);

  useEffect(() => {
    if (selectedTenant) {
      fetchConfigNames();
    } else {
      setConfigNames([]);
    }
  }, [selectedTenant, fetchConfigNames]);

  useEffect(() => {
    fetchVersions(selectedConfig);
  }, [selectedTenant, selectedConfig, fetchVersions]);

  const handleSetActive = async (name: string, version: number) => {
    try {
      await setActiveVersion(selectedTenant || 'default', name, version);
      console.log('Config active version set successfully');
      fetchVersions(selectedConfig);
    } catch (error) {
      console.error('Failed to set config active version:', error);
    }
  };

  const handleConfigChange = (value: string) => {
    setSelectedConfig(value);
    const params: Record<string, string> = {};
    if (value) {
      params.name = value;
    }
    if (selectedTenant) {
      params.tenant = selectedTenant;
    }
    setSearchParams(params);
  };

  const handleTenantChange = (value: string) => {
    setSelectedTenant(value);
    setSelectedConfig(undefined); // Reset selected config when tenant changes
    const params: Record<string, string> = {};
    if (value) {
      params.tenant = value;
    }
    setSearchParams(params);
  };

  const handleCompareWithPrevious = (record: MCPConfigVersion) => {
    const sameConfigVersions = versions
      .filter(v => v.name === record.name)
      .sort((a, b) => b.version - a.version);

    const currentIndex = sameConfigVersions.findIndex(v => v.version === record.version);

    if (currentIndex < sameConfigVersions.length - 1) {
      setSelectedVersions({
        old: sameConfigVersions[currentIndex + 1],
        new: record
      });
      setCompareModalVisible(true);
    } else {
      console.warn('No previous version available');
    }
  };

  const handleCompareWithLatest = (record: MCPConfigVersion) => {
    const latestVersion = versions.find(v => v.name === record.name && v.is_active);
    if (latestVersion && latestVersion.version !== record.version) {
      setSelectedVersions({
        old: record,
        new: latestVersion
      });
      setCompareModalVisible(true);
    } else {
      console.warn('No latest version available');
    }
  };

  const parseJsonString = (jsonStr: string) => {
    try {
      return JSON.parse(jsonStr);
    } catch (e) {
      console.error('Failed to parse JSON string:', e);
      return [];
    }
  };

  const getConfigContent = (version: MCPConfigVersion) => {
    const config = {
      name: version.name,
      tenant: version.tenant,
      createdAt: version.created_at,
      routers: parseJsonString(version.routers),
      servers: parseJsonString(version.servers),
      tools: parseJsonString(version.tools),
      mcp_servers: parseJsonString(version.mcp_servers)
    };
    return yaml.dump(config, {
      indent: 2,
      lineWidth: -1,
      noRefs: true,
      sortKeys: false
    });
  };

  const columns = [
    {
      key: 'name',
      render: (record: MCPConfigVersion) => record.name,
    },
    {
      key: 'tenant',
      render: (record: MCPConfigVersion) => record.tenant,
    },
    {
      key: 'version',
      render: (record: MCPConfigVersion) => record.version,
    },
    {
      key: 'created_by',
      render: (record: MCPConfigVersion) => record.created_by,
    },
    {
      key: 'created_at',
      render: (record: MCPConfigVersion) => dayjs(record.created_at).format('YYYY-MM-DD HH:mm:ss'),
    },
    {
      key: 'action_type',
      render: (record: MCPConfigVersion) => (
        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
          record.action_type === 'Create' ? 'bg-green-100 text-green-800' :
          record.action_type === 'Update' ? 'bg-blue-100 text-blue-800' :
          record.action_type === 'Delete' ? 'bg-red-100 text-red-800' :
          'bg-gray-100 text-gray-800'
        }`}>
          {t(`mcp.configVersions.action_types.${record.action_type.toLowerCase()}`)}
        </span>
      ),
    },
    {
      key: 'active',
      render: (record: MCPConfigVersion) => (
        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
          record.is_active ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'
        }`}>
          {record.is_active ? t('mcp.configVersions.active') : t('mcp.configVersions.inactive')}
        </span>
      ),
    },
    {
      key: 'actions',
      render: (record: MCPConfigVersion) => (
        <div className="flex items-center gap-2">
          {record.is_active ? (
            <span></span>
          ) : (
            <Tooltip content={t('mcp.configVersions.rollback')}>
              <Button
                isIconOnly
                size="sm"
                color="primary"
                variant="flat"
                onPress={() => handleSetActive(record.name, record.version)}
              >
                <LocalIcon icon="heroicons:arrow-uturn-left" className="h-4 w-4" />
              </Button>
            </Tooltip>
          )}
          {!record.is_active && (
            <>
              {record.version > 1 && (
                <Tooltip content={t('mcp.configVersions.compare_with_previous')}>
                  <Button
                    isIconOnly
                    size="sm"
                    color="primary"
                    variant="flat"
                    onPress={() => handleCompareWithPrevious(record)}
                  >
                    <LocalIcon icon="heroicons:chevron-left" className="h-4 w-4" />
                  </Button>
                </Tooltip>
              )}
              {record.version < versions.length && (
                <Tooltip content={t('mcp.configVersions.compare_with_latest')}>
                  <Button
                    isIconOnly
                    size="sm"
                    color="primary"
                    variant="flat"
                    onPress={() => handleCompareWithLatest(record)}
                  >
                    <LocalIcon icon="heroicons:chevron-right" className="h-4 w-4" />
                  </Button>
                </Tooltip>
              )}
            </>
          )}
        </div>
      ),
    },
  ];

  return (
    <div>
      <div className="mb-4 flex gap-4">
        <Select
          className="mt-1 block w-48"
          selectedKeys={selectedTenant ? [selectedTenant] : []}
          onSelectionChange={(keys) => handleTenantChange(Array.from(keys)[0] as string)}
          aria-label={t('mcp.configVersions.select_tenant')}
          placeholder={t('mcp.configVersions.select_tenant')}
        >
          {tenants.map(tenant => (
            <SelectItem key={tenant.name} textValue={tenant.name}>{tenant.name}</SelectItem>
          ))}
        </Select>
        <Select
          className="mt-1 block w-48"
          selectedKeys={selectedConfig ? [selectedConfig] : []}
          onSelectionChange={(keys) => handleConfigChange(Array.from(keys)[0] as string)}
          aria-label={t('mcp.configVersions.select_config')}
          placeholder={t('mcp.configVersions.select_config')}
        >
          {configNames.map(name => (
            <SelectItem key={name} textValue={name}>{name}</SelectItem>
          ))}
        </Select>
      </div>

      <Table aria-label={t('mcp.configVersions.title')}>
        <TableHeader>
          <TableColumn>{t('mcp.configVersions.name')}</TableColumn>
          <TableColumn>{t('mcp.configVersions.tenant')}</TableColumn>
          <TableColumn>{t('mcp.configVersions.version')}</TableColumn>
          <TableColumn>{t('mcp.configVersions.created_by')}</TableColumn>
          <TableColumn>{t('mcp.configVersions.created_at')}</TableColumn>
          <TableColumn>{t('mcp.configVersions.action_type')}</TableColumn>
          <TableColumn>{t('mcp.configVersions.active')}</TableColumn>
          <TableColumn>{t('mcp.configVersions.actions')}</TableColumn>
        </TableHeader>
        <TableBody
          loadingContent={<div>{t('common.loading')}</div>}
          loadingState={loading ? 'loading' : 'idle'}
        >
          {versions.map((record) => (
            <TableRow key={`${record.name}-${record.version}`}>
              {columns.map((column) => (
                <TableCell key={column.key}>{column.render(record)}</TableCell>
              ))}
            </TableRow>
          ))}
        </TableBody>
      </Table>

      <Modal
        isOpen={compareModalVisible}
        onClose={() => setCompareModalVisible(false)}
        size="5xl"
        scrollBehavior="inside"
      >
        <ModalContent>
          <ModalHeader>
            {t('mcp.configVersions.compare_versions')}
          </ModalHeader>
          <ModalBody>
            {selectedVersions.old && selectedVersions.new && (
              <div className="flex flex-col">
                <div className="mb-4 flex justify-between items-center">
                  <div className="flex gap-4">
                    <div>
                      <strong>{t('mcp.configVersions.version')}: {selectedVersions.old.version}</strong>
                      <div>{dayjs(selectedVersions.old.created_at).format('YYYY-MM-DD HH:mm:ss')}</div>
                    </div>
                    <div>
                      <strong>{t('mcp.configVersions.version')}: {selectedVersions.new.version}</strong>
                      <div>{dayjs(selectedVersions.new.created_at).format('YYYY-MM-DD HH:mm:ss')}</div>
                    </div>
                  </div>
                  <Button
                    isIconOnly
                    variant="light"
                    onPress={() => setShowDiffOnly(!showDiffOnly)}
                    className={`text-gray-600 ${showDiffOnly ? 'bg-gray-100' : ''}`}
                    title={showDiffOnly ? t('mcp.configVersions.show_all') : t('mcp.configVersions.show_diff_only')}
                  >
                    <LocalIcon icon="fluent-mdl2:chevron-fold-10"
                      className={`w-5 h-5 transition-transform duration-200 ${showDiffOnly ? 'rotate-180' : ''}`}
                    />
                  </Button>
                </div>

                <ReactDiffViewer
                  oldValue={getConfigContent(selectedVersions.old)}
                  newValue={getConfigContent(selectedVersions.new)}
                  splitView={true}
                  leftTitle={`${t('mcp.configVersions.version')} ${selectedVersions.old.version}`}
                  rightTitle={`${t('mcp.configVersions.version')} ${selectedVersions.new.version}`}
                  showDiffOnly={showDiffOnly}
                  extraLinesSurroundingDiff={3}
                  useDarkTheme={isDark}
                  disableWordDiff={false}
                  hideLineNumbers={false}
                  styles={{
                    variables: {
                      dark: {
                        diffViewerBackground: '#1e1e1e',
                        diffViewerColor: '#d4d4d4',
                        addedBackground: '#0d2a1e',
                        addedColor: '#d4d4d4',
                        removedBackground: '#2a0d0d',
                        removedColor: '#d4d4d4',
                        wordAddedBackground: '#0d2a1e',
                        wordRemovedBackground: '#2a0d0d',
                        codeFoldGutterBackground: '#1e1e1e',
                        codeFoldBackground: '#1e1e1e',
                        codeFoldContentColor: '#d4d4d4',
                        gutterBackground: '#1e1e1e',
                        gutterColor: '#858585',
                        addedGutterBackground: '#0d2a1e',
                        removedGutterBackground: '#2a0d0d',
                        gutterBackgroundDark: '#1e1e1e',
                        highlightBackground: '#1e1e1e',
                        highlightGutterBackground: '#1e1e1e',
                      },
                      light: {
                        diffViewerBackground: '#ffffff',
                        diffViewerColor: '#212529',
                        addedBackground: '#e6ffed',
                        addedColor: '#24292e',
                        removedBackground: '#ffeef0',
                        removedColor: '#24292e',
                        wordAddedBackground: '#acf2bd',
                        wordRemovedBackground: '#fdb8c0',
                        codeFoldGutterBackground: '#f1f8ff',
                        codeFoldBackground: '#f1f8ff',
                        codeFoldContentColor: '#212529',
                        gutterBackground: '#f1f8ff',
                        gutterColor: '#212529',
                        addedGutterBackground: '#e6ffed',
                        removedGutterBackground: '#ffeef0',
                        gutterBackgroundDark: '#f1f8ff',
                        highlightBackground: '#f1f8ff',
                        highlightGutterBackground: '#f1f8ff',
                      },
                    },
                    codeFold: {
                      backgroundColor: isDark ? '#1e1e1e' : '#f1f8ff',
                      color: isDark ? '#d4d4d4' : '#212529',
                    },
                    titleBlock: {
                      backgroundColor: isDark ? '#1e1e1e' : '#ffffff',
                      color: isDark ? '#d4d4d4' : '#212529',
                      borderBottom: `1px solid ${isDark ? '#333' : '#e1e4e8'}`,
                    },
                    splitView: {
                      borderRight: `1px solid ${isDark ? '#333' : '#e1e4e8'}`,
                    },
                    gutter: {
                      borderRight: `1px solid ${isDark ? '#333' : '#e1e4e8'}`,
                      minWidth: '40px',
                    },
                    contentText: {
                      fontFamily: 'Menlo, Monaco, "Courier New", monospace',
                      fontSize: '14px',
                      lineHeight: '1.5',
                    },
                  }}
                />
              </div>
            )}
          </ModalBody>
          <ModalFooter>
            <Button
              size="sm"
              color="primary"
              onPress={() => setCompareModalVisible(false)}
            >
              {t('common.close')}
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>
    </div>
  );
}