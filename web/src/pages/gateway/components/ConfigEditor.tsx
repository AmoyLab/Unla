import {Button, Input, Select, SelectItem, Tab, Tabs} from "@heroui/react";
import Editor from '@monaco-editor/react';
import yaml from 'js-yaml';
import {useCallback, useEffect, useState} from 'react';
import {useTranslation} from 'react-i18next';

import {defaultConfig} from '../constants/defaultConfig';

import {MCPServersConfig} from './MCPServersConfig';
import {PromptsConfig} from './PromptsConfig';
import {RouterConfig} from './RouterConfig';
import {ServersConfig} from './ServersConfig';
import {ToolsConfig} from './ToolsConfig';

import {getTenants} from '@/services/api';
import {ConfigEditorProps, Gateway, Tenant} from '@/types/gateway';

export function ConfigEditor({ config, onChange, isDark, editorOptions, isEditing }: ConfigEditorProps) {
  const { t } = useTranslation();
  const [isYamlMode, setIsYamlMode] = useState<boolean>(false);
  const [parsedConfig, setParsedConfig] = useState<Gateway | null>(null);
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [isLoadingTenants, setIsLoadingTenants] = useState<boolean>(false);
  const [generalFormState, setGeneralFormState] = useState<{name?: string; tenant?: string}>({});

  const updateConfig = useCallback((newData: Partial<Gateway>) => {
    const baseConfig = parsedConfig || defaultConfig;

    const updated: Gateway = {
      ...baseConfig,
      ...newData,
    };

    if (isYamlMode && isEditing && parsedConfig?.name?.trim()) {
      updated.name = parsedConfig.name;
    }

    try {
      const yamlString = yaml.dump(updated);
      setParsedConfig(updated);
      onChange(yamlString);
    } catch (e) {
      console.error("Failed to generate YAML:", e);
    }
  }, [parsedConfig, isYamlMode, isEditing, onChange]);

  useEffect(() => {
    const fetchTenants = async () => {
      setIsLoadingTenants(true);
      try {
        const tenantsData = await getTenants();
        setTenants(tenantsData);
      } catch (error) {
        console.error("Failed to fetch tenants:", error);
      } finally {
        setIsLoadingTenants(false);
      }
    };

    fetchTenants();
  }, []);

  useEffect(() => {
    try {
      if (!config || config.trim() === '') {
        setParsedConfig(defaultConfig);
        return;
      }

      const parsed = yaml.load(config) as Gateway;
      setParsedConfig(parsed);
    } catch (e) {
      console.error("Failed to parse config:", e);
      setParsedConfig(defaultConfig);
    }
  }, [config]);


  return (
    <div className="h-full flex flex-col">
      <div className="flex justify-end mb-4">
        <Button
          color={isYamlMode ? "primary" : "default"}
          variant={isYamlMode ? "solid" : "flat"}
          onPress={() => setIsYamlMode(true)}
          className="mr-2"
          size="sm"
        >
          {t('gateway.yaml_mode')}
        </Button>
        <Button
          color={!isYamlMode ? "primary" : "default"}
          variant={!isYamlMode ? "solid" : "flat"}
          onPress={() => setIsYamlMode(false)}
          size="sm"
        >
          {t('gateway.form_mode')}
        </Button>
      </div>

      {isYamlMode ? (
        <Editor
          height="100%"
          defaultLanguage="yaml"
          value={config}
          onChange={(value) => {
            if (value !== undefined) {
              onChange(value);
            }
          }}
          theme={isDark ? "vs-dark" : "light"}
          options={editorOptions}
        />
      ) : (
        <div className="space-y-4">
          <div className="space-y-2">
            <Input
              label={t('gateway.name')}
              value={generalFormState.name !== undefined ? generalFormState.name : (parsedConfig?.name || "")}
              onChange={(e) => {
                const newName = e.target.value;
                setGeneralFormState(prev => ({
                  ...prev,
                  name: newName
                }));
                updateConfig({ name: newName });
              }}
              isDisabled={Boolean(isEditing && parsedConfig?.name && parsedConfig.name.trim() !== '')}
              description={(isEditing && parsedConfig?.name && parsedConfig.name.trim() !== '') ? t('gateway.name_locked') : undefined}
            />

            <Select
              label={t('gateway.tenant')}
              selectedKeys={(() => {
                if (generalFormState.tenant !== undefined) {
                  return [generalFormState.tenant];
                }
                
                const configTenant = parsedConfig?.tenant?.replace(/^\//, '');
                const activeTenants = tenants.filter(tenant => tenant.isActive);
                
                // If we have active tenants, check if the config tenant exists in them
                if (activeTenants.length > 0) {
                  const tenantExists = activeTenants.some(tenant => tenant.name === configTenant);
                  if (tenantExists && configTenant) {
                    return [configTenant];
                  }
                  // If config tenant doesn't exist or is empty, default to first active tenant
                  return [activeTenants[0].name];
                }
                
                // If no active tenants, fall back to 'default'
                return ['default'];
              })()}
              onChange={(e) => {
                const newTenant = e.target.value;
                setGeneralFormState(prev => ({
                  ...prev,
                  tenant: newTenant
                }));
                updateConfig({ tenant: newTenant });
              }}
              aria-label={t('gateway.tenant')}
              isLoading={isLoadingTenants}
            >
              {tenants.length > 0 ? (
                tenants.filter(tenant => tenant.isActive).map(tenant => (
                  <SelectItem key={tenant.name} textValue={tenant.name}>
                    {tenant.name}
                    {tenant.prefix && <span className="text-tiny text-default-400"> ({tenant.prefix})</span>}
                  </SelectItem>
                ))
              ) : (
                <SelectItem key="default" textValue="default">default</SelectItem>
              )}
            </Select>

            <div className="mt-2">
              <h3 className="text-sm font-medium mb-2">{t('gateway.created_at')}: {new Date().toLocaleString()}</h3>
              <h3 className="text-sm font-medium mb-2">{t('gateway.updated_at')}: {new Date().toLocaleString()}</h3>
            </div>
          </div>

          <Tabs aria-label="Configuration sections" className="w-full" disableAnimation>
            <Tab key="tools" title={t('gateway.tools')}>
              <ToolsConfig
                parsedConfig={parsedConfig || defaultConfig}
                updateConfig={updateConfig}
              />
            </Tab>
            <Tab key="http-servers" title={t('gateway.http_servers')}>
              <ServersConfig
                parsedConfig={parsedConfig || defaultConfig}
                updateConfig={updateConfig}
              />
            </Tab>
            <Tab key="mcp-servers" title={t('gateway.mcp_servers')}>
              <MCPServersConfig
                parsedConfig={parsedConfig || defaultConfig}
                updateConfig={updateConfig}
              />
            </Tab>
            <Tab key="routers" title={t('gateway.routers')}>
              <RouterConfig
                parsedConfig={parsedConfig || defaultConfig}
                updateConfig={updateConfig}
                tenants={tenants}
              />
            </Tab>
            <Tab key="prompts" title={t('gateway.prompts')}>
              <PromptsConfig
                parsedConfig={parsedConfig || defaultConfig}
                updateConfig={updateConfig}
              />              
            </Tab>
          </Tabs>
        </div>
      )}
    </div>
  );
}
