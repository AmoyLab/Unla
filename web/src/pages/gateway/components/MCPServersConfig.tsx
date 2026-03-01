import { Input, Select, SelectItem, Button, Switch, Accordion, AccordionItem } from "@heroui/react";
import { useState, useEffect, useMemo } from 'react';
import { useTranslation } from 'react-i18next';

import LocalIcon from '@/components/LocalIcon';
import type { Gateway, MCPServerConfig } from '@/types/gateway';

interface MCPServersConfigProps {
  parsedConfig: Gateway;
  updateConfig: (newData: Partial<Gateway>) => void;
}

export function MCPServersConfig({
  parsedConfig,
  updateConfig
}: MCPServersConfigProps) {
  const { t } = useTranslation();
  const mcpServers = useMemo(() => 
    parsedConfig?.mcpServers || [{
      type: "stdio",
      name: "",
      command: "",
      args: [],
      env: {},
      headers: {},
      policy: "onDemand",
      preinstalled: false
    }],
    [parsedConfig?.mcpServers]
  );
  const [commandInputs, setCommandInputs] = useState<{ [key: number]: string }>({});

  // Initialize command inputs when mcpServers changes
  useEffect(() => {
    const initialInputs = mcpServers.reduce<{ [key: number]: string }>((acc, server, index) => {
      acc[index] = `${server.command || ''} ${server.args?.join(' ') || ''}`.trim();
      return acc;
    }, {});
    setCommandInputs(initialInputs);
  }, [mcpServers]);

  const updateServer = (index: number, field: 'name' | 'type' | 'policy' | 'command' | 'url' | 'preinstalled', value: string | boolean) => {
    const updatedServers = [...mcpServers];
    const oldName = updatedServers[index].name;
    
    if (field === 'command') {
      // Split the command string by whitespace and update both command and args
      const commandValue = value as string;
      const parts = commandValue.trim().split(/\s+/);
      updatedServers[index] = {
        ...updatedServers[index],
        command: parts[0] || '',
        args: parts.slice(1)
      };
    } else if (field === 'preinstalled') {
      updatedServers[index] = {
        ...updatedServers[index],
        [field]: value as boolean
      };
    } else {
      updatedServers[index] = {
        ...updatedServers[index],
        [field]: value as string
      };
    }

    // If server name changed, update router references
    if (field === 'name' && oldName !== value && parsedConfig.routers) {
      const updatedRouters = parsedConfig.routers.map(router => {
        if (router.server === oldName) {
          return { ...router, server: value as string };
        }
        return router;
      });
      updateConfig({ mcpServers: updatedServers, routers: updatedRouters });
    } else {
      updateConfig({ mcpServers: updatedServers });
    }
  };

  const handleCommandInputChange = (index: number, value: string) => {
    setCommandInputs(prev => ({
      ...prev,
      [index]: value
    }));
  };

  const handleCommandInputBlur = (index: number) => {
    updateServer(index, 'command', commandInputs[index]);
  };

  const updateEnvVariable = (serverIndex: number, envIndex: number, field: 'key' | 'value', value: string) => {
    const updatedServers = [...mcpServers];
    const server = updatedServers[serverIndex];
    const env = { ...server.env };
    const envKeys = Object.keys(env);
    const key = envKeys[envIndex];

    if (field === 'key') {
      if (key !== value) {
        env[value] = env[key];
        delete env[key];
      }
    } else {
      env[key] = value;
    }

    updatedServers[serverIndex] = {
      ...server,
      env
    };

    updateConfig({ mcpServers: updatedServers });
  };

  const isAuthorizationKey = (key: string) => key.toLowerCase() === 'authorization';

  const getAuthorizationToken = (headers?: Record<string, string>) => {
    if (!headers) {
      return '';
    }
    const entry = Object.entries(headers).find(([key]) => isAuthorizationKey(key));
    if (!entry) {
      return '';
    }
    const value = entry[1] || '';
    if (value.toLowerCase().startsWith('bearer ')) {
      return value.slice(7);
    }
    return value;
  };

  const setAuthorizationToken = (serverIndex: number, token: string) => {
    const updatedServers = [...mcpServers];
    const server = updatedServers[serverIndex];
    const headers = { ...(server.headers || {}) };

    for (const key of Object.keys(headers)) {
      if (isAuthorizationKey(key)) {
        delete headers[key];
      }
    }

    const trimmed = token.trim();
    if (trimmed) {
      headers.Authorization = `Bearer ${trimmed}`;
    }

    updatedServers[serverIndex] = {
      ...server,
      headers
    };

    updateConfig({ mcpServers: updatedServers });
  };

  const getEditableHeaderKeys = (headers?: Record<string, string>) =>
    Object.keys(headers || {}).filter((key) => !isAuthorizationKey(key));

  const updateHeader = (serverIndex: number, headerIndex: number, field: 'key' | 'value', value: string) => {
    const updatedServers = [...mcpServers];
    const server = updatedServers[serverIndex];
    const headers = { ...(server.headers || {}) };
    const headerKeys = getEditableHeaderKeys(headers);
    const key = headerKeys[headerIndex];

    if (!key) {
      return;
    }

    if (field === 'key') {
      const newKey = value;

      // Disallow empty header keys
      if (!newKey) {
        return;
      }

      // Disallow overwriting an existing header with a different key
      if (newKey !== key && Object.prototype.hasOwnProperty.call(headers, newKey)) {
        return;
      }

      if (key !== newKey) {
        headers[newKey] = headers[key];
        delete headers[key];
      }
    } else {
      headers[key] = value;
    }

    updatedServers[serverIndex] = {
      ...server,
      headers
    };

    updateConfig({ mcpServers: updatedServers });
  };

  const addHeader = (serverIndex: number) => {
    const updatedServers = [...mcpServers];
    const server = updatedServers[serverIndex];
    const headers = { ...(server.headers || {}) };
    const headerKeys = getEditableHeaderKeys(headers);

    let newKey = "Content-Type";
    let count = 1;

    const commonHeaders = [
      "Accept",
      "X-API-Key",
      "User-Agent",
    ];

    for (const header of commonHeaders) {
      if (!headerKeys.includes(header)) {
        newKey = header;
        break;
      }
    }

    if (headerKeys.includes(newKey)) {
      while (headerKeys.includes(`X-Header-${count}`)) {
        count++;
      }
      newKey = `X-Header-${count}`;
    }

    headers[newKey] = "";

    updatedServers[serverIndex] = {
      ...server,
      headers
    };

    updateConfig({ mcpServers: updatedServers });
  };

  const removeHeader = (serverIndex: number, headerIndex: number) => {
    const updatedServers = [...mcpServers];
    const server = updatedServers[serverIndex];
    const headers = { ...(server.headers || {}) };
    const headerKeys = getEditableHeaderKeys(headers);
    const keyToRemove = headerKeys[headerIndex];

    if (!keyToRemove) {
      return;
    }

    delete headers[keyToRemove];

    updatedServers[serverIndex] = {
      ...server,
      headers
    };

    updateConfig({ mcpServers: updatedServers });
  };

  const addEnvVariable = (serverIndex: number) => {
    const updatedServers = [...mcpServers];
    const server = updatedServers[serverIndex];
    const env = { ...server.env };

    let newKey = "API_KEY";
    let count = 1;

    const commonEnvVars = [
      "AUTH_TOKEN",
      "OPENAI_API_KEY",
      "ANTHROPIC_API_KEY",
      "GITHUB_TOKEN",
      "MODEL_NAME"
    ];

    const existingKeys = Object.keys(env);

    for (const envVar of commonEnvVars) {
      if (!existingKeys.includes(envVar)) {
        newKey = envVar;
        break;
      }
    }

    if (existingKeys.includes(newKey)) {
      while (existingKeys.includes(`ENV_VAR_${count}`)) {
        count++;
      }
      newKey = `ENV_VAR_${count}`;
    }

    env[newKey] = "";

    updatedServers[serverIndex] = {
      ...server,
      env
    };

    updateConfig({ mcpServers: updatedServers });
  };

  const removeEnvVariable = (serverIndex: number, envIndex: number) => {
    const updatedServers = [...mcpServers];
    const server = updatedServers[serverIndex];
    const env = { ...server.env };
    const key = Object.keys(env)[envIndex];
    delete env[key];

    updatedServers[serverIndex] = {
      ...server,
      env
    };

    updateConfig({ mcpServers: updatedServers });
  };

  const addServer = () => {
    const newServer: MCPServerConfig = {
      type: "stdio",
      name: "",
      command: "",
      args: [],
      env: {},
      headers: {},
      policy: "onDemand",
      preinstalled: false
    };
    updateConfig({
      mcpServers: [...mcpServers, newServer]
    });
  };

  const removeServer = (index: number) => {
    const updatedServers = mcpServers.filter((_, i) => i !== index);
    updateConfig({
      mcpServers: updatedServers
    });
  };

  return (
    <div className="space-y-4">
      <Accordion variant="splitted">
        {mcpServers.map((server, index) => (
          <AccordionItem 
            key={index} 
            title={server.name || `MCP Server ${index + 1}`}
            subtitle={server.type}
            startContent={
              <LocalIcon icon={
                  server.type === 'stdio' ? 'lucide:terminal' :
                  server.type === 'sse' ? 'lucide:radio' :
                  'lucide:globe'
                } 
                className="text-primary-500" 
              />
            }
          >
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <Input
                  label={t('gateway.server_name')}
                  value={server.name || ""}
                  onChange={(e) => updateServer(index, 'name', e.target.value)}
                  maxLength={50}
                  description={t('gateway.server_name_limit', { count: server.name?.length || 0, max: 50 })}
                />
                <Select
                  label={t('gateway.mcp_type')}
                  selectedKeys={[server.type || "stdio"]}
                  onChange={(e) => updateServer(index, 'type', e.target.value)}
                  aria-label={t('gateway.mcp_type')}
                >
                  <SelectItem key="stdio" textValue="stdio">stdio</SelectItem>
                  <SelectItem key="sse" textValue="sse">sse</SelectItem>
                  <SelectItem key="streamable-http" textValue="streamable-http">streamable-http</SelectItem>
                </Select>
              </div>

              <Select
                label={t('gateway.startup_policy')}
                selectedKeys={[server.policy || "onDemand"]}
                onChange={(e) => updateServer(index, 'policy', e.target.value)}
                aria-label={t('gateway.startup_policy')}
              >
                <SelectItem key="onDemand" textValue={t('gateway.policy_on_demand')}>{t('gateway.policy_on_demand')}</SelectItem>
                <SelectItem key="onStart" textValue={t('gateway.policy_on_start')}>{t('gateway.policy_on_start')}</SelectItem>
              </Select>

              {(server.type === 'stdio' || !server.type) && (
                <>
                  <div className="bg-content1 p-4 rounded-medium border border-content2">
                    <Switch
                      isSelected={server.preinstalled}
                      onValueChange={(value) => updateServer(index, 'preinstalled', value)}
                      size="sm"
                    >
                      {t('gateway.preinstalled')}
                    </Switch>

                    <Input
                      label={t('gateway.command')}
                      value={commandInputs[index] || ''}
                      onChange={(e) => handleCommandInputChange(index, e.target.value)}
                      onBlur={() => handleCommandInputBlur(index)}
                      placeholder="command arg1 arg2 arg3"
                      type="text"
                      inputMode="text"
                      className="mt-4"
                    />

                    <div className="mt-4">
                      <h4 className="text-sm font-medium mb-2">{t('gateway.env_variables')}</h4>
                      <div className="flex flex-col gap-2">
                        {Object.entries(server.env || {}).map(([key, value], envIndex) => (
                          <div key={envIndex} className="flex items-center gap-2">
                            <Input
                              className="flex-1"
                              value={key}
                              onChange={(e) => updateEnvVariable(index, envIndex, 'key', e.target.value)}
                              placeholder={t('gateway.env_key_placeholder')}
                            />
                            <Input
                              className="flex-1"
                              value={String(value)}
                              onChange={(e) => updateEnvVariable(index, envIndex, 'value', e.target.value)}
                              placeholder={t('gateway.env_value_placeholder')}
                            />
                            <Button
                              color="danger"
                              variant="flat"
                              isIconOnly
                              onPress={() => removeEnvVariable(index, envIndex)}
                            >
                              <LocalIcon icon="lucide:x" />
                            </Button>
                          </div>
                        ))}

                        <Button
                          color="primary"
                          variant="flat"
                          size="sm"
                          startContent={<LocalIcon icon="lucide:plus" />}
                          onPress={() => addEnvVariable(index)}
                        >
                          {t('gateway.add_env_variable')}
                        </Button>
                      </div>
                    </div>
                  </div>
                </>
              )}

              {(server.type === 'sse' || server.type === 'streamable-http') && (
                <div className="bg-content1 p-4 rounded-medium border border-content2">
                  <Input
                    label={t('gateway.url')}
                    value={server.url || ''}
                    onChange={(e) => updateServer(index, 'url', e.target.value)}
                  />

                  <div className="mt-4">
                    <Input
                      label={t('gateway.authorization_bearer')}
                      value={getAuthorizationToken(server.headers)}
                      onChange={(e) => setAuthorizationToken(index, e.target.value)}
                      placeholder={t('gateway.authorization_token_placeholder')}
                      startContent={<span className="text-default-400 text-sm">Bearer</span>}
                    />
                  </div>

                  <div className="mt-4">
                    <div className="flex justify-between items-center mb-2">
                      <h4 className="text-sm font-medium">{t('gateway.mcp_headers')}</h4>
                      <Button
                        color="primary"
                        variant="flat"
                        size="sm"
                        startContent={<LocalIcon icon="lucide:plus" />}
                        onPress={() => addHeader(index)}
                      >
                        {t('gateway.add_header')}
                      </Button>
                    </div>

                    <div className="flex flex-col gap-2">
                      {getEditableHeaderKeys(server.headers).map((key, headerIndex) => (
                        <div key={key} className="flex items-center gap-2">
                          <Input
                            className="flex-1"
                            value={key}
                            onChange={(e) => updateHeader(index, headerIndex, 'key', e.target.value)}
                            placeholder={t('gateway.header_name_placeholder')}
                          />
                          <Input
                            className="flex-1"
                            value={server.headers?.[key] || ""}
                            onChange={(e) => updateHeader(index, headerIndex, 'value', e.target.value)}
                            placeholder={t('gateway.header_value_placeholder')}
                          />
                          <Button
                            color="danger"
                            variant="flat"
                            isIconOnly
                            onPress={() => removeHeader(index, headerIndex)}
                          >
                            <LocalIcon icon="lucide:x" />
                          </Button>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              <div className="flex justify-end">
                <Button 
                  color="danger" 
                  variant="flat" 
                  size="sm"
                  startContent={<LocalIcon icon="lucide:trash-2" />}
                  onPress={() => removeServer(index)}
                >
                  {t('gateway.remove_server')}
                </Button>
              </div>
            </div>
          </AccordionItem>
        ))}
      </Accordion>

      <div className="flex justify-center">
        <Button
          color="primary"
          variant="flat"
          startContent={<LocalIcon icon="lucide:plus" />}
          onPress={addServer}
        >
          {t('gateway.add_mcp_server')}
        </Button>
      </div>
    </div>
  );
}
