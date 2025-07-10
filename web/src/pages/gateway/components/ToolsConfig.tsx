import { Input, Select, SelectItem, Button, Checkbox, Accordion, AccordionItem, Textarea } from "@heroui/react";
import { useTranslation } from 'react-i18next';

import LocalIcon from '@/components/LocalIcon';
import { Gateway, ToolConfig, ServerConfig, ArgConfig, PropertyConfig } from '@/types/gateway';

interface ToolsConfigProps {
  parsedConfig: Gateway;
  updateConfig: (newData: Partial<Gateway>) => void;
}

export function ToolsConfig({
  parsedConfig,
  updateConfig
}: ToolsConfigProps) {
  const { t } = useTranslation();
  const tools = parsedConfig?.tools || [];

  const updateTool = (index: number, field: string, value: string | Array<{
    name: string;
    position: string;
    required: boolean;
    type: string;
    description: string;
    default: string;
  }>) => {
    const updatedTools = [...tools];
    const oldName = updatedTools[index].name;
    updatedTools[index] = {
      ...updatedTools[index],
      [field]: value
    };

    // If tool name changed, update server references
    if (field === 'name' && oldName !== value && parsedConfig.servers) {
      const updatedServers = parsedConfig.servers.map((server: ServerConfig) => {
        if (server.allowedTools) {
          const updatedAllowedTools = server.allowedTools.map((toolName: string) =>
            toolName === oldName ? value as string : toolName
          );
          return { ...server, allowedTools: updatedAllowedTools };
        }
        return server;
      });
      updateConfig({ tools: updatedTools, servers: updatedServers });
    } else {
      updateConfig({ tools: updatedTools });
    }
  };

  const updateHeader = (toolIndex: number, headerIndex: number, field: 'key' | 'value', value: string) => {
    const updatedTools = [...tools];
    const tool = updatedTools[toolIndex];
    const headers = { ...tool.headers };
    const headersOrder = [...(tool.headersOrder || Object.keys(headers))];

    if (field === 'key') {
      const oldKey = headersOrder[headerIndex];
      const newKey = value;
      if (oldKey !== newKey) {
        // Update header key
        headers[newKey] = headers[oldKey];
        delete headers[oldKey];
        headersOrder[headerIndex] = newKey;
      }
    } else {
      // Update header value
      headers[headersOrder[headerIndex]] = value;
    }

    updatedTools[toolIndex] = {
      ...tool,
      headers,
      headersOrder
    };

    updateConfig({ tools: updatedTools });
  };

  const addHeader = (toolIndex: number) => {
    const updatedTools = [...tools];
    const tool = updatedTools[toolIndex];
    const headers = { ...tool.headers };
    const headersOrder = [...(tool.headersOrder || Object.keys(headers))];

    let newKey = "Content-Type";
    let count = 1;

    const commonHeaders = [
      "Authorization",
      "Accept",
      "X-API-Key",
      "User-Agent",
    ];

    for (const header of commonHeaders) {
      if (!headersOrder.includes(header)) {
        newKey = header;
        break;
      }
    }

    if (headersOrder.includes(newKey)) {
      while (headersOrder.includes(`X-Header-${count}`)) {
        count++;
      }
      newKey = `X-Header-${count}`;
    }

    headers[newKey] = "";
    headersOrder.push(newKey);

    updatedTools[toolIndex] = {
      ...tool,
      headers,
      headersOrder
    };

    updateConfig({ tools: updatedTools });
  };

  const removeHeader = (toolIndex: number, headerIndex: number) => {
    const updatedTools = [...tools];
    const tool = updatedTools[toolIndex];
    const headers = { ...tool.headers };
    const headersOrder = [...(tool.headersOrder || Object.keys(headers))];

    const keyToRemove = headersOrder[headerIndex];
    delete headers[keyToRemove];
    headersOrder.splice(headerIndex, 1);

    updatedTools[toolIndex] = {
      ...tool,
      headers,
      headersOrder
    };

    updateConfig({ tools: updatedTools });
  };

  return (
    <div className="space-y-4">
      <Accordion variant="splitted">
        {tools.map((tool: ToolConfig, index: number) => (
          <AccordionItem
            key={index}
            title={tool.name || `Tool ${index + 1}`}
            subtitle={tool.description}
            startContent={
              <LocalIcon icon="lucide:wrench" 
                className="text-primary-500" 
              />
            }
          >
            <div className="p-2 space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <Input
                  label={t('gateway.tool_name')}
                  value={tool.name || ""}
                  onChange={(e) => updateTool(index, 'name', e.target.value)}
                />
                <Input
                  label={t('gateway.description')}
                  value={tool.description || ""}
                  onChange={(e) => updateTool(index, 'description', e.target.value)}
                />
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <Select
                  label={t('gateway.method')}
                  selectedKeys={[tool.method || "GET"]}
                  onChange={(e) => updateTool(index, 'method', e.target.value)}
                  aria-label={t('gateway.method')}
                >
                  <SelectItem key="GET" textValue="GET">GET</SelectItem>
                  <SelectItem key="POST" textValue="POST">POST</SelectItem>
                  <SelectItem key="PUT" textValue="PUT">PUT</SelectItem>
                  <SelectItem key="DELETE" textValue="DELETE">DELETE</SelectItem>
                </Select>
                <Input
                  label={t('gateway.endpoint')}
                  value={tool.endpoint || ""}
                  onChange={(e) => updateTool(index, 'endpoint', e.target.value)}
                />
              </div>

              {/* Headers Section */}
              <div className="bg-content1 p-4 rounded-medium border border-content2">
                <div className="flex justify-between items-center mb-3">
                  <h4 className="text-md font-medium">Headers</h4>
                  <Button
                    size="sm"
                    color="primary"
                    variant="flat"
                    startContent={<LocalIcon icon="lucide:plus" />}
                    onPress={() => addHeader(index)}
                  >
                    {t('gateway.add_header')}
                  </Button>
                </div>

                <div className="space-y-3">
                  {(tool.headersOrder || Object.keys(tool.headers || {})).map((key: string, headerIndex: number) => (
                    <div key={headerIndex} className="flex gap-2">
                      <Input
                        className="flex-1"
                        value={key}
                        onChange={(e) => updateHeader(index, headerIndex, 'key', e.target.value)}
                        placeholder={t('gateway.header_name_placeholder')}
                      />
                      <Input
                        className="flex-1"
                        value={tool.headers?.[key] || ""}
                        onChange={(e) => updateHeader(index, headerIndex, 'value', e.target.value)}
                        placeholder={t('gateway.header_value_placeholder')}
                      />
                      <Button
                        isIconOnly
                        color="danger"
                        variant="light"
                        className="self-end mb-1"
                        onPress={() => removeHeader(index, headerIndex)}
                      >
                        <LocalIcon icon="lucide:x" />
                      </Button>
                    </div>
                  ))}
                </div>
              </div>

              {/* Arguments Section */}
              <div className="bg-content1 p-4 rounded-medium border border-content2">
                <div className="flex justify-between items-center mb-3">
                  <h4 className="text-md font-medium">{t('gateway.arguments_config')}</h4>
                  <Button
                    color="primary"
                    size="sm"
                    variant="flat"
                    startContent={<LocalIcon icon="lucide:plus" />}
                    onPress={() => {
                      const updatedArgs = [...(tool.args || [])];
                      updatedArgs.push({
                        name: "",
                        position: "body",
                        required: false,
                        type: "string",
                        description: "",
                        default: ""
                      });
                      updateTool(index, 'args', updatedArgs);
                    }}
                  >
                    {t('gateway.add_argument')}
                  </Button>
                </div>

                <div className="space-y-3">
                  {(tool.args || []).map((arg: ArgConfig, argIndex: number) => (
                    <div key={argIndex} className="flex flex-col gap-2 p-3 border border-content2 rounded-md bg-content1">
                      <div className="flex items-center gap-2">
                        <Input
                          className="flex-1"
                          label={t('gateway.argument_name')}
                          value={arg.name || ""}
                          onChange={(e) => {
                            const updatedArgs = [...(tool.args || [])];
                            updatedArgs[argIndex] = {
                              ...updatedArgs[argIndex],
                              name: e.target.value
                            };
                            updateTool(index, 'args', updatedArgs);
                          }}
                          placeholder={t('gateway.argument_name')}
                        />
                        <Select
                          className="flex-1"
                          label={t('gateway.argument_position')}
                          selectedKeys={[arg.position || "body"]}
                          onChange={(e) => {
                            const updatedArgs = [...(tool.args || [])];
                            updatedArgs[argIndex] = {
                              ...updatedArgs[argIndex],
                              position: e.target.value
                            };
                            updateTool(index, 'args', updatedArgs);
                          }}
                        >
                          <SelectItem key="body" textValue={t('gateway.position_body')}>{t('gateway.position_body')}</SelectItem>
                          <SelectItem key="query" textValue={t('gateway.position_query')}>{t('gateway.position_query')}</SelectItem>
                          <SelectItem key="path" textValue={t('gateway.position_path')}>{t('gateway.position_path')}</SelectItem>
                          <SelectItem key="form-data" textValue={t('gateway.type_form_data')}>{t('gateway.type_form_data')}</SelectItem>
                        </Select>
                      </div>

                      <div className="flex items-center gap-2">
                        <Select
                          className="flex-1"
                          label={t('gateway.argument_type')}
                          selectedKeys={[arg.type || "string"]}
                          onChange={(e) => {
                            const updatedArgs = [...(tool.args || [])];
                            updatedArgs[argIndex] = {
                              ...updatedArgs[argIndex],
                              type: e.target.value
                            };
                            updateTool(index, 'args', updatedArgs);
                          }}
                        >
                          <SelectItem key="string" textValue={t('gateway.type_string')}>{t('gateway.type_string')}</SelectItem>
                          <SelectItem key="number" textValue={t('gateway.type_number')}>{t('gateway.type_number')}</SelectItem>
                          <SelectItem key="boolean" textValue={t('gateway.type_boolean')}>{t('gateway.type_boolean')}</SelectItem>
                          <SelectItem key="array" textValue={t('gateway.type_array')}>{t('gateway.type_array')}</SelectItem>
                          <SelectItem key="object" textValue={t('gateway.type_object')}>{t('gateway.type_object')}</SelectItem>
                        </Select>

                        <div className="flex items-center gap-2">
                          <Checkbox
                            isSelected={arg.required || false}
                            onValueChange={(isSelected) => {
                              const updatedArgs = [...(tool.args || [])];
                              updatedArgs[argIndex] = {
                                ...updatedArgs[argIndex],
                                required: isSelected
                              };
                              updateTool(index, 'args', updatedArgs);
                            }}
                          >
                            {t('gateway.argument_required')}
                          </Checkbox>
                        </div>
                      </div>

                      {/* 嵌套参数配置 - 当类型为 array 或 object 时显示 */}
                      {(arg.type === 'array' || arg.type === 'object') && (
                        <div className="bg-content2 p-3 rounded-md border border-content3 ml-4">
                          <h5 className="text-sm font-medium mb-2">
                            {arg.type === 'array' ? t('gateway.array_items_config') : t('gateway.object_properties_config')}
                          </h5>

                          {arg.type === 'array' && (
                            <div className="space-y-2">
                              <Select
                                label={t('gateway.array_item_type')}
                                selectedKeys={[arg.items?.type || "string"]}
                                onChange={(e) => {
                                  const updatedArgs = [...(tool.args || [])];
                                  updatedArgs[argIndex] = {
                                    ...updatedArgs[argIndex],
                                    items: {
                                      ...updatedArgs[argIndex].items,
                                      type: e.target.value
                                    }
                                  };
                                  updateTool(index, 'args', updatedArgs);
                                }}
                              >
                                <SelectItem key="string" textValue={t('gateway.type_string')}>{t('gateway.type_string')}</SelectItem>
                                <SelectItem key="number" textValue={t('gateway.type_number')}>{t('gateway.type_number')}</SelectItem>
                                <SelectItem key="boolean" textValue={t('gateway.type_boolean')}>{t('gateway.type_boolean')}</SelectItem>
                                <SelectItem key="object" textValue={t('gateway.type_object')}>{t('gateway.type_object')}</SelectItem>
                              </Select>

                              {/* 如果数组元素是对象，显示对象属性配置 */}
                              {arg.items?.type === 'object' && (
                                <div className="space-y-2">
                                  <div className="flex justify-between items-center">
                                    <span className="text-sm">{t('gateway.object_properties')}</span>
                                    <Button
                                      size="sm"
                                      color="primary"
                                      variant="flat"
                                      startContent={<LocalIcon icon="lucide:plus" />}
                                      onPress={() => {
                                        const updatedArgs = [...(tool.args || [])];
                                        const currentItems = updatedArgs[argIndex].items || { type: 'object', properties: {} };
                                        const newPropertyName = `property${Object.keys(currentItems.properties || {}).length + 1}`;
                                        updatedArgs[argIndex] = {
                                          ...updatedArgs[argIndex],
                                          items: {
                                            ...currentItems,
                                            properties: {
                                              ...currentItems.properties,
                                              [newPropertyName]: {
                                                type: 'string',
                                                description: ''
                                              }
                                            }
                                          }
                                        };
                                        updateTool(index, 'args', updatedArgs);
                                      }}
                                    >
                                      {t('gateway.add_property')}
                                    </Button>
                                  </div>

                                  {arg.items?.properties && Object.entries(arg.items.properties).map(([propName, propConfig]: [string, PropertyConfig], propIndex: number) => (
                                    <div key={propIndex} className="grid grid-cols-1 lg:grid-cols-12 gap-2 p-3 border border-content3 rounded-md bg-content1">
                                      <div className="lg:col-span-6">
                                        <Input
                                          label={t('gateway.property_name')}
                                          value={propName}
                                          onChange={(e) => {
                                            const updatedArgs = [...(tool.args || [])];
                                            const currentItems = updatedArgs[argIndex].items || { type: 'object', properties: {} };
                                            const newProperties = { ...currentItems.properties };

                                            // 删除旧的属性名，添加新的属性名
                                            delete newProperties[propName];
                                            newProperties[e.target.value] = propConfig;

                                            updatedArgs[argIndex] = {
                                              ...updatedArgs[argIndex],
                                              items: {
                                                ...currentItems,
                                                properties: newProperties
                                              }
                                            };
                                            updateTool(index, 'args', updatedArgs);
                                          }}
                                        />
                                      </div>
                                      <div className="lg:col-span-6">
                                        <Select
                                          label={t('gateway.property_type')}
                                          selectedKeys={[(propConfig as PropertyConfig).type || "string"]}
                                          onChange={(e) => {
                                            const updatedArgs = [...(tool.args || [])];
                                            const currentItems = updatedArgs[argIndex].items || { type: 'object', properties: {} };
                                            updatedArgs[argIndex] = {
                                              ...updatedArgs[argIndex],
                                              items: {
                                                ...currentItems,
                                                properties: {
                                                  ...currentItems.properties,
                                                  [propName]: {
                                                    ...(propConfig as PropertyConfig),
                                                    type: e.target.value
                                                  }
                                                }
                                              }
                                            };
                                            updateTool(index, 'args', updatedArgs);
                                          }}
                                        >
                                          <SelectItem key="string" textValue={t('gateway.type_string')}>{t('gateway.type_string')}</SelectItem>
                                          <SelectItem key="number" textValue={t('gateway.type_number')}>{t('gateway.type_number')}</SelectItem>
                                          <SelectItem key="boolean" textValue={t('gateway.type_boolean')}>{t('gateway.type_boolean')}</SelectItem>
                                        </Select>
                                      </div>
                                      <div className="lg:col-span-11">
                                        <Input
                                          label={t('gateway.property_description')}
                                          value={(propConfig as PropertyConfig).description || ""}
                                          onChange={(e) => {
                                            const updatedArgs = [...(tool.args || [])];
                                            const currentItems = updatedArgs[argIndex].items || { type: 'object', properties: {} };
                                            updatedArgs[argIndex] = {
                                              ...updatedArgs[argIndex],
                                              items: {
                                                ...currentItems,
                                                properties: {
                                                  ...currentItems.properties,
                                                  [propName]: {
                                                    ...(propConfig as PropertyConfig),
                                                    description: e.target.value
                                                  }
                                                }
                                              }
                                            };
                                            updateTool(index, 'args', updatedArgs);
                                          }}
                                        />
                                      </div>
                                      <div className="lg:col-span-1 flex items-end">
                                        <Button
                                          isIconOnly
                                          color="danger"
                                          variant="light"
                                          size="sm"
                                          onPress={() => {
                                            const updatedArgs = [...(tool.args || [])];
                                            const currentItems = updatedArgs[argIndex].items || { type: 'object', properties: {} };
                                            const newProperties = { ...currentItems.properties };
                                            delete newProperties[propName];
                                            updatedArgs[argIndex] = {
                                              ...updatedArgs[argIndex],
                                              items: {
                                                ...currentItems,
                                                properties: newProperties
                                              }
                                            };
                                            updateTool(index, 'args', updatedArgs);
                                          }}
                                        >
                                          <LocalIcon icon="lucide:x" />
                                        </Button>
                                      </div>
                                    </div>
                                  ))}
                                </div>
                              )}
                            </div>
                          )}

                          {arg.type === 'object' && (
                            <div className="space-y-2">
                              <div className="flex justify-between items-center">
                                <span className="text-sm">{t('gateway.object_properties')}</span>
                                <Button
                                  size="sm"
                                  color="primary"
                                  variant="flat"
                                  startContent={<LocalIcon icon="lucide:plus" />}
                                  onPress={() => {
                                    const updatedArgs = [...(tool.args || [])];
                                    const currentItems = updatedArgs[argIndex].items || { type: 'object', properties: {} };
                                    const newPropertyName = `property${Object.keys(currentItems.properties || {}).length + 1}`;
                                    updatedArgs[argIndex] = {
                                      ...updatedArgs[argIndex],
                                      items: {
                                        ...currentItems,
                                        properties: {
                                          ...currentItems.properties,
                                          [newPropertyName]: {
                                            type: 'string',
                                            description: ''
                                          }
                                        }
                                      }
                                    };
                                    updateTool(index, 'args', updatedArgs);
                                  }}
                                >
                                  {t('gateway.add_property')}
                                </Button>
                              </div>

                              {arg.items?.properties && Object.entries(arg.items.properties).map(([propName, propConfig]: [string, PropertyConfig], propIndex: number) => (
                                <div key={propIndex} className="grid grid-cols-1 lg:grid-cols-12 gap-2 p-3 border border-content3 rounded-md bg-content1">
                                  <div className="lg:col-span-6">
                                    <Input
                                      label={t('gateway.property_name')}
                                      value={propName}
                                      onChange={(e) => {
                                        const updatedArgs = [...(tool.args || [])];
                                        const currentItems = updatedArgs[argIndex].items || { type: 'object', properties: {} };
                                        const newProperties = { ...currentItems.properties };

                                        // 删除旧的属性名，添加新的属性名
                                        delete newProperties[propName];
                                        newProperties[e.target.value] = propConfig as PropertyConfig;

                                        updatedArgs[argIndex] = {
                                          ...updatedArgs[argIndex],
                                          items: {
                                            ...currentItems,
                                            properties: newProperties
                                          }
                                        };
                                        updateTool(index, 'args', updatedArgs);
                                      }}
                                    />
                                  </div>
                                  <div className="lg:col-span-6">
                                    <Select
                                      label={t('gateway.property_type')}
                                      selectedKeys={[(propConfig as PropertyConfig).type || "string"]}
                                      onChange={(e) => {
                                        const updatedArgs = [...(tool.args || [])];
                                        const currentItems = updatedArgs[argIndex].items || { type: 'object', properties: {} };
                                        updatedArgs[argIndex] = {
                                          ...updatedArgs[argIndex],
                                          items: {
                                            ...currentItems,
                                            properties: {
                                              ...currentItems.properties,
                                              [propName]: {
                                                ...(propConfig as PropertyConfig),
                                                type: e.target.value
                                              }
                                            }
                                          }
                                        };
                                        updateTool(index, 'args', updatedArgs);
                                      }}
                                    >
                                      <SelectItem key="string" textValue={t('gateway.type_string')}>{t('gateway.type_string')}</SelectItem>
                                      <SelectItem key="number" textValue={t('gateway.type_number')}>{t('gateway.type_number')}</SelectItem>
                                      <SelectItem key="boolean" textValue={t('gateway.type_boolean')}>{t('gateway.type_boolean')}</SelectItem>
                                    </Select>
                                  </div>
                                  <div className="lg:col-span-11">
                                    <Input
                                      label={t('gateway.property_description')}
                                      value={(propConfig as PropertyConfig).description || ""}
                                      onChange={(e) => {
                                        const updatedArgs = [...(tool.args || [])];
                                        const currentItems = updatedArgs[argIndex].items || { type: 'object', properties: {} };
                                        updatedArgs[argIndex] = {
                                          ...updatedArgs[argIndex],
                                          items: {
                                            ...currentItems,
                                            properties: {
                                              ...currentItems.properties,
                                              [propName]: {
                                                ...(propConfig as PropertyConfig),
                                                description: e.target.value
                                              }
                                            }
                                          }
                                        };
                                        updateTool(index, 'args', updatedArgs);
                                      }}
                                    />
                                  </div>
                                  <div className="lg:col-span-1 flex items-end">
                                    <Button
                                      isIconOnly
                                      color="danger"
                                      variant="light"
                                      size="sm"
                                      onPress={() => {
                                        const updatedArgs = [...(tool.args || [])];
                                        const currentItems = updatedArgs[argIndex].items || { type: 'object', properties: {} };
                                        const newProperties = { ...currentItems.properties };
                                        delete newProperties[propName];
                                        updatedArgs[argIndex] = {
                                          ...updatedArgs[argIndex],
                                          items: {
                                            ...currentItems,
                                            properties: newProperties
                                          }
                                        };
                                        updateTool(index, 'args', updatedArgs);
                                      }}
                                    >
                                      <LocalIcon icon="lucide:x" />
                                    </Button>
                                  </div>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      )}

                      <Input
                        label={t('gateway.argument_description')}
                        value={arg.description || ""}
                        onChange={(e) => {
                          const updatedArgs = [...(tool.args || [])];
                          updatedArgs[argIndex] = {
                            ...updatedArgs[argIndex],
                            description: e.target.value
                          };
                          updateTool(index, 'args', updatedArgs);
                        }}
                        placeholder={t('gateway.argument_description')}
                      />
                      <Input
                        label={t('gateway.argument_default')}
                        value={arg.default || ""}
                        onChange={(e) => {
                          const updatedArgs = [...(tool.args || [])];
                          updatedArgs[argIndex] = {
                            ...updatedArgs[argIndex],
                            default: e.target.value
                          };
                          updateTool(index, 'args', updatedArgs);
                        }}
                        placeholder={t('gateway.argument_default')}
                      />
                      <div className="flex justify-end">
                        <Button
                          color="danger"
                          variant="flat"
                          size="sm"
                          startContent={<LocalIcon icon="lucide:trash-2" />}
                          onPress={() => {
                            const updatedArgs = [...(tool.args || [])];
                            updatedArgs.splice(argIndex, 1);
                            updateTool(index, 'args', updatedArgs);
                          }}
                        >
                          {t('gateway.remove_argument')}
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Request/Response Body */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <Textarea
                  label={t('gateway.request_body')}
                  value={tool.requestBody || ""}
                  onChange={(e) => updateTool(index, 'requestBody', e.target.value)}
                  placeholder={t('gateway.request_body_placeholder')}
                  minRows={5}
                  className="font-mono text-sm"
                />
                <Textarea
                  label={t('gateway.response_body')}
                  value={tool.responseBody || ""}
                  onChange={(e) => updateTool(index, 'responseBody', e.target.value)}
                  placeholder={t('gateway.response_body_placeholder')}
                  minRows={5}
                  className="font-mono text-sm"
                />
              </div>

              <div className="flex justify-end">
                <Button
                  color="danger"
                  variant="flat"
                  size="sm"
                  startContent={<LocalIcon icon="lucide:trash-2" />}
                  onPress={() => {
                    const updatedTools = [...tools];
                    updatedTools.splice(index, 1);
                    updateConfig({ tools: updatedTools });
                  }}
                >
                  {t('gateway.remove_tool')}
                </Button>
              </div>
            </div>
          </AccordionItem>
        ))}
      </Accordion>

      {/* Add Tool Button */}
      <div className="flex justify-center">
        <Button
          color="primary"
          variant="flat"
          startContent={<LocalIcon icon="lucide:plus" />}
          onPress={() => {
            const updatedTools = [...tools];
            updatedTools.push({
              name: "",
              description: "",
              method: "GET",
              endpoint: "",
              headers: {
                "Content-Type": "application/json"
              },
              headersOrder: ["Content-Type"],
              args: [],
              requestBody: "",
              responseBody: "{{.Response.Body}}"
            });
            updateConfig({ tools: updatedTools });
          }}
        >
          {t('gateway.add_tool')}
        </Button>
      </div>
    </div>
  );
} 