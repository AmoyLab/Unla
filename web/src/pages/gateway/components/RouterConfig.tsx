import { Input, Select, SelectItem, Button, Switch, Chip, Accordion, AccordionItem } from "@heroui/react";
import { useState } from "react";
import { useTranslation } from 'react-i18next';

import LocalIcon from '@/components/LocalIcon';
import { Gateway, CORSConfig, Tenant } from '@/types/gateway';

interface RouterConfigProps {
  parsedConfig: Gateway;
  updateConfig: (newData: Partial<Gateway>) => void;
  tenants: Tenant[];
}

export function RouterConfig({
  parsedConfig,
  updateConfig,
  tenants,
}: RouterConfigProps) {
  const { t } = useTranslation();
  const selectedTenant = tenants.find(t => t.name === parsedConfig?.tenant);
  const routers = parsedConfig?.routers || [{ server: "", prefix: "/" }];

  // Add state for input values
  const [originInput, setOriginInput] = useState("");
  const [headerInput, setHeaderInput] = useState("");
  const [exposeHeaderInput, setExposeHeaderInput] = useState("");

  const updateRouter = (index: number, field: string, value: string) => {
    const updatedRouters = [...routers];
    updatedRouters[index] = {
      ...updatedRouters[index],
      [field]: value
    };
    updateConfig({ routers: updatedRouters });
  };

  const renderCorsConfig = (router: { cors?: CORSConfig }, index: number) => {
    const corsConfig = router.cors;
    if (!corsConfig) return null;

    const updateCors = (updates: Partial<CORSConfig>) => {
      const updatedCors = { ...corsConfig, ...updates };
      const updatedRouters = routers.map((r, i) =>
        i === index ? { ...r, cors: updatedCors } : r
      );
      updateConfig({ routers: updatedRouters });
    };

    const addCorsItem = (field: keyof CORSConfig, value: string) => {
      if (!value?.trim()) return;
      const currentValues = corsConfig[field] as string[] || [];
      if (!currentValues.includes(value.trim())) {
        updateCors({
          [field]: [...currentValues, value.trim()]
        });
      }
    };

    const removeCorsItem = (field: keyof CORSConfig, itemIndex: number) => {
      const currentValues = corsConfig[field] as string[] || [];
      updateCors({
        [field]: currentValues.filter((_, i) => i !== itemIndex)
      });
    };

    return (
      <div className="space-y-4">
        <div>
          <div className="flex justify-between items-center mb-3">
            <h4 className="text-md font-medium">{t('gateway.allow_origins')}</h4>
            <Button
              size="sm"
              color="primary"
              variant="flat"
              startContent={<LocalIcon icon="lucide:plus" />}
              onPress={() => {
                addCorsItem('allowOrigins', originInput);
                setOriginInput('');
              }}
            >
              {t('gateway.add_origin')}
            </Button>
          </div>
          <div className="flex flex-wrap gap-1 mb-2">
            {(corsConfig.allowOrigins || []).map((origin: string, originIndex: number) => (
              <Chip
                key={originIndex}
                onClose={() => removeCorsItem('allowOrigins', originIndex)}
                variant="flat"
              >
                {origin}
              </Chip>
            ))}
          </div>
          <Input
            size="sm"
            placeholder={t('gateway.origin_placeholder')}
            value={originInput}
            onChange={(e) => setOriginInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                addCorsItem('allowOrigins', originInput);
                setOriginInput('');
              }
            }}
          />
        </div>

        <div>
          <div className="flex justify-between items-center mb-3">
            <h4 className="text-md font-medium">{t('gateway.allow_methods')}</h4>
          </div>
          <div className="flex flex-wrap gap-1 mb-2">
            {(corsConfig.allowMethods || []).map((method: string, methodIndex: number) => (
              <Chip
                key={methodIndex}
                onClose={() => removeCorsItem('allowMethods', methodIndex)}
                variant="flat"
              >
                {method}
              </Chip>
            ))}
          </div>
          <Select
            size="sm"
            id={`method-select-${index}`}
            aria-label={t('gateway.http_method')}
            onChange={(e) => addCorsItem('allowMethods', e.target.value)}
          >
            {['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD', 'PATCH'].map(method => (
              <SelectItem key={method} textValue={method}>{method}</SelectItem>
            ))}
          </Select>
        </div>

        <div>
          <div className="flex justify-between items-center mb-3">
            <h4 className="text-md font-medium">{t('gateway.allow_headers')}</h4>
            <Button
              size="sm"
              color="primary"
              variant="flat"
              startContent={<LocalIcon icon="lucide:plus" />}
              onPress={() => {
                addCorsItem('allowHeaders', headerInput);
                setHeaderInput('');
              }}
            >
              {t('gateway.add_header')}
            </Button>
          </div>
          <div className="flex flex-wrap gap-1 mb-2">
            {(corsConfig.allowHeaders || []).map((header: string, headerIndex: number) => (
              <Chip
                key={headerIndex}
                onClose={() => removeCorsItem('allowHeaders', headerIndex)}
                variant="flat"
              >
                {header}
              </Chip>
            ))}
          </div>
          <Input
            size="sm"
            placeholder={t('gateway.header_placeholder')}
            value={headerInput}
            onChange={(e) => setHeaderInput(e.target.value)}
            list={`common-headers-${index}`}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                addCorsItem('allowHeaders', headerInput);
                setHeaderInput('');
              }
            }}
          />
          <datalist id={`common-headers-${index}`}>
            <option value="Content-Type" />
            <option value="Authorization" />
            <option value="X-Requested-With" />
            <option value="Accept" />
            <option value="Origin" />
            <option value="Mcp-Session-Id" />
            <option value="mcp-protocol-version" />
          </datalist>
        </div>

        <div>
          <div className="flex justify-between items-center mb-3">
            <h4 className="text-md font-medium">{t('gateway.expose_headers')}</h4>
            <Button
              size="sm"
              color="primary"
              variant="flat"
              startContent={<LocalIcon icon="lucide:plus" />}
              onPress={() => {
                addCorsItem('exposeHeaders', exposeHeaderInput);
                setExposeHeaderInput('');
              }}
            >
              {t('gateway.add_expose_header')}
            </Button>
          </div>
          <div className="flex flex-wrap gap-1 mb-2">
            {(corsConfig.exposeHeaders || []).map((header: string, headerIndex: number) => (
              <Chip
                key={headerIndex}
                onClose={() => removeCorsItem('exposeHeaders', headerIndex)}
                variant="flat"
              >
                {header}
              </Chip>
            ))}
          </div>
          <Input
            size="sm"
            placeholder={t('gateway.expose_header_placeholder')}
            value={exposeHeaderInput}
            onChange={(e) => setExposeHeaderInput(e.target.value)}
            list={`common-expose-headers-${index}`}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                addCorsItem('exposeHeaders', exposeHeaderInput);
                setExposeHeaderInput('');
              }
            }}
          />
          <datalist id={`common-expose-headers-${index}`}>
            <option value="Content-Length" />
            <option value="Mcp-Session-Id" />
            <option value="mcp-protocol-version" />			
            <option value="X-Rate-Limit" />
          </datalist>
        </div>

        <div className="flex items-center gap-2">
          <Switch
            size="sm"
            isSelected={Boolean(corsConfig.allowCredentials)}
            onValueChange={(isSelected) => updateCors({ allowCredentials: isSelected })}
          />
          <span className="text-sm font-medium">{t('gateway.credentials')}</span>
        </div>
      </div>
    );
  };

  return (
    <div className="space-y-4">
      <Accordion variant="splitted">
        {routers.map((router, index) => (
          <AccordionItem
            key={index}
            title={router.prefix || `Router ${index + 1}`}
            subtitle={router.server}
            startContent={
              <LocalIcon icon="lucide:route"
                className="text-primary-500"
              />
            }
          >
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <Input
                  label={t('gateway.prefix')}
                  value={(router.prefix || "").replace(selectedTenant?.prefix || "", "")}
                  startContent={
                    <div className="pointer-events-none flex items-center">
                      <span className="text-default-400 text-small">{selectedTenant?.prefix}</span>
                    </div>
                  }
                  onChange={(e) => {
                    const pathPart = e.target.value.trim();
                    const fullPrefix = `${selectedTenant?.prefix}${pathPart}`;
                    updateRouter(index, 'prefix', fullPrefix);
                  }}
                />
                <Select
                  label={t('gateway.server')}
                  selectedKeys={router.server ? [router.server] : []}
                  aria-label={t('gateway.server')}
                  onChange={(e) => updateRouter(index, 'server', e.target.value)}
                >
                  <>
                    {(parsedConfig?.servers || []).map(server => (
                      <SelectItem key={server.name} textValue={server.name}>
                        {server.name}
                      </SelectItem>
                    ))}
                    {(parsedConfig?.mcpServers || []).map(server => (
                      <SelectItem key={server.name} textValue={server.name}>
                        {server.name}
                      </SelectItem>
                    ))}
                  </>
                </Select>
                <Input
                  label={t('gateway.sse_prefix')}
                  value={(router.ssePrefix || "")}
                  onChange={(e) => {
                    const pathPart = e.target.value.trim();
                    updateRouter(index, 'ssePrefix', pathPart);
                  }}
                  placeholder={t('gateway.sse_prefix_placeholder')}
                />
              </div>

              {/* CORS配置部分 */}
              <div className="bg-content1 p-4 rounded-medium border border-content2">
                <div className="flex items-center gap-2 mb-4">
                  <Switch
                    size="sm"
                    isSelected={Boolean(router.cors)}
                    onValueChange={(isSelected) => {
                      if (isSelected) {
                        updateConfig({
                          routers: routers.map((r, i) =>
                            i === index ? {
                              ...r,
                              cors: {
                                allowOrigins: ['*'],
                                allowMethods: ['GET', 'POST', 'PUT', 'OPTIONS'],
                                allowHeaders: ['Content-Type', 'Authorization', 'Mcp-Session-Id', 'mcp-protocol-version' ],
                                exposeHeaders: ['Mcp-Session-Id' ,'mcp-protocol-version'],
                                allowCredentials: true
                              }
                            } : r
                          )
                        });
                      } else {
                        const updatedRouters = [...routers];
                        const { cors: _, ...restRouter } = updatedRouters[index];
                        updatedRouters[index] = restRouter;
                        updateConfig({ routers: updatedRouters });
                      }
                    }}
                  />
                  <span className="text-sm font-medium">{t('gateway.enable_cors')}</span>
                </div>

                {router.cors && renderCorsConfig(router, index)}
              </div>

              {/* 认证开关部分 */}
              <div className="space-y-4">
                <div className="flex items-center gap-2">
                  <Switch
                    size="sm"
                    isSelected={Boolean(router.auth)}
                    onValueChange={(isSelected) => {
                      const updatedRouters = [...routers];
                      if (isSelected) {
                        updatedRouters[index] = {
                          ...updatedRouters[index],
                          auth: { mode: 'oauth2' }
                        };
                      } else {
                        const { auth: _auth, ...rest } = updatedRouters[index];
                        updatedRouters[index] = rest;
                      }
                      updateConfig({ routers: updatedRouters });
                    }}
                  />
                  <span className="text-sm font-medium">{t('gateway.enable_auth')}</span>
                </div>

                {router.auth && (
                  <div className="pl-6">
                    <Select
                      size="sm"
                      label={t('gateway.auth_mode')}
                      selectedKeys={['oauth2']}
                      aria-label={t('gateway.auth_mode')}
                      isDisabled={true}
                    >
                      <SelectItem key="oauth2" textValue="OAuth2">OAuth2</SelectItem>
                    </Select>
                  </div>
                )}
              </div>

              <div className="flex justify-end">
                <Button
                  color="danger"
                  variant="flat"
                  size="sm"
                  startContent={<LocalIcon icon="lucide:trash-2" />}
                  onPress={() => {
                    const updatedRouters = [...routers];
                    updatedRouters.splice(index, 1);
                    updateConfig({ routers: updatedRouters });
                  }}
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
          onPress={() => {
            const updatedRouters = [...routers];
            const serverName = parsedConfig?.servers?.[0]?.name || parsedConfig?.mcpServers?.[0]?.name || "";

            updatedRouters.push({
              server: serverName,
              prefix: selectedTenant?.prefix + '/' + Math.random().toString(36).substring(2, 6)
            });
            updateConfig({ routers: updatedRouters });
          }}
        >
          {t('gateway.add_router')}
        </Button>
      </div>
    </div>
  );
}
