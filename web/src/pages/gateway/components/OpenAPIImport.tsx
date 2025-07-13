import { Button, Dropdown, DropdownTrigger, DropdownMenu, DropdownItem, Input } from '@heroui/react';
import React, { useCallback, useState, useEffect } from 'react';
import { useDropzone } from 'react-dropzone';
import { useTranslation } from 'react-i18next';

import LocalIcon from '@/components/LocalIcon';
import { importOpenAPI, getTenants } from '@/services/api';
import type { Tenant } from '@/types/gateway';
import { toast } from "@/utils/toast.ts";

interface OpenAPIImportProps {
  onSuccess?: () => void;
  selectedTenant?: string;
}

const OpenAPIImport: React.FC<OpenAPIImportProps> = ({ onSuccess, selectedTenant: inheritedTenant }) => {
  const { t } = useTranslation();
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [selectedTenant, setSelectedTenant] = useState<string>('');
  const [prefix, setPrefix] = useState('');
  const [loadingTenants, setLoadingTenants] = useState(false);

  useEffect(() => {
    if (tenants.length === 0) {
      setLoadingTenants(true);
      getTenants()
        .then((data) => {
          setTenants(data);
          // Set default tenant selection
          if (inheritedTenant) {
            // Use inherited tenant from gateway page
            const tenant = data.find((t: Tenant) => t.name === inheritedTenant);
            if (tenant) {
              setSelectedTenant(tenant.name);
            }
          } else if (data.length > 0) {
            // Default to first tenant if no inheritance
            setSelectedTenant(data[0].name);
          }
        })
        .catch(() => toast.error(t('errors.fetch_tenants')))
        .finally(() => setLoadingTenants(false));
    }
  }, [tenants.length, inheritedTenant, t]);

  const onDrop = useCallback(async (acceptedFiles: globalThis.File[]) => {
    if (acceptedFiles.length === 0) {
      toast.error(t('errors.invalid_openapi_file'), {
        duration: 3000,
      });
      return;
    }

    try {
      // Find the selected tenant object
      const tenantObj = tenants.find((t: Tenant) => t.name === selectedTenant);
      if (!tenantObj) {
        toast.error(t('errors.select_tenant_required', 'Please select a tenant'), {
          duration: 3000,
        });
        return;
      }

      const tenantName = tenantObj.name;
      await importOpenAPI(acceptedFiles[0], tenantName, prefix);
      toast.success(t('errors.import_openapi_success'), {
        duration: 3000,
      });
      onSuccess?.();
    } catch {
      toast.error(t('errors.import_openapi_failed'), {
        duration: 3000,
      })
    }
  }, [onSuccess, selectedTenant, prefix, tenants, t]);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'application/json': ['.json'],
      'application/yaml': ['.yaml', '.yml'],
      'text/yaml': ['.yaml', '.yml']
    },
    multiple: false
  });

  return (
    <div className="w-full space-y-6">
      {/* Configuration Section */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <LocalIcon icon="lucide:building" className="text-lg text-primary" />
            <label className="text-sm font-medium">{t('gateway.tenant', 'Tenant')}</label>
          </div>
          <Dropdown isDisabled={loadingTenants || tenants.length === 0} className="w-full">
            <DropdownTrigger>
              <Button variant="bordered" className="w-full justify-start" size="lg">
                {loadingTenants ? (
                  <div className="flex items-center gap-2">
                    <div className="w-4 h-4 border-2 border-primary border-t-transparent rounded-full animate-spin" />
                    {t('common.loading', 'Loading...')}
                  </div>
                ) : selectedTenant ? (
                  <div className="flex items-center gap-2">
                    <LocalIcon icon="lucide:check-circle" className="text-success" />
                    {tenants.find(t => t.name === selectedTenant)?.name}
                  </div>
                ) : (
                  <div className="flex items-center gap-2">
                    <LocalIcon icon="lucide:building" className="text-default-400" />
                    {t('gateway.select_tenant', 'Select Tenant')}
                  </div>
                )}
              </Button>
            </DropdownTrigger>
            <DropdownMenu aria-label="Tenant List" selectionMode="single" selectedKeys={selectedTenant ? [selectedTenant] : []} onAction={key => setSelectedTenant(key as string)}>
              {tenants.map(tenant => (
                <DropdownItem key={tenant.name}>
                  <div className="flex items-center gap-2">
                    <LocalIcon icon="lucide:building" className="text-primary" />
                    <span>{tenant.name}</span>
                    <span className="text-xs text-default-400">({tenant.prefix})</span>
                  </div>
                </DropdownItem>
              ))}
            </DropdownMenu>
          </Dropdown>
        </div>

        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <LocalIcon icon="lucide:tag" className="text-lg text-primary" />
            <label className="text-sm font-medium">{t('gateway.prefix', 'Prefix')}</label>
          </div>
          <Input
            value={prefix}
            onChange={e => setPrefix(e.target.value)}
            placeholder={t('gateway.prefix_placeholder', 'Enter prefix (optional)')}
            size="lg"
            startContent={
              <div className="pointer-events-none flex items-center">
                <span className="text-default-400 text-small">
                  {selectedTenant ? `${tenants.find(t => t.name === selectedTenant)?.prefix}/` : '/'}
                </span>
              </div>
            }
          />
        </div>
      </div>

      {/* File Upload Section */}
      <div className="space-y-4">
        <div className="flex items-center gap-2">
          <LocalIcon icon="lucide:upload-cloud" className="text-xl text-primary" />
          <h3 className="text-lg font-semibold">{t('gateway.upload_openapi_file', 'Upload OpenAPI File')}</h3>
        </div>

        <div
          {...getRootProps()}
          className={`relative flex flex-col items-center justify-center p-8 border-2 border-dashed rounded-xl cursor-pointer transition-all duration-200 ${
            isDragActive
              ? 'bg-primary/10 border-primary scale-[1.02] shadow-lg'
              : 'bg-content1 border-divider hover:border-primary/50 hover:bg-content2/50'
          }`}
        >
          <input {...getInputProps()} style={{ display: 'none' }} />

          <div className={`p-4 rounded-full mb-4 transition-colors ${
            isDragActive ? 'bg-primary/20' : 'bg-primary/10'
          }`}>
            <LocalIcon
              icon={isDragActive ? "lucide:download" : "lucide:upload-cloud"}
              className={`text-3xl transition-colors ${
                isDragActive ? 'text-primary' : 'text-primary/70'
              }`}
            />
          </div>

          {isDragActive ? (
            <div className="text-center">
              <p className="text-lg font-medium text-primary mb-2">
                {t('gateway.drop_file_here', 'Drop the file here')}
              </p>
              <p className="text-sm text-default-500">
                {t('gateway.release_to_upload', 'Release to upload')}
              </p>
            </div>
          ) : (
            <div className="text-center">
              <p className="text-lg font-medium mb-2">
                {t('gateway.drag_drop_openapi', 'Drag and drop your OpenAPI specification')}
              </p>
              <p className="text-sm text-default-500 mb-4">
                {t('gateway.or_click_to_browse', 'or click to browse files')}
              </p>
              <Button
                color="primary"
                variant="flat"
                size="lg"
                className="font-medium"
                onClick={e => {
                  e.stopPropagation();
                  document.querySelector<HTMLInputElement>('input[type="file"]')?.click();
                }}
              >
                <LocalIcon icon="lucide:folder-open" className="mr-2" />
                {t('gateway.select_file', 'Select File')}
              </Button>
            </div>
          )}

          <div className="mt-6 flex flex-wrap gap-2 justify-center">
            <div className="flex items-center gap-1 px-3 py-1 bg-success/10 text-success rounded-full text-xs">
              <LocalIcon icon="lucide:file-text" className="text-sm" />
              JSON
            </div>
            <div className="flex items-center gap-1 px-3 py-1 bg-warning/10 text-warning rounded-full text-xs">
              <LocalIcon icon="lucide:file-code" className="text-sm" />
              YAML
            </div>
            <div className="flex items-center gap-1 px-3 py-1 bg-secondary/10 text-secondary rounded-full text-xs">
              <LocalIcon icon="lucide:file-code" className="text-sm" />
              YML
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default OpenAPIImport;
