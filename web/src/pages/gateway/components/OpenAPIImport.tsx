import { Card, CardBody, Button, Dropdown, DropdownTrigger, DropdownMenu, DropdownItem, Input } from '@heroui/react';
import { t } from 'i18next';
import React, { useCallback, useState, useEffect } from 'react';
import { useDropzone } from 'react-dropzone';

import LocalIcon from '@/components/LocalIcon';
import { importOpenAPI, getTenants } from '@/services/api';
import { toast } from "@/utils/toast.ts";
import type { Tenant } from '@/types/gateway';

interface OpenAPIImportProps {
  onSuccess?: () => void;
}

const OpenAPIImport: React.FC<OpenAPIImportProps> = ({ onSuccess }) => {
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [selectedTenant, setSelectedTenant] = useState<string>('');
  const [prefix, setPrefix] = useState('');
  const [loadingTenants, setLoadingTenants] = useState(false);

  useEffect(() => {
    if (showAdvanced && tenants.length === 0) {
      setLoadingTenants(true);
      getTenants()
        .then((data) => setTenants(data))
        .catch(() => toast.error(t('errors.fetch_tenants')))
        .finally(() => setLoadingTenants(false));
    }
  }, [showAdvanced, tenants.length]);

  const onDrop = useCallback(async (acceptedFiles: globalThis.File[]) => {
    if (acceptedFiles.length === 0) {
      toast.error(t('errors.invalid_openapi_file'), {
        duration: 3000,
      });
      return;
    }

    try {
      // Find the selected tenant object
      const tenantObj = tenants.find((t: Tenant) => t.id.toString() === selectedTenant);
      // Use tenant.prefix if available, otherwise empty string
      const tenantPrefix = tenantObj ? tenantObj.prefix : '';
      await importOpenAPI(acceptedFiles[0], tenantPrefix, prefix);
      toast.success(t('errors.import_openapi_success'), {
        duration: 3000,
      });
      onSuccess?.();
    } catch {
      toast.error(t('errors.import_openapi_failed'), {
        duration: 3000,
      })
    }
  }, [onSuccess, selectedTenant, prefix, tenants]);

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
    <Card className="w-full">
      <CardBody>
        <div
          {...getRootProps()}
          className={`flex flex-col items-center justify-center p-6 border-2 border-dashed rounded-lg cursor-pointer transition-colors ${
            isDragActive ? 'bg-primary/10 border-primary' : 'bg-content2 border-divider'
          }`}
        >
          <input {...getInputProps()} style={{ display: 'none' }} />
          <LocalIcon icon="lucide:upload" className="text-4xl mb-4 text-primary" />
          {isDragActive ? (
            <p className="text-lg text-primary">Drop the OpenAPI specification file here...</p>
          ) : (
            <div className="text-center">
              <p className="text-lg">Drag and drop an OpenAPI specification file here</p>
              <p className="text-sm text-default-500 mt-2">or</p>
              <Button color="primary" variant="flat" className="mt-2" onClick={e => { e.stopPropagation(); document.querySelector<HTMLInputElement>('input[type="file"]')?.click(); }}>
                Select a file
              </Button>
            </div>
          )}
          <p className="text-sm text-default-500 mt-4">
            Supported formats: JSON (.json), YAML (.yaml, .yml)
          </p>
        </div>
        <div className="mt-4 w-full flex flex-col items-center">
          <Button size="sm" variant="light" onClick={() => setShowAdvanced((v) => !v)}>
            {showAdvanced ? t('common.hide_advanced_options', 'Hide Advanced Options') : t('common.show_advanced_options', 'Show Advanced Options')}
          </Button>
          {showAdvanced && (
            <div className="w-full mt-4 flex flex-col gap-4 items-center">
              <div className="w-full max-w-xs">
                <label className="block text-sm font-medium mb-1">{t('gateway.tenant', 'Tenant')}</label>
                <Dropdown isDisabled={loadingTenants || tenants.length === 0} className="w-full">
                  <DropdownTrigger>
                    <Button variant="bordered" className="w-full">
                      {selectedTenant ? tenants.find(t => t.id.toString() === selectedTenant)?.name : t('gateway.select_tenant', 'Select Tenant')}
                    </Button>
                  </DropdownTrigger>
                  <DropdownMenu aria-label="Tenant List" selectionMode="single" selectedKeys={selectedTenant ? [selectedTenant] : []} onAction={key => setSelectedTenant(key as string)}>
                    {tenants.map(tenant => (
                      <DropdownItem key={tenant.id.toString()}>{tenant.name}</DropdownItem>
                    ))}
                  </DropdownMenu>
                </Dropdown>
              </div>
              <div className="w-full max-w-xs">
                <label className="block text-sm font-medium mb-1">{t('gateway.prefix', 'Prefix')}</label>
                <Input value={prefix} onChange={e => setPrefix(e.target.value)} placeholder={t('gateway.prefix_placeholder', 'Enter prefix (optional)')} />
              </div>
            </div>
          )}
        </div>
      </CardBody>
    </Card>
  );
};

export default OpenAPIImport;
