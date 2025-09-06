import {useParams, useNavigate} from 'react-router-dom';
import {Button, Breadcrumbs, BreadcrumbItem} from '@heroui/react';
import {useTranslation} from 'react-i18next';

import CapabilitiesViewer from './components/CapabilitiesViewer';
import LocalIcon from '../../components/LocalIcon';

export default function CapabilitiesPage() {
  const {t} = useTranslation();
  const navigate = useNavigate();
  const {tenant, serverName} = useParams<{tenant: string; serverName: string}>();

  if (!tenant || !serverName) {
    return (
      <div className="container mx-auto p-4">
        <div className="text-center py-8">
          <p className="text-danger">{t('errors.server_error')}</p>
          <Button 
            color="primary" 
            onPress={() => navigate('/gateway')}
            className="mt-4"
          >
            {t('common.back')}
          </Button>
        </div>
      </div>
    );
  }

  return (
    <div className="container mx-auto p-4 min-h-screen">
      {/* 面包屑导航 */}
      <div className="mb-6">
        <Breadcrumbs>
          <BreadcrumbItem onPress={() => navigate('/gateway')}>
            <div className="flex items-center gap-2">
              <LocalIcon icon="lucide:server" className="text-sm" />
              {t('nav.gateway')}
            </div>
          </BreadcrumbItem>
          <BreadcrumbItem>
            <div className="flex items-center gap-2">
              <LocalIcon icon="lucide:brain" className="text-sm" />
              {t('capabilities.mcp_service_capabilities')}
            </div>
          </BreadcrumbItem>
        </Breadcrumbs>
      </div>

      {/* 页面标题 */}
      <div className="mb-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-3 bg-gradient-to-br from-primary-100 to-secondary-100 rounded-lg">
              <LocalIcon icon="lucide:brain" className="text-xl text-primary-600" />
            </div>
            <div>
              <div className="flex items-center gap-2 mb-1">
                <h1 className="text-2xl font-bold">
                  {t('capabilities.mcp_service_capabilities')}
                </h1>
                <div className="px-3 py-1 bg-primary-100 text-primary-700 rounded-full text-sm font-medium">
                  MCP
                </div>
              </div>
              <div className="flex items-center gap-2 text-default-600">
                <LocalIcon icon="lucide:server" className="text-sm" />
                <span className="font-medium">{t('capabilities.service_name')}:</span>
                <code className="px-2 py-1 bg-default-100 rounded text-sm font-mono">{serverName}</code>
                <span className="text-default-400">•</span>
                <span className="font-medium">{t('capabilities.tenant')}:</span>
                <code className="px-2 py-1 bg-default-100 rounded text-sm font-mono">{tenant}</code>
              </div>
              <p className="text-default-500 mt-2">
                {t('capabilities.mcp_service_description')}
              </p>
            </div>
          </div>
          <Button
            color="default"
            variant="light"
            startContent={<LocalIcon icon="lucide:chevron-left" />}
            onPress={() => navigate('/gateway')}
          >
            {t('common.back')}
          </Button>
        </div>
      </div>

      {/* 能力查看器 */}
      <div className="bg-content1 rounded-large shadow-small p-6">
        <CapabilitiesViewer
          tenant={tenant}
          serverName={serverName}
          enableToolManagement={true}
          onToolStatusChange={(toolName, enabled) => {
            console.log(`Tool ${toolName} ${enabled ? 'enabled' : 'disabled'}`);
          }}
          onBatchToolStatusChange={(updates) => {
            console.log(`Batch update:`, updates);
          }}
        />
      </div>
    </div>
  );
}