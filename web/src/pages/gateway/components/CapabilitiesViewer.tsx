import {
  Button,
  Card,
  CardBody,
  Chip,
  Input,
  Modal,
  ModalBody,
  ModalContent,
  ModalFooter,
  ModalHeader,
  Spinner,
  useDisclosure,
  Dropdown,
  DropdownTrigger,
  DropdownMenu,
  DropdownItem,
  Code,
  Divider,
  Tabs,
  Tab
} from '@heroui/react';
import React from 'react';
import {useTranslation} from 'react-i18next';
import hljs from 'highlight.js/lib/core';
import json from 'highlight.js/lib/languages/json';
import yaml from 'highlight.js/lib/languages/yaml';
import copy from 'copy-to-clipboard';
import YAML from 'js-yaml';
import 'highlight.js/styles/github.css';

import LocalIcon from '@/components/LocalIcon';
import {getMCPServerCapabilities} from '@/services/api';
import type {
  CapabilitiesState,
  CapabilityItem,
  CapabilityType,
  MCPCapabilities,
  Tool,
  Prompt,
  Resource,
  ResourceTemplate
} from '@/types/mcp';
import {toast} from '@/utils/toast';

// 注册高亮语言
hljs.registerLanguage('json', json);
hljs.registerLanguage('yaml', yaml);

// 代码高亮组件
interface CodeHighlightProps {
  code: string;
  language: 'json' | 'yaml';
  className?: string;
}

const CodeHighlight: React.FC<CodeHighlightProps> = ({ code, language, className = '' }) => {
  const [highlighted, setHighlighted] = React.useState('');

  React.useEffect(() => {
    const result = hljs.highlight(code, { language });
    setHighlighted(result.value);
  }, [code, language]);

  const handleCopy = () => {
    if (copy(code)) {
      toast.success('复制成功');
    } else {
      toast.error('复制失败');
    }
  };

  return (
    <div className={`relative group ${className}`}>
      <div className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity">
        <Button
          isIconOnly
          size="sm"
          variant="flat"
          onPress={handleCopy}
          aria-label="复制代码"
          className="bg-default-100/80 backdrop-blur-sm"
        >
          <LocalIcon icon="lucide:copy" className="text-sm" />
        </Button>
      </div>
      <pre className="text-sm overflow-x-auto bg-default-100 p-4 rounded-lg">
        <code 
          className={`hljs language-${language}`}
          dangerouslySetInnerHTML={{ __html: highlighted }}
        />
      </pre>
    </div>
  );
};

// 导出功能组件
interface ExportButtonProps {
  data: any;
  filename: string;
  className?: string;
}

const ExportButton: React.FC<ExportButtonProps> = ({ data, filename, className = '' }) => {
  const { t } = useTranslation();

  const handleExport = (format: 'json' | 'yaml') => {
    try {
      let content: string;
      let mimeType: string;
      let extension: string;
      
      if (format === 'json') {
        content = JSON.stringify(data, null, 2);
        mimeType = 'application/json';
        extension = 'json';
      } else {
        content = YAML.dump(data, { indent: 2 });
        mimeType = 'text/yaml';
        extension = 'yaml';
      }
      
      const blob = new Blob([content], { type: mimeType });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `${filename}.${extension}`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
      
      toast.success(t('capabilities.export_success'));
    } catch (error) {
      toast.error(t('capabilities.export_failed'));
    }
  };

  return (
    <Dropdown className={className}>
      <DropdownTrigger>
        <Button
          variant="flat"
          size="sm"
          startContent={<LocalIcon icon="lucide:download" />}
        >
          {t('capabilities.export')}
        </Button>
      </DropdownTrigger>
      <DropdownMenu
        aria-label="导出格式"
        onAction={(key) => handleExport(key as 'json' | 'yaml')}
      >
        <DropdownItem key="json" startContent={<LocalIcon icon="lucide:file-json" />}>
          导出为 JSON
        </DropdownItem>
        <DropdownItem key="yaml" startContent={<LocalIcon icon="lucide:file-code" />}>
          导出为 YAML
        </DropdownItem>
      </DropdownMenu>
    </Dropdown>
  );
};

// 能力详情Modal组件
interface CapabilityDetailModalProps {
  isOpen: boolean;
  onClose: () => void;
  capability: CapabilityItem | null;
  type: CapabilityType;
}

const CapabilityDetailModal: React.FC<CapabilityDetailModalProps> = ({
  isOpen,
  onClose,
  capability,
  type
}) => {
  const {t} = useTranslation();

  // 移除选项卡相关状态和逻辑，简化组件

  const renderToolDetails = (tool: Tool) => {
    const hasProperties = tool.inputSchema?.properties && Object.keys(tool.inputSchema.properties).length > 0;
    
    return (
      <div className="space-y-6">
        {/* 基本信息 */}
        <div className="space-y-4">
          {tool.description && (
            <div>
              <h4 className="text-sm font-semibold mb-2 flex items-center gap-2">
                <LocalIcon icon="lucide:file-text" className="text-sm" />
                {t('common.description')}
              </h4>
              <div className="bg-default-50 p-3 rounded-lg">
                <p className="text-sm text-default-700">{tool.description}</p>
              </div>
            </div>
          )}
        </div>

        {/* 参数信息 */}
        <div>
          <h3 className="text-lg font-semibold mb-3 flex items-center gap-2">
            <LocalIcon icon="lucide:wrench" className="text-lg" />
            参数信息
          </h3>
          
          <div className="space-y-4">
            {/* 参数统计 */}
            <div className="flex gap-2">
              <Chip variant="flat" color="secondary" size="sm">
                {hasProperties ? Object.keys(tool.inputSchema.properties!).length : 0} 个参数
              </Chip>
              <Chip variant="flat" color="default" size="sm">
                {tool.inputSchema?.type || 'object'} 类型
              </Chip>
            </div>

            {/* 参数详情 */}
            {hasProperties ? (
              <div className="space-y-3">
                {Object.entries(tool.inputSchema.properties!).map(([key, prop]: [string, any]) => (
                  <div key={key} className="border border-default-200 rounded-lg p-3">
                    <div className="flex items-center gap-2 mb-2">
                      <Code color="primary" size="sm">{key}</Code>
                      {prop.type && (
                        <Chip variant="flat" color="secondary" size="sm">{prop.type}</Chip>
                      )}
                      {(tool.inputSchema.required as string[])?.includes?.(key) && (
                        <Chip variant="flat" color="danger" size="sm">
                          {t('common.required')}
                        </Chip>
                      )}
                    </div>
                    {prop.description && (
                      <p className="text-xs text-default-600 mb-2">{prop.description}</p>
                    )}
                    {prop.enum && (
                      <div>
                        <span className="text-xs text-default-500 font-medium">可选值: </span>
                        <div className="flex gap-1 flex-wrap mt-1">
                          {prop.enum.map((value: any, index: number) => (
                            <Code key={index} size="sm" color="default">{String(value)}</Code>
                          ))}
                        </div>
                      </div>
                    )}
                    {prop.default !== undefined && (
                      <div>
                        <span className="text-xs text-default-500 font-medium">默认值: </span>
                        <Code size="sm" color="success">{JSON.stringify(prop.default)}</Code>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-8">
                <LocalIcon icon="lucide:folder-open" className="text-4xl text-default-300 mb-2" />
                <p className="text-default-500">该工具无参数</p>
              </div>
            )}
          </div>
        </div>

        {/* JSON Schema */}
        <div>
          <div className="flex justify-between items-center mb-3">
            <h3 className="text-lg font-semibold flex items-center gap-2">
              <LocalIcon icon="lucide:file-code" className="text-lg" />
              JSON Schema
            </h3>
            <ExportButton data={tool.inputSchema} filename={`tool-${tool.name}-schema`} />
          </div>
          <CodeHighlight 
            code={JSON.stringify(tool.inputSchema, null, 2)} 
            language="json" 
          />
        </div>
      </div>
    );
  };

  const renderPromptDetails = (prompt: Prompt) => {
    const hasArguments = prompt.arguments && prompt.arguments.length > 0;
    
    return (
      <div className="space-y-6">
        {/* 基本信息 */}
        <div className="space-y-4">
          {prompt.description && (
            <div>
              <h4 className="text-sm font-semibold mb-2 flex items-center gap-2">
                <LocalIcon icon="lucide:file-text" className="text-sm" />
                {t('common.description')}
              </h4>
              <div className="bg-default-50 p-3 rounded-lg">
                <p className="text-sm text-default-700">{prompt.description}</p>
              </div>
            </div>
          )}
          
          <div>
            <h4 className="text-sm font-semibold mb-2 flex items-center gap-2">
              <LocalIcon icon="lucide:wrench" className="text-sm" />
              参数统计
            </h4>
            <div className="flex gap-2">
              <Chip variant="flat" color="secondary" size="sm">
                {hasArguments ? prompt.arguments!.length : 0} 个参数
              </Chip>
              {hasArguments && (
                <Chip variant="flat" color="danger" size="sm">
                  {prompt.arguments!.filter(arg => arg.required).length} 个必填
                </Chip>
              )}
            </div>
          </div>
        </div>

        {/* 参数列表 */}
        <div className="space-y-4">
          <h4 className="text-sm font-semibold flex items-center gap-2">
            <LocalIcon icon="lucide:file-text" className="text-sm" />
            参数列表
          </h4>
          {hasArguments ? (
            <div className="space-y-3">
              {prompt.arguments!.map((arg, index) => (
                <div key={index} className="border border-default-200 rounded-lg p-3">
                  <div className="flex items-center gap-2 mb-2">
                    <Code color="secondary" size="sm">{arg.name}</Code>
                    {arg.required && (
                      <Chip variant="flat" color="danger" size="sm">
                        {t('common.required')}
                      </Chip>
                    )}
                  </div>
                  {arg.description && (
                    <p className="text-sm text-default-600">{arg.description}</p>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8">
              <LocalIcon icon="lucide:folder-open" className="text-4xl text-default-300 mb-2" />
              <p className="text-default-500">该提示无参数</p>
            </div>
          )}
        </div>

        {/* 原始数据 */}
        <div className="space-y-4">
          <div className="flex justify-between items-center">
            <h4 className="text-sm font-semibold flex items-center gap-2">
              <LocalIcon icon="lucide:file-code" className="text-sm" />
              Prompt 数据
            </h4>
            <ExportButton data={prompt} filename={`prompt-${prompt.name}`} />
          </div>
          <CodeHighlight 
            code={JSON.stringify(prompt, null, 2)} 
            language="json" 
          />
        </div>
      </div>
    );
  };

  const renderResourceDetails = (resource: Resource) => {
    return (
      <div className="space-y-6">
        {/* 基本信息 */}
        <div className="space-y-4">
          <div>
            <h4 className="text-sm font-semibold mb-2 flex items-center gap-2">
              <LocalIcon icon="lucide:external-link" className="text-sm" />
              {t('capabilities.resource_uri')}
            </h4>
            <div className="bg-default-100 p-3 rounded-lg">
              <code className="text-sm break-all font-mono">{resource.uri}</code>
              <Button
                isIconOnly
                size="sm"
                variant="light"
                className="ml-2"
                onPress={() => copy(resource.uri) && toast.success('复制成功')}
                aria-label="复制URI"
              >
                <LocalIcon icon="lucide:copy" className="text-sm" />
              </Button>
            </div>
          </div>
          
          {resource.mimeType && (
            <div>
              <h4 className="text-sm font-semibold mb-2 flex items-center gap-2">
                <LocalIcon icon="lucide:file-code" className="text-sm" />
                MIME 类型
              </h4>
              <Chip variant="flat" color="secondary">{resource.mimeType}</Chip>
            </div>
          )}
          
          {resource.description && (
            <div>
              <h4 className="text-sm font-semibold mb-2 flex items-center gap-2">
                <LocalIcon icon="lucide:file-text" className="text-sm" />
                {t('common.description')}
              </h4>
              <div className="bg-default-50 p-3 rounded-lg">
                <p className="text-sm text-default-700">{resource.description}</p>
              </div>
            </div>
          )}
        </div>

        {/* 原始数据 */}
        <div className="space-y-4">
          <div className="flex justify-between items-center">
            <h4 className="text-sm font-semibold flex items-center gap-2">
              <LocalIcon icon="lucide:file-code" className="text-sm" />
              Resource 数据
            </h4>
            <ExportButton data={resource} filename={`resource-${resource.name}`} />
          </div>
          <CodeHighlight 
            code={JSON.stringify(resource, null, 2)} 
            language="json" 
          />
        </div>
      </div>
    );
  };

  const renderResourceTemplateDetails = (template: ResourceTemplate) => {
    const extractTemplateParams = (uriTemplate: string): string[] => {
      const matches = uriTemplate.match(/\{([^}]+)\}/g);
      return matches ? matches.map(match => match.slice(1, -1)) : [];
    };
    
    const templateParams = extractTemplateParams(template.uriTemplate);
    
    return (
      <div className="space-y-6">
        {/* 基本信息 */}
        <div className="space-y-4">
          
          <div>
            <h4 className="text-sm font-semibold mb-2 flex items-center gap-2">
              <LocalIcon icon="lucide:file-code" className="text-sm" />
              URI 模板
            </h4>
            <div className="bg-default-100 p-3 rounded-lg">
              <code className="text-sm break-all font-mono">{template.uriTemplate}</code>
              <Button
                isIconOnly
                size="sm"
                variant="light"
                className="ml-2"
                onPress={() => copy(template.uriTemplate) && toast.success('复制成功')}
                aria-label="复制URI模板"
              >
                <LocalIcon icon="lucide:copy" className="text-sm" />
              </Button>
            </div>
          </div>
          
          {templateParams.length > 0 && (
            <div>
              <h4 className="text-sm font-semibold mb-2 flex items-center gap-2">
                <LocalIcon icon="lucide:wrench" className="text-sm" />
                模板参数
              </h4>
              <div className="flex gap-1 flex-wrap">
                {templateParams.map((param, index) => (
                  <Code key={index} size="sm" color="warning">{param}</Code>
                ))}
              </div>
            </div>
          )}
          
          {template.mimeType && (
            <div>
              <h4 className="text-sm font-semibold mb-2 flex items-center gap-2">
                <LocalIcon icon="lucide:file-code" className="text-sm" />
                MIME 类型
              </h4>
              <Chip variant="flat" color="secondary">{template.mimeType}</Chip>
            </div>
          )}
          
          {template.description && (
            <div>
              <h4 className="text-sm font-semibold mb-2 flex items-center gap-2">
                <LocalIcon icon="lucide:file-text" className="text-sm" />
                {t('common.description')}
              </h4>
              <div className="bg-default-50 p-3 rounded-lg">
                <p className="text-sm text-default-700">{template.description}</p>
              </div>
            </div>
          )}
        </div>

        {/* 原始数据 */}
        <div className="space-y-4">
          <div className="flex justify-between items-center">
            <h4 className="text-sm font-semibold flex items-center gap-2">
              <LocalIcon icon="lucide:file-code" className="text-sm" />
              Resource Template 数据
            </h4>
            <ExportButton data={template} filename={`resource-template-${template.name}`} />
          </div>
          <CodeHighlight 
            code={JSON.stringify(template, null, 2)} 
            language="json" 
          />
        </div>
      </div>
    );
  };

  const renderDetailContent = () => {
    if (!capability) return null;

    switch (type) {
      case 'tools':
        return renderToolDetails({...capability, inputSchema: (capability as any).inputSchema} as Tool);
      case 'prompts':
        return renderPromptDetails({...capability, arguments: (capability as any).arguments} as Prompt);
      case 'resources':
        return renderResourceDetails({...capability, uri: (capability as any).uri} as Resource);
      case 'resourceTemplates':
        return renderResourceTemplateDetails({...capability, uriTemplate: (capability as any).uriTemplate} as ResourceTemplate);
      default:
        return null;
    }
  };

  return (
    <Modal 
      isOpen={isOpen} 
      onClose={onClose} 
      size="4xl" 
      scrollBehavior="inside"
      classNames={{
        wrapper: "overflow-hidden",
        base: "max-h-[90vh]",
        body: "p-0",
      }}
    >
      <ModalContent>
        <ModalHeader className="flex flex-col gap-1 px-6 pt-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className={`p-2 rounded-lg ${
                type === 'tools' ? 'bg-primary-100' :
                type === 'prompts' ? 'bg-secondary-100' :
                type === 'resources' ? 'bg-success-100' :
                type === 'resourceTemplates' ? 'bg-warning-100' : 'bg-default-100'
              }`}>
                <LocalIcon 
                  icon={getCapabilityIcon(type)} 
                  className={`text-lg ${
                    type === 'tools' ? 'text-primary-600' :
                    type === 'prompts' ? 'text-secondary-600' :
                    type === 'resources' ? 'text-success-600' :
                    type === 'resourceTemplates' ? 'text-warning-600' : 'text-default-600'
                  }`} 
                />
              </div>
              <div>
                <h2 className="text-xl font-semibold">{capability?.name}</h2>
              </div>
            </div>
            <Chip 
              variant="flat" 
              color={getCapabilityColor(type)}
              className="flex-shrink-0"
            >
              {t(`capabilities.${type}`)}
            </Chip>
          </div>
        </ModalHeader>
        
        <Divider />
        
        <ModalBody className="px-6 py-4">
          {renderDetailContent()}
        </ModalBody>
        
        <Divider />
        
        <ModalFooter className="px-6 pb-6">
          <Button variant="flat" onPress={onClose}>
            {t('common.cancel')}
          </Button>
          <Button color="primary" onPress={onClose}>
            {t('common.close')}
          </Button>
        </ModalFooter>
      </ModalContent>
    </Modal>
  );
};

// 获取能力类型图标
const getCapabilityIcon = (type: CapabilityType): string => {
  switch (type) {
    case 'tools':
      return 'lucide:wrench';
    case 'prompts':
      return 'lucide:message-square';
    case 'resources':
      return 'lucide:file';
    case 'resourceTemplates':
      return 'lucide:file-code';
    default:
      return 'lucide:box';
  }
};

// 获取能力类型颜色
const getCapabilityColor = (type: CapabilityType): 'primary' | 'secondary' | 'success' | 'warning' | 'default' => {
  switch (type) {
    case 'tools':
      return 'primary';
    case 'prompts':
      return 'secondary';
    case 'resources':
      return 'success';
    case 'resourceTemplates':
      return 'warning';
    default:
      return 'default';
  }
};

// 搜索结果高亮组件
interface HighlightTextProps {
  text: string;
  searchTerm: string;
  caseSensitive?: boolean;
  className?: string;
}

const HighlightText: React.FC<HighlightTextProps> = ({
  text,
  searchTerm,
  caseSensitive = false,
  className = ''
}) => {
  if (!searchTerm.trim()) {
    return <span className={className}>{text}</span>;
  }

  const flags = caseSensitive ? 'g' : 'gi';
  const regex = new RegExp(`(${searchTerm.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, flags);
  const parts = text.split(regex);

  return (
    <span className={className}>
      {parts.map((part, index) =>
        regex.test(part) ? (
          <mark key={index} className="bg-yellow-200 text-yellow-900 px-1 rounded">
            {part}
          </mark>
        ) : (
          <span key={index}>{part}</span>
        )
      )}
    </span>
  );
};

interface CapabilitiesViewerProps {
  tenant: string;
  serverName: string;
  className?: string;
}

const CapabilitiesViewer: React.FC<CapabilitiesViewerProps> = ({
  tenant,
  serverName,
  className = ''
}) => {
  const {t} = useTranslation();
  const {isOpen, onOpen, onClose} = useDisclosure();
  const [selectedCapability, setSelectedCapability] = React.useState<CapabilityItem | null>(null);
  const [selectedCapabilityType, setSelectedCapabilityType] = React.useState<CapabilityType>('tools');

  // 组件状态
  const [state, setState] = React.useState<CapabilitiesState>({
    loading: true,
    error: null,
    data: null,
    filteredData: null,
    searchTerm: '',
    selectedType: 'all'
  });

  // 高级搜索状态
  const [advancedSearch, setAdvancedSearch] = React.useState({
    enabled: false,
    paramCountFilter: 'all' as 'all' | 'none' | 'few' | 'many',
    mimeTypeFilter: '',
    serverNameFilter: '',
    tenantFilter: '',
    searchInDescription: true,
    caseSensitive: false
  });

  
  // 参数展开状态管理
  const [expandedParams, setExpandedParams] = React.useState<Set<string>>(new Set());

  // 获取能力数据
  const fetchCapabilities = React.useCallback(async () => {
    try {
      setState(prev => ({...prev, loading: true, error: null}));
      const data = await getMCPServerCapabilities(tenant, serverName);
      
      setState(prev => ({
        ...prev,
        loading: false,
        data,
        filteredData: data
      }));
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : t('errors.unknown');
      setState(prev => ({
        ...prev,
        loading: false,
        error: errorMessage
      }));
      toast.error(t('errors.fetch_mcp_capabilities'));
    }
  }, [tenant, serverName, t]);

  // 初始加载
  React.useEffect(() => {
    fetchCapabilities();
  }, [fetchCapabilities]);

  // 筛选数据
  const filterCapabilities = React.useCallback((
    data: MCPCapabilities,
    searchTerm: string,
    selectedType: CapabilityType | 'all',
    advancedFilters: typeof advancedSearch
  ): MCPCapabilities => {
    const filtered: MCPCapabilities = {};

    const matchesSearch = (item: {name: string, description?: string}) => {
      const searchIn = advancedFilters.searchInDescription ? 
        `${item.name} ${item.description || ''}` : item.name;
      
      const searchText = advancedFilters.caseSensitive ? searchIn : searchIn.toLowerCase();
      const searchPattern = advancedFilters.caseSensitive ? searchTerm : searchTerm.toLowerCase();
      
      return searchText.includes(searchPattern);
    };

    const filterArray = <T extends {name: string, description?: string}>(
      items: T[] | undefined,
      type: CapabilityType
    ): T[] => {
      if (!items) return [];
      if (selectedType !== 'all' && selectedType !== type) return [];
      
      return items.filter(item => {
        // 基本文本搜索
        if (searchTerm && !matchesSearch(item)) return false;
        
        // 高级筛选只在启用时应用
        if (!advancedFilters.enabled) return true;
        
        
        // 参数数量筛选
        if (advancedFilters.paramCountFilter !== 'all') {
          let paramCount = 0;
          if (type === 'tools') {
            const tool = item as any;
            paramCount = tool.inputSchema?.properties ? Object.keys(tool.inputSchema.properties).length : 0;
          } else if (type === 'prompts') {
            const prompt = item as any;
            paramCount = prompt.arguments?.length || 0;
          }
          
          const matchesParamFilter = 
            (advancedFilters.paramCountFilter === 'none' && paramCount === 0) ||
            (advancedFilters.paramCountFilter === 'few' && paramCount > 0 && paramCount <= 3) ||
            (advancedFilters.paramCountFilter === 'many' && paramCount > 3);
          
          if (!matchesParamFilter) return false;
        }
        
        // MIME类型筛选（仅适用于资源）
        if ((type === 'resources' || type === 'resourceTemplates') && advancedFilters.mimeTypeFilter) {
          const mimeType = (item as any).mimeType || '';
          if (!mimeType.toLowerCase().includes(advancedFilters.mimeTypeFilter.toLowerCase())) {
            return false;
          }
        }
        
        // 服务名称筛选
        if (advancedFilters.serverNameFilter) {
          if (!serverName.toLowerCase().includes(advancedFilters.serverNameFilter.toLowerCase())) {
            return false;
          }
        }
        
        // 租户筛选
        if (advancedFilters.tenantFilter) {
          if (!tenant.toLowerCase().includes(advancedFilters.tenantFilter.toLowerCase())) {
            return false;
          }
        }
        
        return true;
      });
    };

    filtered.tools = filterArray(data.tools, 'tools') as Tool[];
    filtered.prompts = filterArray(data.prompts, 'prompts') as Prompt[];
    filtered.resources = filterArray(data.resources, 'resources') as Resource[];
    filtered.resourceTemplates = filterArray(data.resourceTemplates, 'resourceTemplates') as ResourceTemplate[];

    return filtered;
  }, []);

  // 搜索和类型筛选
  React.useEffect(() => {
    if (!state.data) return;
    
    const filtered = filterCapabilities(state.data, state.searchTerm, state.selectedType, advancedSearch);
    setState(prev => ({...prev, filteredData: filtered}));
  }, [state.data, state.searchTerm, state.selectedType, advancedSearch, filterCapabilities]);

  // 处理搜索
  const handleSearch = (value: string) => {
    setState(prev => ({...prev, searchTerm: value}));
  };

  // 处理类型选择
  const handleTypeSelection = (type: React.Key) => {
    setState(prev => ({...prev, selectedType: String(type) as CapabilityType | 'all'}));
  };

  // 打开详情模态框
  const handleOpenDetail = (capability: CapabilityItem, type: CapabilityType) => {
    setSelectedCapability(capability);
    setSelectedCapabilityType(type);
    onOpen();
  };



  // 切换参数展开状态
  const toggleParamExpansion = (itemName: string) => {
    setExpandedParams(prev => {
      const newSet = new Set(prev);
      if (newSet.has(itemName)) {
        newSet.delete(itemName);
      } else {
        newSet.add(itemName);
      }
      return newSet;
    });
  };


  // 渲染能力卡片
  const renderCapabilityCard = (item: CapabilityItem, type: CapabilityType) => {
    const color = getCapabilityColor(type);
    const iconBgClass = color === 'primary' ? 'bg-primary-100' :
                       color === 'secondary' ? 'bg-secondary-100' :
                       color === 'success' ? 'bg-success-100' :
                       color === 'warning' ? 'bg-warning-100' : 'bg-default-100';
    
    const iconColorClass = color === 'primary' ? 'text-primary-600' :
                          color === 'secondary' ? 'text-secondary-600' :
                          color === 'success' ? 'text-success-600' :
                          color === 'warning' ? 'text-warning-600' : 'text-default-600';


    return (
      <Card 
        key={`${type}-${item.name}`}
        className={`w-full hover:shadow-md transition-shadow`}
      >
        <CardBody className="flex flex-row items-center gap-3 p-4">
          
          <div className="flex-shrink-0">
            <div className={`p-2 rounded-lg ${iconBgClass}`}>
              <LocalIcon 
                icon={getCapabilityIcon(type)} 
                className={`text-lg ${iconColorClass}`}
              />
            </div>
          </div>
          <div className="flex-grow min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <h3 className="font-semibold text-sm break-words flex-shrink-0">
                <HighlightText
                  text={item.name}
                  searchTerm={state.searchTerm}
                  caseSensitive={advancedSearch.caseSensitive}
                />
              </h3>
              <Button
                size="sm"
                variant="flat"
                color="primary"
                onPress={() => handleOpenDetail(item, type)}
                className="h-6 px-2 text-xs"
              >
                {t('capabilities.view_details')}
              </Button>
              <div className="flex items-center gap-1 flex-shrink-0 ml-auto">
                <Chip 
                  size="sm" 
                  variant="flat" 
                  color={color}
                  className="flex-shrink-0"
                >
                  {t(`capabilities.${type}`)}
                </Chip>
              </div>
            </div>
            {/* MCP 服务信息 */}
            <div className="flex items-center gap-2 mb-1 text-xs text-default-500">
              <LocalIcon icon="lucide:server" className="text-xs" />
              <span>{t('capabilities.service_name')}:</span>
              <code className="px-1.5 py-0.5 bg-default-100 rounded text-xs font-mono">{serverName}</code>
              <span className="text-default-400">•</span>
              <span>{t('capabilities.tenant')}:</span>
              <code className="px-1.5 py-0.5 bg-default-100 rounded text-xs font-mono">{tenant}</code>
            </div>
            
            {item.description && (
              <p className="text-xs text-default-500 line-clamp-4 mb-2">
                {advancedSearch.searchInDescription ? (
                  <HighlightText
                    text={item.description}
                    searchTerm={state.searchTerm}
                    caseSensitive={advancedSearch.caseSensitive}
                  />
                ) : (
                  item.description
                )}
              </p>
            )}
            
            {/* 工具入参信息 */}
            {type === 'tools' && (() => {
              const tool = item as any;
              const properties = tool.inputSchema?.properties || {};
              const required = tool.inputSchema?.required || [];
              const paramCount = Object.keys(properties).length;
              const isExpanded = expandedParams.has(item.name);
              
              if (paramCount > 0) {
                return (
                  <div className="border-t border-default-200 pt-3 mt-2">
                    <div className="flex items-center gap-3 mb-2">
                      <div className="flex items-center gap-2">
                        <LocalIcon icon="lucide:wrench" className="text-sm text-default-400" />
                        <span className="text-sm font-medium text-default-700">
                          {t('capabilities.parameters')} ({paramCount})
                        </span>
                      </div>
                      <div onClick={(e) => e.stopPropagation()}>
                        <Button
                          size="sm"
                          variant="light"
                          className="h-auto min-w-0 p-1"
                          onPress={() => toggleParamExpansion(item.name)}
                        >
                        <div className="flex items-center gap-1">
                          <LocalIcon 
                            icon={isExpanded ? "lucide:chevron-left" : "lucide:chevron-right"} 
                            className="text-sm text-default-400" 
                          />
                          <span className="text-sm text-default-500">
                            {isExpanded ? t('capabilities.collapse') : t('capabilities.expand')}
                          </span>
                        </div>
                        </Button>
                      </div>
                    </div>
                    {isExpanded && (
                      <div className="space-y-2">
                        {Object.entries(properties)
                          .sort(([a], [b]) => {
                            // 先显示必需参数，再显示可选参数
                            const aRequired = required.includes(a);
                            const bRequired = required.includes(b);
                            if (aRequired && !bRequired) return -1;
                            if (!aRequired && bRequired) return 1;
                            // 相同类型按字母顺序排序
                            return a.localeCompare(b);
                          })
                          .map(([paramName, paramSchema]: [string, any]) => (
                          <div key={paramName} className="flex items-start justify-between py-2 px-3 bg-default-50 rounded-lg">
                            <div className="flex-grow min-w-0">
                              <div className="flex items-center gap-2 mb-1">
                                <span className="font-medium text-sm text-default-800">{paramName}</span>
                                {required.includes(paramName) && (
                                  <Chip size="sm" color="warning" variant="flat" className="text-xs">
                                    {t('capabilities.required')}
                                  </Chip>
                                )}
                              </div>
                              <div className="space-y-2">
                                <div className="flex items-center gap-3 text-xs text-default-600">
                                  {paramSchema.type && (
                                    <div className="flex items-center gap-1">
                                      <LocalIcon icon="lucide:tag" className="text-xs" />
                                      <span className="font-mono">{paramSchema.type}</span>
                                    </div>
                                  )}
                                  {paramSchema.description && (
                                    <div className="flex items-center gap-1">
                                      <LocalIcon icon="lucide:file-text" className="text-xs" />
                                      <span className="line-clamp-2">{paramSchema.description}</span>
                                    </div>
                                  )}
                                </div>
                                {paramSchema.enum && (
                                  <div className="flex items-start gap-1">
                                    <LocalIcon icon="lucide:file-text" className="text-xs text-default-500 mt-0.5" />
                                    <div>
                                      <span className="text-xs text-default-500">可选值: </span>
                                      <div className="flex gap-1 flex-wrap mt-1">
                                        {paramSchema.enum.map((value: any, index: number) => (
                                          <Code key={index} size="sm" color="default" className="text-xs">{String(value)}</Code>
                                        ))}
                                      </div>
                                    </div>
                                  </div>
                                )}
                                {paramSchema.default !== undefined && (
                                  <div className="flex items-start gap-1">
                                    <LocalIcon icon="lucide:star" className="text-xs text-default-500 mt-0.5" />
                                    <div>
                                      <span className="text-xs text-default-500">默认值: </span>
                                      <Code size="sm" color="success" className="text-xs">{String(paramSchema.default)}</Code>
                                    </div>
                                  </div>
                                )}
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                );
              }
              return null;
            })()}
          </div>
          
        </CardBody>
      </Card>
    );
  };

  // 渲染能力列表
  const renderCapabilitiesList = (capabilities: MCPCapabilities) => {
    const allItems: Array<{item: CapabilityItem; type: CapabilityType}> = [];

    if (capabilities.tools) {
      capabilities.tools.forEach(tool => 
        allItems.push({item: {...tool, type: 'tools'}, type: 'tools'})
      );
    }
    if (capabilities.prompts) {
      capabilities.prompts.forEach(prompt => 
        allItems.push({item: {...prompt, type: 'prompts'}, type: 'prompts'})
      );
    }
    if (capabilities.resources) {
      capabilities.resources.forEach(resource => 
        allItems.push({item: {...resource, type: 'resources'}, type: 'resources'})
      );
    }
    if (capabilities.resourceTemplates) {
      capabilities.resourceTemplates.forEach(template => 
        allItems.push({item: {...template, type: 'resourceTemplates'}, type: 'resourceTemplates'})
      );
    }

    if (allItems.length === 0) {
      return (
        <div className="text-center py-8">
          <LocalIcon icon="lucide:folder-open" className="text-4xl text-default-300 mb-2" />
          <p className="text-default-500">{t('capabilities.no_capabilities')}</p>
        </div>
      );
    }

    return (
      <div className="flex flex-col gap-3">
        {allItems.map(({item, type}) => renderCapabilityCard(item, type))}
      </div>
    );
  };

  // 渲染标签页内容
  const renderTabContent = (type: CapabilityType) => {
    if (!state.filteredData) return null;

    const items = state.filteredData[type] || [];
    
    if (items.length === 0) {
      return (
        <div className="text-center py-8">
          <LocalIcon icon={getCapabilityIcon(type)} className="text-4xl text-default-300 mb-2" />
          <p className="text-default-500">
            {t('capabilities.no_type_capabilities', {type: t(`capabilities.${type}`)})}
          </p>
        </div>
      );
    }

    return (
      <div className="space-y-4">
        
        {/* 工具列表 */}
        <div className="flex flex-col gap-3">
          {items.map(item => renderCapabilityCard({...item, type}, type))}
        </div>
      </div>
    );
  };

  if (state.loading) {
    return (
      <div className={`flex justify-center items-center py-8 ${className}`}>
        <Spinner size="lg" />
      </div>
    );
  }

  if (state.error) {
    return (
      <div className={`text-center py-8 ${className}`}>
        <LocalIcon icon="lucide:alert-circle" className="text-4xl text-danger-400 mb-2" />
        <p className="text-danger-600 mb-4">{state.error}</p>
        <Button color="primary" variant="flat" onPress={fetchCapabilities}>
          {t('common.retry')}
        </Button>
      </div>
    );
  }

  return (
    <div className={`space-y-4 ${className}`}>
      {/* 搜索和筛选栏 */}
      <div className="flex flex-col gap-4">
        <div className="flex flex-col sm:flex-row gap-4">
          <Input
            placeholder={t('capabilities.search_placeholder')}
            startContent={<LocalIcon icon="lucide:search" className="text-default-400" />}
            value={state.searchTerm}
            onValueChange={handleSearch}
            className="flex-grow"
            isClearable
          />
          <div className="flex gap-2">
            <Button
              variant="flat"
              startContent={<LocalIcon icon="lucide:search" />}
              onPress={() => setAdvancedSearch(prev => ({...prev, enabled: !prev.enabled}))}
              color={advancedSearch.enabled ? "primary" : "default"}
            >
              {t('capabilities.advanced_search')}
            </Button>
          </div>
        </div>
        
        {/* 高级搜索面板 */}
        {advancedSearch.enabled && (
          <Card className="p-4">
            <div className="space-y-4">
              <h4 className="text-sm font-semibold flex items-center gap-2">
                <LocalIcon icon="lucide:search" className="text-sm" />
                {t('capabilities.advanced_filters')}
              </h4>
              
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
                
                {/* 参数数量筛选 */}
                <div>
                  <label className="text-xs text-default-600 mb-1 block">
                    {t('capabilities.param_count_filter')}
                  </label>
                  <select
                    value={advancedSearch.paramCountFilter}
                    onChange={(e) => setAdvancedSearch(prev => ({
                      ...prev,
                      paramCountFilter: e.target.value as 'all' | 'none' | 'few' | 'many'
                    }))}
                    className="w-full px-3 py-2 text-sm border rounded-lg bg-default-50"
                  >
                    <option value="all">{t('common.all')}</option>
                    <option value="none">{t('capabilities.no_params')}</option>
                    <option value="few">{t('capabilities.few_params')}</option>
                    <option value="many">{t('capabilities.many_params')}</option>
                  </select>
                </div>
                
                {/* 服务名称筛选 */}
                <div>
                  <label className="text-xs text-default-600 mb-1 block">
                    {t('capabilities.service_name')}
                  </label>
                  <Input
                    size="sm"
                    placeholder={serverName}
                    value={advancedSearch.serverNameFilter}
                    onValueChange={(value) => setAdvancedSearch(prev => ({
                      ...prev,
                      serverNameFilter: value
                    }))}
                    className="w-full"
                    startContent={<LocalIcon icon="lucide:server" className="text-default-400 text-xs" />}
                  />
                </div>
                
                {/* 租户筛选 */}
                <div>
                  <label className="text-xs text-default-600 mb-1 block">
                    {t('capabilities.tenant')}
                  </label>
                  <Input
                    size="sm"
                    placeholder={tenant}
                    value={advancedSearch.tenantFilter}
                    onValueChange={(value) => setAdvancedSearch(prev => ({
                      ...prev,
                      tenantFilter: value
                    }))}
                    className="w-full"
                    startContent={<LocalIcon icon="lucide:users" className="text-default-400 text-xs" />}
                  />
                </div>
                
                {/* MIME类型筛选 */}
                <div>
                  <label className="text-xs text-default-600 mb-1 block">
                    MIME {t('common.type')}
                  </label>
                  <Input
                    size="sm"
                    placeholder="text/plain, application/json"
                    value={advancedSearch.mimeTypeFilter}
                    onValueChange={(value) => setAdvancedSearch(prev => ({
                      ...prev,
                      mimeTypeFilter: value
                    }))}
                    className="w-full"
                  />
                </div>
                
                {/* 搜索选项 */}
                <div className="space-y-2">
                  <label className="text-xs text-default-600 block">
                    {t('capabilities.search_options')}
                  </label>
                  <div className="space-y-1">
                    <label className="flex items-center gap-2 text-xs">
                      <input
                        type="checkbox"
                        checked={advancedSearch.searchInDescription}
                        onChange={(e) => setAdvancedSearch(prev => ({
                          ...prev,
                          searchInDescription: e.target.checked
                        }))}
                        className="w-3 h-3"
                      />
                      {t('capabilities.search_in_description')}
                    </label>
                    <label className="flex items-center gap-2 text-xs">
                      <input
                        type="checkbox"
                        checked={advancedSearch.caseSensitive}
                        onChange={(e) => setAdvancedSearch(prev => ({
                          ...prev,
                          caseSensitive: e.target.checked
                        }))}
                        className="w-3 h-3"
                      />
                      {t('capabilities.case_sensitive')}
                    </label>
                  </div>
                </div>
              </div>
              
              {/* 重置按钮 */}
              <div className="flex justify-end">
                <Button
                  variant="flat"
                  size="sm"
                  startContent={<LocalIcon icon="lucide:rotate-ccw" />}
                  onPress={() => setAdvancedSearch({
                    enabled: true,
                    paramCountFilter: 'all',
                    mimeTypeFilter: '',
                    serverNameFilter: '',
                    tenantFilter: '',
                    searchInDescription: true,
                    caseSensitive: false
                  })}
                >
                  {t('common.reset')}
                </Button>
              </div>
            </div>
          </Card>
        )}
        
        <Tabs
          selectedKey={state.selectedType}
          onSelectionChange={(key) => handleTypeSelection(key as React.Key)}
          size="sm"
          classNames={{
            tabList: "bg-default-100 p-1 rounded-lg"
          }}
        >
          <Tab
            key="all"
            title={
              <div className="flex items-center gap-1">
                <LocalIcon icon="lucide:folder-open" className="text-sm" />
                <span>{t('common.all')}</span>
              </div>
            }
          />
          <Tab
            key="tools"
            title={
              <div className="flex items-center gap-1">
                <LocalIcon icon="lucide:wrench" className="text-sm" />
                <span>{t('capabilities.tools')}</span>
              </div>
            }
          />
          <Tab
            key="prompts"
            title={
              <div className="flex items-center gap-1">
                <LocalIcon icon="lucide:message-square" className="text-sm" />
                <span>{t('capabilities.prompts')}</span>
              </div>
            }
          />
          <Tab
            key="resources"
            title={
              <div className="flex items-center gap-1">
                <LocalIcon icon="lucide:file-text" className="text-sm" />
                <span>{t('capabilities.resources')}</span>
              </div>
            }
          />
          <Tab
            key="resourceTemplates"
            title={
              <div className="flex items-center gap-1">
                <LocalIcon icon="lucide:file-code" className="text-sm" />
                <span>{t('capabilities.resource_templates')}</span>
              </div>
            }
          />
        </Tabs>
      </div>

      {/* 内容区域 */}
      <div className="min-h-[400px]">
        {state.selectedType === 'all' ? (
          renderCapabilitiesList(state.filteredData || {})
        ) : (
          renderTabContent(state.selectedType)
        )}
      </div>

      {/* 详情模态框 */}
      <CapabilityDetailModal
        isOpen={isOpen}
        onClose={onClose}
        capability={selectedCapability}
        type={selectedCapabilityType}
      />
    </div>
  );
};

export default CapabilitiesViewer;