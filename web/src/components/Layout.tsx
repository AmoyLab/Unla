import {
  Avatar,
  Button,
  Dropdown,
  DropdownItem,
  DropdownMenu,
  DropdownTrigger,
  Link as HeroLink,
  Navbar,
  NavbarContent,
  NavbarItem,
  Tooltip
} from "@heroui/react";
import React, {useEffect, useState} from 'react';
import {useTranslation} from 'react-i18next';
import {Link, useLocation, useNavigate} from 'react-router-dom';

import {ChangePasswordDialog} from '@/components/ChangePasswordDialog';
import {LanguageSwitcher} from '@/components/LanguageSwitcher';
import LocalIcon from '@/components/LocalIcon';
import {WechatQRCode} from '@/components/WechatQRCode';
import {getCurrentUser} from '@/services/api';
import {toast} from '@/utils/toast';

import logoImg from '/logo.png';

interface LayoutProps {
  children: React.ReactNode;
}

export function Layout({ children }: LayoutProps) {
  const location = useLocation();
  const navigate = useNavigate();
  const { t } = useTranslation();
  const [isCollapsed, setIsCollapsed] = React.useState(false);
  const [isDark, setIsDark] = React.useState(() => {
    const savedTheme = window.localStorage.getItem('theme');
    return savedTheme === 'dark';
  });
  const [isChangePasswordOpen, setIsChangePasswordOpen] = React.useState(false);
  const [isWechatQRCodeOpen, setIsWechatQRCodeOpen] = React.useState(false);
  const [userInfo, setUserInfo] = useState<{ username: string; role: string } | null>(null);

  // Initialize theme on mount
  React.useEffect(() => {
    if (isDark) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }, [isDark]);

  useEffect(() => {
    const fetchUserInfo = async () => {
      try {
        const response = await getCurrentUser();
        setUserInfo(response.data);
      } catch (error) {
        toast.error(t('errors.fetch_user', { error: (error as Error).message }), {
          duration: 3000,
        });
      }
    };

    fetchUserInfo();
  }, [t]);

  const llmConfigAdminOnly = window.RUNTIME_CONFIG?.LLM_CONFIG_ADMIN_ONLY;
  const canShowLLM =
    llmConfigAdminOnly === false ||
    (llmConfigAdminOnly === true && userInfo?.role === 'admin');

  const menuGroups = [
    {
      key: 'chat-ai',
      label: t('nav.groups.chat_ai', 'Chat & AI'),
      items: [
        {
          key: 'chat',
          label: t('nav.chat'),
          icon: 'lucide:message-square',
          path: '/chat',
        },
        ...(canShowLLM ? [{
          key: 'llm',
          label: t('nav.llm'),
          icon: 'lucide:brain',
          path: '/llm',
        }] : []),
      ]
    },
    {
      key: 'gateway-config',
      label: t('nav.groups.gateway_config', 'Gateway & Config'),
      items: [
        {
          key: 'gateway',
          label: t('nav.gateway'),
          icon: 'lucide:server',
          path: '/gateway',
        },
        {
          key: 'config-versions',
          label: t('nav.config_versions'),
          icon: 'lucide:history',
          path: '/config-versions',
        },
      ]
    },
    ...(userInfo?.role === 'admin' ? [{
      key: 'management',
      label: t('nav.groups.management', 'Management'),
      items: [
        {
          key: 'users',
          label: t('nav.users'),
          icon: 'lucide:users',
          path: '/users',
        },
        {
          key: 'tenants',
          label: t('nav.tenants'),
          icon: 'lucide:building',
          path: '/tenants',
        }
      ]
    }] : []),
  ];

  const handleLogout = () => {
    window.localStorage.removeItem('token');
    navigate('/login');
  };

  const toggleTheme = () => {
    setIsDark(!isDark);
    document.documentElement.classList.toggle('dark');
    window.localStorage.setItem('theme', !isDark ? 'dark' : 'light');
  };

  return (
    <div className="min-h-screen bg-background text-foreground">
      {/* Top Navigation Bar */}
      <Navbar
        className="bg-card border-b border-border shadow-sm"
        maxWidth="full"
        height="4rem"
      >
        <NavbarContent className={`transition-all duration-300 ${isCollapsed ? 'ml-20' : 'ml-56'}`}>
          <NavbarItem>
            <Button
              isIconOnly
              variant="light"
              onPress={() => setIsCollapsed(!isCollapsed)}
              aria-label={t('common.toggle_sidebar')}
            >
              <LocalIcon icon={isCollapsed ? "lucide:chevron-right" : "lucide:chevron-left"} />
            </Button>
          </NavbarItem>
        </NavbarContent>
        <NavbarContent justify="end" className="gap-4">
          <NavbarItem>
            <LanguageSwitcher />
          </NavbarItem>
          <NavbarItem>
            <Tooltip content={t('common.join_wechat')}>
              <Button
                variant="light"
                isIconOnly
                onPress={() => setIsWechatQRCodeOpen(true)}
              >
                <LocalIcon icon="mdi:wechat" className="text-2xl" />
              </Button>
            </Tooltip>
          </NavbarItem>
          <NavbarItem>
            <Tooltip content={t('common.join_discord')}>
              <Button
                as={HeroLink}
                href="https://discord.gg/udf69cT9TY"
                target="_blank"
                variant="light"
                isIconOnly
              >
                <LocalIcon icon="ic:baseline-discord" className="text-2xl" />
              </Button>
            </Tooltip>
          </NavbarItem>
          <NavbarItem>
            <Tooltip content={t('common.view_github')}>
              <Button
                as={HeroLink}
                href="https://github.com/amoylab/unla"
                target="_blank"
                variant="light"
                isIconOnly
              >
                <LocalIcon icon="mdi:github" className="text-2xl" />
              </Button>
            </Tooltip>
          </NavbarItem>
          <NavbarItem>
            <Tooltip content={t('common.view_docs')}>
              <Button
                as={HeroLink}
                href="https://docs.unla.amoylab.com/"
                target="_blank"
                variant="light"
                isIconOnly
              >
                <LocalIcon icon="mdi:book-open-page-variant" className="text-2xl" />
              </Button>
            </Tooltip>
          </NavbarItem>
          <NavbarItem>
            <Tooltip content={t('common.switch_theme', { theme: isDark ? t('common.light') : t('common.dark') })}>
              <Button
                variant="light"
                isIconOnly
                onPress={toggleTheme}
              >
                <LocalIcon icon={isDark ? "lucide:sun" : "lucide:moon"}
                  className="text-2xl"
                />
              </Button>
            </Tooltip>
          </NavbarItem>
        </NavbarContent>
      </Navbar>

      <div className="flex h-[calc(100vh-4rem)]">
        {/* Sidebar */}
        <div
          className={`h-screen bg-card text-foreground flex flex-col fixed left-0 top-0 z-40 transition-all duration-300 border-r border-border shadow-lg ${
            isCollapsed ? "w-20" : "w-56"
          }`}
        >
          <div className="flex items-center justify-center p-4 border-b border-border h-16">
            {isCollapsed ? (
              <img src={logoImg} alt="MCP Logo" className="w-8 h-8" />
            ) : (
              <div className="flex items-center gap-2">
                <img src={logoImg} alt="MCP Logo" className="w-6 h-6" />
                <span className="text-xl font-bold">Unla</span>
                <span className="text-xs text-muted-foreground ml-1">
                  {window.RUNTIME_CONFIG?.version || 'dev'}
                </span>
              </div>
            )}
          </div>

          <nav className="flex-1 overflow-y-auto p-2">
            {menuGroups.map((group, groupIndex) => (
              <div key={group.key} className={groupIndex > 0 ? "mt-6" : ""}>
                {!isCollapsed && (
                  <div className="px-4 py-2 mb-2">
                    <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                      {group.label}
                    </span>
                  </div>
                )}
                {isCollapsed && groupIndex > 0 && (
                  <div className="mx-2 mb-2 border-t border-border"></div>
                )}
                {group.items.map((item) => (
                  isCollapsed ? (
                    <Tooltip
                      key={item.path}
                      content={item.label}
                      placement="right"
                    >
                      <Link
                        to={item.path}
                        className={`flex items-center w-full px-4 py-2 rounded-lg mb-1 ${
                          (item.path === "/"
                            ? location.pathname === "/"
                            : location.pathname.startsWith(item.path))
                            ? 'bg-primary/10 text-primary'
                            : 'hover:bg-accent text-foreground'
                        }`}
                      >
                        <LocalIcon icon={item.icon} width={24} height={24} />
                      </Link>
                    </Tooltip>
                  ) : (
                    <Link
                      key={item.path}
                      to={item.path}
                      className={`flex items-center w-full px-4 py-2 rounded-lg mb-1 ${
                        (item.path === "/"
                          ? location.pathname === "/"
                          : location.pathname.startsWith(item.path))
                          ? 'bg-primary/10 text-primary'
                          : 'hover:bg-accent text-foreground'
                      }`}
                    >
                      <LocalIcon icon={item.icon} width={20} height={20} className="mr-3" />
                      <span>{item.label}</span>
                    </Link>
                  )
                ))}
              </div>
            ))}
          </nav>

          {/* User Profile Section */}
          <div className="p-4 border-t border-border">
            <Dropdown placement="top-end">
              <DropdownTrigger>
                {isCollapsed ? (
                  <Button
                    isIconOnly
                    variant="light"
                    className="w-full"
                  >
                    <Avatar
                      size="sm"
                      name={userInfo?.username || 'User'}
                      className="bg-primary/10"
                    />
                  </Button>
                ) : (
                  <Button
                    variant="light"
                    className="w-full flex items-center justify-start gap-2"
                  >
                    <Avatar
                      size="sm"
                      name={userInfo?.username || 'User'}
                      className="bg-primary/10"
                    />
                    <div className="flex flex-col items-start">
                      <span className="text-sm font-medium">{userInfo?.username || 'User'}</span>
                      <span className="text-xs text-muted-foreground">{userInfo?.role || 'User'}</span>
                    </div>
                  </Button>
                )}
              </DropdownTrigger>
              <DropdownMenu aria-label="User menu">
                <DropdownItem
                  key="change-password"
                  startContent={<LocalIcon icon="lucide:key" />}
                  onPress={() => setIsChangePasswordOpen(true)}
                >
                  {t('auth.change_password')}
                </DropdownItem>
                <DropdownItem
                  key="logout"
                  startContent={<LocalIcon icon="lucide:log-out" />}
                  onPress={handleLogout}
                  className="text-danger"
                >
                  {t('auth.logout')}
                </DropdownItem>
              </DropdownMenu>
            </Dropdown>
          </div>
        </div>

        {/* Main Content */}
        <div className={`flex-1 transition-all duration-300 ${isCollapsed ? 'ml-20' : 'ml-56'} h-full overflow-hidden`}>
          <div className="p-6 h-full overflow-y-auto">
            {children}
          </div>
        </div>
      </div>

      <ChangePasswordDialog
        isOpen={isChangePasswordOpen}
        onOpenChange={() => setIsChangePasswordOpen(false)}
      />

      <WechatQRCode
        isOpen={isWechatQRCodeOpen}
        onOpenChange={() => setIsWechatQRCodeOpen(false)}
      />
    </div>
  );
}
