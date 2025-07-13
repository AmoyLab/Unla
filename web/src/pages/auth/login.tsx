import { Button, Input, Card, CardBody, CardHeader } from "@heroui/react";
import axios from 'axios';
import React, { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';

import LocalIcon from '@/components/LocalIcon';
import api from '@/services/api';
import { toast } from '@/utils/toast';

export function LoginPage() {
  const { t } = useTranslation();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    // Initialize theme on login page
    const savedTheme = window.localStorage.getItem('theme');
    if (savedTheme === 'dark') {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }

    // Check if already logged in
    const token = window.localStorage.getItem('token');
    if (token) {
      navigate('/');
    }
  }, [navigate]);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);

    try {
      const response = await api.post('/auth/login', { username, password });
      window.localStorage.setItem('token', response.data.token);
      toast.success(t('auth.login_success'));
      navigate('/');
    } catch (error) {
      if (axios.isAxiosError(error) && error.response?.data?.error) {
        toast.error(error.response.data.error);
      } else {
        toast.error(t('auth.login_failed'));
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-background">
      <Card className="w-full max-w-md">
        <CardHeader className="flex flex-col gap-1.5 p-6">
          <div className="flex items-center gap-2">
            <LocalIcon icon="lucide:server" className="text-primary text-2xl" />
            <h1 className="text-2xl font-bold">Unla - MCP Gateway</h1>
          </div>
          <p className="text-default-500">
            {t('auth.login_to_continue')}
          </p>
        </CardHeader>
        <CardBody className="p-6">
          <form onSubmit={handleLogin} className="flex flex-col gap-4">
            <Input
              label={t('auth.username')}
              placeholder={t('auth.username_placeholder')}
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              startContent={<LocalIcon icon="lucide:user" className="text-default-400" />}
              required
            />
            <Input
              label={t('auth.password')}
              type="password"
              placeholder={t('auth.password_placeholder')}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              startContent={<LocalIcon icon="lucide:lock" className="text-default-400" />}
              required
            />
            <Button
              type="submit"
              color="primary"
              isLoading={loading}
              className="w-full"
            >
              {t('auth.login')}
            </Button>
          </form>
        </CardBody>
      </Card>
    </div>
  );
}