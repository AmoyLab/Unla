import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, useLocation } from 'react-router-dom';

import { Layout } from './components/Layout';
import { LoginPage } from './pages/auth/login';
import { LLMChatInterface } from './pages/chat/llm-chat-interface';
import { ConfigVersionsPage } from './pages/gateway/config-versions';
import { GatewayManager } from './pages/gateway/gateway-manager';
import CapabilitiesPage from './pages/gateway/capabilities';
import LLMSettings from './pages/llm/llm-settings';
import { TenantManagement } from './pages/users/tenant-management';
import { UserManagement } from './pages/users/user-management';

// Initialize theme on app startup
function ThemeInitializer() {
  React.useEffect(() => {
    const savedTheme = window.localStorage.getItem('theme');
    if (savedTheme === 'dark') {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }, []);

  return null;
}

// Route guard component
function PrivateRoute({ children }: { children: React.ReactNode }) {
  const location = useLocation();
  const token = window.localStorage.getItem('token');

  if (!token) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return <>{children}</>;
}

// Main layout component
function MainLayout() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<GatewayManager />} />
        <Route path="/chat" element={<LLMChatInterface />} />
        <Route path="/chat/:sessionId" element={<LLMChatInterface />} />
        <Route path="/gateway/capabilities/:tenant/:serverName" element={<PrivateRoute><CapabilitiesPage /></PrivateRoute>} />
        <Route path="/gateway/*" element={<GatewayManager />} />
        <Route path="/gateway" element={<PrivateRoute><GatewayManager /></PrivateRoute>} />
        <Route path="/gateway/configs/:name/versions" element={<PrivateRoute><ConfigVersionsPage /></PrivateRoute>} />
        <Route path="/config-versions" element={<PrivateRoute><ConfigVersionsPage /></PrivateRoute>} />
        <Route path="/llm" element={<PrivateRoute><LLMSettings /></PrivateRoute>} />
        <Route path="/users" element={<PrivateRoute><UserManagement /></PrivateRoute>} />
        <Route path="/tenants" element={<TenantManagement />} />
      </Routes>
    </Layout>
  );
}

export default function App() {
  return (
    <Router
      basename={(window.RUNTIME_CONFIG?.VITE_BASE_URL as string) || '/'}
      future={{ v7_relativeSplatPath: true, v7_startTransition: true }}
    >
      <ThemeInitializer />
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route
          path="/*"
          element={
            <PrivateRoute>
              <MainLayout />
            </PrivateRoute>
          }
        />
      </Routes>
    </Router>
  );
}
