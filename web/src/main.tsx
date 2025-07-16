import { HeroUIProvider, ToastProvider } from "@heroui/react";
import { loader } from '@monaco-editor/react';
import axios from "axios";
import React from "react";
import ReactDOM from "react-dom/client";

import App from "./App.tsx";
import { LoadingScreen } from "./components/LoadingScreen";
import './i18n';

import "./index.css";

// Configure Monaco Editor to use local files
interface MonacoGlobal {
  MonacoEnvironment: {
    getWorkerUrl: (moduleId: string, label: string) => string;
  };
}

(globalThis as unknown as MonacoGlobal).MonacoEnvironment = {
  getWorkerUrl: function (_moduleId: string, _label: string) {
    // Use base worker for all cases since project only uses YAML
    return '/monaco-editor/vs/base/worker/workerMain.js';
  }
};

// Configure @monaco-editor/react to use local monaco-editor
loader.config({
  paths: {
    vs: '/monaco-editor/vs'
  }
});

// Initialize monaco
loader.init().then(() => {
  // Monaco is now loaded and available
  console.log('Monaco Editor loaded from local files');
}).catch((error) => {
  console.error('Failed to load Monaco Editor:', error);
});

// Initialize theme immediately before React renders
const savedTheme = window.localStorage.getItem('theme');
if (savedTheme === 'dark') {
  document.documentElement.classList.add('dark');
} else if (savedTheme === 'light') {
  document.documentElement.classList.remove('dark');
}

// Define proper types for RUNTIME_CONFIG
export interface RuntimeConfig {
  apiBaseUrl: string;
  debugMode: boolean;
  version: string;
  features: {
    enableExperimental: boolean;
    [key: string]: boolean;
  };
  VITE_DIRECT_MCP_GATEWAY_MODIFIER: string;
  LLM_CONFIG_ADMIN_ONLY: boolean;
  [key: string]: unknown; // For any additional properties
}

// Provide defaults for runtime config
const defaultRuntimeConfig: RuntimeConfig = {
  apiBaseUrl: '',
  debugMode: false,
  version: '0.0.0',
  features: {
    enableExperimental: false
  },
  VITE_DIRECT_MCP_GATEWAY_MODIFIER: ':5235',
  LLM_CONFIG_ADMIN_ONLY: false
};

declare global {
  interface Window {
    RUNTIME_CONFIG: RuntimeConfig;
  }
}

// Get root element and create root instance only once
const rootElement = document.getElementById("root");
if (!rootElement) {
  throw new Error("Root element not found");
}

// Create root instance only once
const root = ReactDOM.createRoot(rootElement);

// Show loading screen immediately
root.render(
  <React.StrictMode>
    <HeroUIProvider>
      <LoadingScreen />
    </HeroUIProvider>
  </React.StrictMode>
);

// Fetch runtime config before rendering the app
const fetchRuntimeConfig = async () => {
  // Only log in development mode
  const isDev = import.meta.env.DEV;

  try {
    if (isDev) {
      console.log("[RUNTIME_CONFIG] Fetching /api/runtime-config...");
    }
    const response = await axios.get<RuntimeConfig>("/api/runtime-config");
    if (isDev) {
      console.log("[RUNTIME_CONFIG] Fetched config:", response.data);
    }

    // Merge with defaults to ensure all properties exist
    window.RUNTIME_CONFIG = {
      ...defaultRuntimeConfig,
      ...response.data,
      // Deep merge for nested objects
      features: {
        ...defaultRuntimeConfig.features,
        ...(response.data.features || {})
      },
      VITE_DIRECT_MCP_GATEWAY_MODIFIER:
        typeof response.data.VITE_DIRECT_MCP_GATEWAY_MODIFIER === 'undefined'
          ? defaultRuntimeConfig.VITE_DIRECT_MCP_GATEWAY_MODIFIER
          : (response.data.VITE_DIRECT_MCP_GATEWAY_MODIFIER as string),
      // Ensure LLM_CONFIG_ADMIN_ONLY is set to false if not present
      LLM_CONFIG_ADMIN_ONLY: typeof response.data.LLM_CONFIG_ADMIN_ONLY === 'undefined' ? false : response.data.LLM_CONFIG_ADMIN_ONLY
    };
  } catch (error) {
    // Always log errors, but with conditional detail level
    console.error(
      "[RUNTIME_CONFIG] Failed to load runtime config",
      isDev ? error : ''
    );

    // Use defaults on error
    window.RUNTIME_CONFIG = { 
      ...defaultRuntimeConfig,
      LLM_CONFIG_ADMIN_ONLY: false
    };
  }

  // Render the main application using the existing root
  if (isDev) {
    console.log("[RUNTIME_CONFIG] Rendering React app...");
  }

  root.render(
    <React.StrictMode>
      <HeroUIProvider>
        <ToastProvider placement="bottom-right" />
        <main className="text-foreground bg-background h-screen overflow-hidden">
          <App />
        </main>
      </HeroUIProvider>
    </React.StrictMode>
  );
};

// Start loading the runtime configuration
fetchRuntimeConfig();
