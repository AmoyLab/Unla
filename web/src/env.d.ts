/// <reference types="vite/client" />

interface ImportMetaEnv {
  // Add Vite's built-in env variables
  readonly MODE: string;
  readonly DEV: boolean;
  readonly PROD: boolean;
  readonly SSR: boolean;
  
  // App-specific env variables
  readonly VITE_MCP_GATEWAY_BASE_URL: string;
  readonly VITE_DIRECT_MCP_GATEWAY_MODIFIER: string;
  readonly VITE_API_BASE_URL: string;
  readonly VITE_WS_BASE_URL: string;
  
  // Allow any other env variables to be defined
  readonly [key: string]: string | boolean | undefined;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
