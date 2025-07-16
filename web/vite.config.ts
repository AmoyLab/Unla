import react from "@vitejs/plugin-react";
import { defineConfig, loadEnv } from "vite";
import pkg from './package.json';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));

export default defineConfig(({ mode }) => {
  // Load env file based on `mode` in the current working directory.
  // Set the third parameter to '' to load all env regardless of the `VITE_` prefix.
  const env = loadEnv(mode, __dirname, '');

  return {
    base: env.VITE_BASE_URL || '/',
    plugins: [react()],
    build: {
      target: 'esnext',
      minify: 'esbuild',
      sourcemap: false,
    },
    define: {
      __APP_VERSION__: JSON.stringify(pkg.version),
      MONACO_ENV: {
        getWorkerUrl: () => '/monaco-editor/vs/base/worker/workerMain.js'
      }
    },
    resolve: {
      alias: {
        '@': '/src',
      },
    },
    server: {
      allowedHosts: true,
      proxy: {
        '/api': {
          target: env.VITE_DEV_API_BASE_URL || '/api',
          changeOrigin: true,
        }
      },
    },
  };
});
