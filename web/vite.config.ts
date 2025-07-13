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
      rollupOptions: {
        output: {
          manualChunks: (id) => {
            // Separate vendor chunks to avoid the rollup bug
            if (id.includes('node_modules')) {
              if (id.includes('katex')) return 'katex';
              if (id.includes('highlight.js')) return 'highlight';
              if (id.includes('monaco-editor')) return 'monaco';
              if (id.includes('react')) return 'react';
              return 'vendor';
            }
          }
        },
        onwarn(warning, warn) {
          // Suppress certain warnings that might trigger the bug
          if (warning.code === 'EVAL') return;
          if (warning.code === 'CIRCULAR_DEPENDENCY') return;
          warn(warning);
        }
      },
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
