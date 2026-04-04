import { defineConfig } from 'vite';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  base: '/corrupted-oracle/',
  build: {
    outDir: 'out',
  },
  plugins: [tailwindcss()],
});
