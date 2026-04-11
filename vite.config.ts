import { defineConfig } from 'vite';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  base: '/crypto-lab-corrupted-oracle/',
  build: {
    outDir: 'dist',
  },
  plugins: [tailwindcss()],
});
