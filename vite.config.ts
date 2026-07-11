import { defineConfig } from 'vitest/config';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  base: '/crypto-lab-corrupted-oracle/',
  build: {
    outDir: 'dist',
  },
  plugins: [tailwindcss()],
  test: {
    include: ['src/**/*.test.ts'],
  },
});
