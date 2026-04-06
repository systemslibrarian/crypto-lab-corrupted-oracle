import { defineConfig } from 'vite';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  base: '/crypto-lab-iron-letter/',
  build: {
    outDir: 'out',
  },
  plugins: [tailwindcss()],
});
