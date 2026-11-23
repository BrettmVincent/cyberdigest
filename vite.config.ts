import { svelte } from '@sveltejs/vite-plugin-svelte';
import { defineConfig, type Plugin } from 'vite';

// GitHub Pages cannot send response headers, so the CSP is a <meta> tag.
// It is injected only into production builds (Vite's dev server needs inline styles/HMR).
const CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "object-src 'none'",
].join('; ');

const csp = (): Plugin => ({
  name: 'cyberdigest-csp',
  apply: 'build',
  transformIndexHtml: (html) =>
    html.replace(
      '<!-- CSP -->',
      `<meta http-equiv="Content-Security-Policy" content="${CSP}" />\n    <meta name="referrer" content="no-referrer" />`,
    ),
});

export default defineConfig({
  root: 'web',
  base: './',
  publicDir: 'public',
  plugins: [svelte({ configFile: '../svelte.config.js' }), csp()],
  build: {
    outDir: '../dist',
    emptyOutDir: true,
    target: 'es2022',
    // Keep CSS in a file (never inline) so style-src 'self' holds.
    cssCodeSplit: false,
    assetsInlineLimit: 0,
  },
});
