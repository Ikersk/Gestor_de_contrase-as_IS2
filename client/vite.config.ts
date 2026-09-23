import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { defineConfig } from 'vite';
import type { Plugin } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

function sriPlugin(): Plugin {
  return {
    name: 'add-subresource-integrity',
    async writeBundle(options, bundle) {
      const integrityByAsset = new Map<string, string>();

      for (const output of Object.values(bundle)) {
        if (output.type !== 'asset' && output.type !== 'chunk') continue;
        if (!/\.(css|js)$/.test(output.fileName)) continue;

        const content = output.type === 'asset'
          ? output.source
          : output.code;
        const bytes = typeof content === 'string' ? Buffer.from(content) : Buffer.from(content);
        const digest = createHash('sha384').update(bytes).digest('base64');
        integrityByAsset.set(output.fileName, `sha384-${digest}`);
      }

      const outputDirectory = options.dir || path.dirname(options.file || 'dist/index.html');
      const indexPath = path.join(outputDirectory, 'index.html');
      let html = await readFile(indexPath, 'utf8');

      for (const [fileName, integrity] of integrityByAsset) {
        const assetReference = `"/${fileName}"`;
        html = html.replaceAll(
          assetReference,
          `${assetReference} integrity="${integrity}" crossorigin="anonymous"`,
        );
      }

      await writeFile(indexPath, html);
    },
  };
}

export default defineConfig({
  plugins: [react(), tailwindcss(), sriPlugin()],
  server: {
    proxy: {
      '/api': 'http://localhost:3000',
    },
  },
});
