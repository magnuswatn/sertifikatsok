import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'

// We don't want to change the JS bundle
// when bumping the version, as a bump
// could contain only api changes, so we set
// the version inside index.html instead,
// as that is small and should be reloaded
// often anyways.
const versionPlugin = (version) => {

  // We don't do any HTML encoding, so
  // need to check that the version is
  // formatted as we expect (a git hash).
  const re = /^[a-zA-Z0-9]+$/;
  if (!re.exec(version)) {
    throw new Error(`Invalid version specified: ${version}`)
  }

  return {
    name: 'version-plugin',
    transformIndexHtml(html) {
      return html.replace(
        /__SERTIFIKATSOK_VERSION__/,
        version,
      )
    },
  }
}

// https://vitejs.dev/config/
export default defineConfig(({ command, mode, ssrBuild }) => {

  let version;
  if (command == 'build') {
    version = process.env.SERTIFIKATSOK_VERSION;
    if (version === undefined) {
      throw new Error("Missing 'SERTIFIKATSOK_VERSION' env variable");
    }
  } else {
    version = 'dev';
  }

  let serverConfig = {};
  if (process.env.VITE_PROXY) {
    serverConfig.proxy = {
      '/api': 'http://127.0.0.1:7001',
      '/revocation_info': 'http://127.0.0.1:7001',
    }
  }

  if (process.env.VITE_EXPOSE_0_0_0_0) {
    serverConfig.host = "0.0.0.0"
  }

  return {
    plugins: [svelte(), versionPlugin(version)],
    server: serverConfig,
  }
})
