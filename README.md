# sni-router

A TLS proxy that intercepts connections based on SNI hostname and applies configurable rules, while passing all other traffic through transparently.

## Requirements

- Node.js 22+
- OpenSSL CLI (`openssl` in PATH)

## Why not Bun?

Bun 1.3.3 has a bug where `tls.TLSSocket` wrapping an existing `net.Socket` with `isServer: true` never completes the TLS handshake. The MITM intercept path requires creating a TLS server socket over a raw TCP connection after exchanging HTTP CONNECT data, which triggers this bug. The `secure` event never fires and the handshake hangs indefinitely. Node.js handles this correctly.

Found by AI (GLM 5.1), may be not true.

# As library

```typescript
import { SniRouter, loadJsonConfig, loadTsConfig } from "sni-router";

// JSON
const config = loadJsonConfig("./sni-router.json");

// TypeScript
const config = await loadTsConfig("./sni-router.ts"); // or {} config itself...

const router = new SniRouter({ config });
await router.start();

// later
await router.stop();
```

## As CLI app

```bash
npm install
```

## Usage

### Generate a CA certificate

```bash
npx tsx src/cli.ts --generate-ca
```

Options:

| Flag | Default | Description |
|------|---------|-------------|
| `--cn=NAME` | `SNI Router CA` | Common name for the CA cert |
| `--cert=PATH` | from config | CA cert output path |
| `--key=PATH` | from config | CA key output path |

Environment variables `CA_CN` and `CA_DAYS` (default `3650`) can also be used.

### Start the proxy

```bash
# JSON config
npx tsx src/cli.ts --config example-configurations/sni-router.json

# TypeScript config
npx tsx src/cli.ts --ts-config example-configurations/sni-router.ts
```

`--config` and `--ts-config` are mutually exclusive.

Or with npm scripts:

```bash
npm start       # start proxy (requires editing to set config path)
npm run dev     # start with file watching
```

## Configuration

Two config formats are supported. See `example-configurations/` for working examples.

### JSON config (`--config`)

Validated with zod. Safe — no code execution.

```json
{
  "proxy": { "host": "0.0.0.0", "port": 8080 },
  "mitm": {
    "enabled": true,
    "certDir": "./certs",
    "caCertPath": "./ca.pem",
    "caKeyPath": "./ca.key",
    "rules": {
      "*.example.com": {
        "type": "serve-static",
        "value": "./html",
        "fallback": "example.html"
      }
    }
  }
}
```

### TypeScript config (`--ts-config`)

Full flexibility — computed values, environment variables, imports. Validated with zod after import.

```typescript
import type { ServerConfig } from "../src/config.js";

const config: ServerConfig = {
  proxy: {
    host: process.env.PROXY_HOST ?? "0.0.0.0",
    port: parseInt(process.env.PROXY_PORT ?? "8080"),
  },
  mitm: {
    enabled: true,
    certDir: "./certs",
    caCertPath: "./ca.pem",
    caKeyPath: "./ca.key",
    rules: {
      "*.example.com": {
        type: "serve-static",
        value: "./html",
        fallback: "example.html",
      },
    },
  },
};

export default config;
```

### Rule types

| Type | Description |
|------|-------------|
| `serve-static` | Serves files from `value` path. If `value` is a directory, serves files matching the URL path. `fallback` specifies a file to serve when the requested path doesn't exist. |
| `redirect` | Serves an HTML page with a meta redirect to `value`. |

### Wildcard patterns

Rules support `*.domain` wildcards. `*.example.com` matches `foo.example.com` and `bar.example.com`.

## How it works

1. Listens as an HTTP CONNECT proxy
2. Reads the first bytes to detect CONNECT requests or raw TLS ClientHello
3. For CONNECT: extracts the target hostname from the request line
4. For raw TLS: extracts the SNI hostname from the ClientHello
5. If the hostname matches a rule and MITM is enabled:
   - Generates a TLS certificate signed by the CA
   - Performs a TLS handshake with the client
   - Serves the configured static/redirect response
6. Otherwise: forwards traffic to the real server transparently

## Quick Guide: Redirect All Traffic Through the Proxy

### Prerequisites

Generate a CA certificate and install it as a trusted root on the client machine. This is required for HTTPS interception — without it, browsers and apps will reject the MITM certificates.

```bash
npx tsx src/cli.ts --generate-ca --config example-configurations/sni-router.json
```

### Windows

#### System proxy (apps that respect system proxy settings)

Settings → Network & Internet → Proxy → Manual proxy setup:

- Address: `<proxy-ip>`
- Port: `8080`

Or via command line (run as admin):

```powershell
netsh winhttp set proxy <proxy-ip>:8080
```

To reset:

```powershell
netsh winhttp reset proxy
```

#### Install CA certificate

1. Copy `ca-final.pem` to the Windows machine
2. Double-click the `.pem` file → Install Certificate → Local Machine → Place all certificates in: **Trusted Root Certification Authorities**

Or via PowerShell (run as admin):

```powershell
Import-Certificate -FilePath ca-final.pem -CertStoreLocation Cert:\LocalMachine\Root
```

#### Transparent (redirect all TCP 443 via iptables equivalent)

For full transparent interception without per-app proxy config, use a tool like [Proxifier](https://www.proxifier.com/) or [Netch](https://github.com/netchx/netch) to redirect all outbound TCP 443 through the proxy.

### Linux

#### Environment variable (curl, wget, most CLI tools)

```bash
export https_proxy=http://<proxy-ip>:8080
export HTTPS_PROXY=http://<proxy-ip>:8080
curl https://example.com
```

#### iptables (transparent — redirects all outbound 443)

Replace `<proxy-ip>` with the proxy's IP and `<local-ip>` with this machine's own IP (to avoid loops):

```bash
# Redirect outbound 443 to proxy
sudo iptables -t nat -A OUTPUT -p tcp --dport 443 ! -d <local-ip> -j DNAT --to-destination <proxy-ip>:8080

# Reset
sudo iptables -t nat -D OUTPUT -p tcp --dport 443 ! -d <local-ip> -j DNAT --to-destination <proxy-ip>:8080
```

#### Install CA certificate

```bash
sudo cp ca-final.pem /usr/local/share/ca-certificates/sni-router.crt
sudo update-ca-certificates
```

For Firefox (uses its own cert store): Preferences → Privacy & Security → Certificates → View Certificates → Import → select `ca-final.pem`

### macOS

#### System proxy

System Preferences → Network → Advanced → Proxies:

- Secure Web Proxy (HTTPS): `<proxy-ip>`, port `8080`

#### Install CA certificate

1. Double-click `ca-final.pem` → opens Keychain Access
2. Add to **System** keychain
3. Open the certificate → Trust → When using this certificate: **Always Trust**

### Android

1. Install CA certificate: Settings → Security → Install from storage → select `ca-final.pem`
2. Set proxy: Settings → Wi-Fi → long-press network → Modify network → Advanced options → Proxy → Manual → `<proxy-ip>:8080`

Note: Android 7+ ignores user-installed CAs for most apps. Use a device with a rooted ROM or Android emulator with a writable system partition for full interception.

### iOS

1. Install CA certificate: open `ca-final.pem` via Safari → install profile → Settings → General → VPN & Device Management → install the profile → Settings → General → About → Certificate Trust Settings → enable full trust
2. Set proxy: Settings → Wi-Fi → tap network → Configure Proxy → Manual → `<proxy-ip>:8080`
