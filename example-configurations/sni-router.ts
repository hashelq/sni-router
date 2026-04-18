// npx tsx src/cli.ts --ts-config example-configurations/sni-router.ts

import type { ServerConfig } from "../src/config.js";
import type { MitmHandler } from "../src/types.js";

const config: ServerConfig = {
  proxy: {
    host: "0.0.0.0",
    port: 8080,
  },
  mitm: {
    enabled: true,
    certDir: "./certs",
    caCertPath: "./ca-final.pem",
    caKeyPath: "./ca-key-only.pem",
    rules: {
      "*.example.com": {
        type: "serve-static",
        value: "./example-configurations/html",
        fallback: "example.html",
      },
      "handle.example.com": {
        type: "handle",
        value: ((req: any, res: any) => {
          const html = `
            <html>
              <body>
                <h1>Handled: ${req.hostname}</h1>
                <p>${req.method} ${req.url}</p>
                <p>Headers: <pre>${JSON.stringify(req.headers, null, 2)}</pre></p>
              </body>
            </html>
          `;

          res.write([
            "HTTP/1.1 200 OK",
            "Content-Type: text/html; charset=utf-8",
            `Content-Length: ${Buffer.byteLength(html)}`,
            "Connection: close",
            "", "",
          ].join("\r\n") + html);
          res.end();
        }) as any,
      },
    },
  },
};

export default config;
