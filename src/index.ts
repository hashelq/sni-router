/**
 * SNI Router — core library.
 *
 * A TLS proxy that intercepts connections based on SNI hostname
 * and applies configurable rules (serve static files, redirect, handle)
 * while passing all other traffic transparently.
 */

import * as net from "node:net";
import * as tls from "node:tls";
import * as fs from "node:fs";
import * as path from "node:path";
import * as stream from "node:stream";
import { CertManager, type GenerateCACertsOptions, type CACertResult } from "./certs.js";
import { extractSNI } from "./sni.js";
import { matchRule, type ServerConfig, type Rule } from "./config.js";
import type { MitmHandler } from "./types.js";

function log(level: "info" | "warn" | "error", msg: string): void {
  const ts = new Date().toISOString();
  switch (level) {
    case "info": console.log(`[${ts}] ${msg}`); break;
    case "warn": console.warn(`[${ts}] WARN ${msg}`); break;
    case "error": console.error(`[${ts}] ERROR ${msg}`); break;
  }
}

// ── Static file loader ────────────────────────────────────────────────

const MIME_TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".gif": "image/gif",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
  ".ttf": "font/ttf",
  ".txt": "text/plain; charset=utf-8",
};

function getMimeType(filePath: string): string {
  const ext = path.extname(filePath).toLowerCase();
  return MIME_TYPES[ext] || "application/octet-stream";
}

function loadStaticFile(basePath: string, urlPath: string, fallback?: string): { body: Buffer; contentType: string } | null {
  const isDir = fs.existsSync(basePath) && fs.statSync(basePath).isDirectory();

  if (isDir) {
    let resolved = urlPath.split("?")[0];
    if (resolved === "/" || resolved === "") resolved = "index.html";
    else resolved = resolved.slice(1);
    const safePath = path.resolve(basePath, resolved);
    const resolvedBase = path.resolve(basePath);
    if (!safePath.startsWith(resolvedBase)) return null;
    if (fs.existsSync(safePath) && fs.statSync(safePath).isFile()) {
      return { body: fs.readFileSync(safePath), contentType: getMimeType(safePath) };
    }
    if (fallback) {
      const fallbackPath = path.resolve(basePath, fallback);
      if (fallbackPath.startsWith(resolvedBase) && fs.existsSync(fallbackPath) && fs.statSync(fallbackPath).isFile()) {
        return { body: fs.readFileSync(fallbackPath), contentType: getMimeType(fallbackPath) };
      }
    }
    const indexPath = path.join(basePath, "index.html");
    if (fs.existsSync(indexPath)) {
      return { body: fs.readFileSync(indexPath), contentType: "text/html; charset=utf-8" };
    }
    return null;
  }

  if (fs.existsSync(basePath)) {
    return { body: fs.readFileSync(basePath), contentType: getMimeType(basePath) };
  }
  return null;
}

// ── Bidirectional forwarder ───────────────────────────────────────────

async function forward(from: net.Socket, to: net.Socket, label: string): Promise<void> {
  try {
    for await (const chunk of from) {
      if (!to.write(chunk)) {
        await new Promise<void>((resolve) => to.once("drain", resolve));
      }
    }
  } catch {
  } finally {
    to.end();
    from.destroy();
    log("info", `[forward:${label}] stopped`);
  }
}

// ── DuplexStream ──────────────────────────────────────────────────────

class DuplexStream extends stream.Duplex {
  constructor(raw: net.Socket | tls.TLSSocket) {
    super({ objectMode: false });
    raw.on("data", (chunk: Buffer) => { if (!this.destroyed) this.push(chunk); });
    raw.on("end", () => { this.push(null); });
    raw.on("error", () => {});
    this._write = (chunk: Buffer, _encoding: BufferEncoding, cb: () => void) => {
      if (!raw.destroyed) raw.write(chunk);
      cb();
    };
    this._destroy = (_err: Error | null, cb: () => void) => {
      if (!raw.destroyed) raw.destroy();
      cb();
    };
  }
}

// ── Header parser ─────────────────────────────────────────────────────

function parseHeaders(text: string): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const line of text.split("\r\n").slice(1)) {
    const idx = line.indexOf(":");
    if (idx > 0) {
      headers[line.slice(0, idx).trim().toLowerCase()] = line.slice(idx + 1).trim();
    }
  }
  return headers;
}

// ── Main class ────────────────────────────────────────────────────────

export interface SniRouterOptions {
  config: ServerConfig;
  log?: typeof log;
}

export class SniRouter {
  private config: ServerConfig;
  private certManager: CertManager;
  private server: net.Server | null = null;
  private _log: typeof log;

  constructor(opts: SniRouterOptions) {
    this._log = opts.log ?? log;
    this.config = opts.config;
    this.certManager = new CertManager(
      this.config.mitm.certDir,
      this.config.mitm.caCertPath,
      this.config.mitm.caKeyPath,
    );
  }

  async start(): Promise<net.Server> {
    const { host, port } = this.config.proxy;
    this.server = net.createServer((sock) => this.handleClient(sock));
    this.server.on("error", (err) => this._log("error", `Server error: ${err.message}`));

    await new Promise<void>((resolve) => {
      this.server!.listen({ host, port }, () => {
        this._log("info", `SNI Router listening on ${host}:${port}`);
        this._log("info", this.config.mitm.enabled
          ? `MITM enabled — ${Object.keys(this.config.mitm.rules).length} rule(s)`
          : "MITM disabled — all traffic passes through");
        resolve();
      });
    });
    return this.server;
  }

  async stop(): Promise<void> {
    if (this.server) {
      await new Promise<void>((resolve) => this.server!.close((err) => (err ? resolve() : resolve())));
      this.server = null;
      this._log("info", "SNI Router stopped");
    }
  }

  getCertManager(): CertManager { return this.certManager; }
  getConfig(): ServerConfig { return this.config; }

  async generateCA(opts: GenerateCACertsOptions): Promise<CACertResult> {
    const result = await this.certManager.generateCACerts({
      ...opts,
      certPath: opts.certPath ?? this.config.mitm.caCertPath,
      keyPath: opts.keyPath ?? this.config.mitm.caKeyPath,
    });
    this.certManager.clearCache();
    this._log("info", `CA certificate generated: ${result.commonName}`);
    return result;
  }

  // ── Client handler ────────────────────────────────────────────────

  private async handleClient(client: net.Socket): Promise<void> {
    client.setNoDelay(true);
    client.setTimeout(10000, () => { this._log("info", "Client timeout"); client.destroy(); });

    try {
      const data = await this.readSome(client, 8192);
      if (!data || data.length === 0) return;
      client.setTimeout(0);

      if (data.subarray(0, 8).toString() === "CONNECT ") {
        const lines = data.toString("utf-8", 0, data.indexOf("\r\n")).split(/\r?\n/);
        const parts = lines[0].split(" ");
        if (parts.length >= 2) {
          const [target, portStr] = parts[1].split(":");
          const port = parseInt(portStr || "443", 10);
          const headerEnd = data.indexOf("\r\n\r\n") + 4;
          const leftover = headerEnd < data.length ? data.subarray(headerEnd) : Buffer.alloc(0);
          client.pause();
          await this.handleConnect(client, target, port, leftover);
        }
      } else {
        const hostname = extractSNI(data);
        const rule = hostname ? matchRule(hostname, this.config.mitm.rules) : null;
        if (rule && this.config.mitm.enabled) {
          await this.handleMITM(client, hostname!, data, rule);
        } else if (hostname) {
          await this.handlePassthrough(client, hostname, 443, data, false);
        } else {
          const headerText = data.toString("utf-8");
          const hostHeader = headerText.match(/^Host:\s*(.+?)\r?$/mi)?.[1];
          const httpHost = hostHeader?.split(":")[0];
          const httpPort = hostHeader ? parseInt(hostHeader.split(":")[1] || "80", 10) : 80;
          if (httpHost) {
            await this.handlePassthrough(client, httpHost, httpPort, data, false);
          } else {
            client.write("HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nContent-Length: 40\r\nConnection: close\r\n\r\nCould not extract SNI from connection.\r\n");
            client.destroy();
          }
        }
      }
    } catch (err) {
      this._log("error", `Client error: ${(err as Error).message}`);
      client.destroy();
    }
  }

  private async handleConnect(client: net.Socket, hostname: string, port: number, leftover: Buffer): Promise<void> {
    const rule = matchRule(hostname, this.config.mitm.rules);
    if (rule && this.config.mitm.enabled) {
      await this.handleMITMConnect(client, hostname, leftover, rule);
    } else {
      client.resume();
      await this.handlePassthrough(client, hostname, port, leftover, true);
    }
  }

  private async handleMITM(client: net.Socket, hostname: string, clientHello: Buffer, rule: Rule): Promise<void> {
    this._log("info", `INTERCEPT ${hostname} [${rule.type}]`);
    client.write(clientHello);
    const { certPath, keyPath } = await this.certManager.getCert(hostname);
    const tlsSocket = new tls.TLSSocket(client, {
      cert: fs.readFileSync(certPath), key: fs.readFileSync(keyPath),
      minVersion: "TLSv1.2", rejectUnauthorized: false, isServer: true,
    });
    try {
      await this.serveMITMResponse(new DuplexStream(tlsSocket), hostname, rule);
    } catch (err) {
      this._log("error", `MITM error for ${hostname}: ${(err as Error).message}`);
    } finally {
      tlsSocket.destroy();
    }
  }

  private async handleMITMConnect(client: net.Socket, hostname: string, _leftover: Buffer, rule: Rule): Promise<void> {
    this._log("info", `INTERCEPT CONNECT ${hostname} [${rule.type}]`);
    const { certPath, keyPath } = await this.certManager.getCert(hostname);
    client.write("HTTP/1.1 200 Connection established\r\n\r\n");
    const tlsSocket = new tls.TLSSocket(client, {
      secureContext: tls.createSecureContext({ cert: fs.readFileSync(certPath), key: fs.readFileSync(keyPath), minVersion: "TLSv1.2" }),
      isServer: true, rejectUnauthorized: false,
    });
    client.resume();
    try {
      await new Promise<void>((resolve, reject) => {
        tlsSocket.on("secure", () => { this._log("info", `MITM CONNECT TLS handshake complete for ${hostname}`); resolve(); });
        tlsSocket.on("error", reject);
      });
      await this.serveMITMResponse(tlsSocket, hostname, rule);
    } catch (err) {
      this._log("error", `MITM CONNECT error for ${hostname}: ${(err as Error).message}`);
    } finally {
      tlsSocket.destroy();
    }
  }

  // ── MITM response ───────────────────────────────────────────────────

  private async serveMITMResponse(stream: tls.TLSSocket | DuplexStream, hostname: string, rule: Rule): Promise<void> {
    const requestData = await this.collectUntil(stream, "\r\n\r\n", 16384);
    if (!requestData) return;

    const headerText = requestData.toString("utf-8");
    const parts = headerText.split("\r\n")[0].split(" ");
    const headers = parseHeaders(headerText);
    const method = parts.length >= 2 ? parts[0] : "GET";
    const url = parts.length >= 2 ? parts[1] : "/";

    let body = Buffer.alloc(0);
    const bodyStart = requestData.indexOf(Buffer.from("\r\n\r\n"));
    if (bodyStart >= 0) body = Buffer.from(requestData.subarray(bodyStart + 4));
    const contentLength = parseInt(headers["content-length"] || "0", 10);
    if (contentLength > 0 && body.length < contentLength) {
      body = Buffer.concat([body, await this.collectBytes(stream, contentLength - body.length)]);
    }

    if (rule.type === "handle") {
      try {
        let ended = false;
        await rule.value(
          { method, url, headers, body, hostname },
          {
            write: (d: string | Buffer) => stream.write(d),
            end: () => { ended = true; },
          },
        );
        if (ended) stream.end();
      } catch (err) {
        this._log("error", `Handle error for ${hostname}: ${(err as Error).message}`);
        stream.write("HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
      }
    } else if (method === "GET") {
      await this.sendStaticResponse(stream, hostname, rule, url);
    } else {
      stream.write("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    }
  }

  private sendStaticResponse(stream: tls.TLSSocket | DuplexStream, hostname: string, rule: Rule, urlPath: string): Promise<void> {
    let body: Buffer;
    let contentType = "text/html; charset=utf-8";

    if (rule.type === "serve-static") {
      const loaded = loadStaticFile(rule.value!, urlPath, rule.fallback);
      if (loaded) { body = loaded.body; contentType = loaded.contentType; }
      else body = Buffer.from(`<html><body><h1>${hostname} - MITM Intercepted</h1></body></html>`);
    } else if (rule.type === "redirect") {
      body = Buffer.from(`<html><head><meta http-equiv="refresh" content="0;url=${rule.value}"></head><body>Redirecting...</body></html>`);
    } else {
      body = Buffer.from("OK");
    }

    const response = [
      "HTTP/1.1 200 OK",
      `Content-Type: ${contentType}`,
      `Content-Length: ${body.length}`,
      "Connection: close", "", "",
    ].join("\r\n") + body.toString();

    return new Promise<void>((resolve, reject) => {
      stream.write(response, () => resolve());
    });
  }

  // ── Passthrough ─────────────────────────────────────────────────────

  private async handlePassthrough(client: net.Socket, hostname: string, port: number, leftover: Buffer, isConnect: boolean): Promise<void> {
    this._log("info", `PASS ${hostname}:${port}`);
    try {
      const server = new net.Socket();
      await new Promise<void>((resolve, reject) => {
        server.connect(port, hostname, resolve);
        server.setTimeout(10000);
        server.on("error", reject);
      });
      if (isConnect) client.write("HTTP/1.1 200 Connection established\r\n\r\n");
      if (leftover.length > 0) server.write(leftover);
      await Promise.all([forward(client, server, hostname), forward(server, client, hostname)]);
    } catch (err) {
      this._log("error", `Passthrough error for ${hostname}:${port}: ${(err as Error).message}`);
      if (isConnect) client.write("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    }
  }

  // ── Async helpers ─────────────────────────────────────────────────

  private async readSome(sock: net.Socket, maxBytes: number): Promise<Buffer | null> {
    return new Promise((resolve) => {
      const chunks: Buffer[] = [];
      let total = 0;
      let settled = false;
      let idleTimer: ReturnType<typeof setTimeout> | null = null;
      const cleanup = () => { sock.removeListener("data", onData); sock.removeListener("end", onEnd); sock.removeListener("error", onError); if (idleTimer) clearTimeout(idleTimer); };
      const done = (r: Buffer | null) => { if (settled) return; settled = true; cleanup(); resolve(r); };
      const resetIdle = () => { if (idleTimer) clearTimeout(idleTimer); idleTimer = setTimeout(() => done(chunks.length === 0 ? null : Buffer.concat(chunks)), 100); };
      const onData = (c: Buffer) => { chunks.push(c); total += c.length; total >= maxBytes ? done(Buffer.concat(chunks)) : resetIdle(); };
      const onEnd = () => done(chunks.length === 0 ? null : Buffer.concat(chunks));
      const onError = () => done(null);
      sock.on("data", onData); sock.once("end", onEnd); sock.once("error", onError); resetIdle();
    });
  }

  private async collectUntil(s: tls.TLSSocket | DuplexStream, delimiter: string, maxBytes: number): Promise<Buffer | null> {
    return new Promise((resolve) => {
      const chunks: Buffer[] = [];
      let total = 0;
      let settled = false;
      const cleanup = () => { s.removeListener("data", onData); s.removeListener("end", onEnd); s.removeListener("error", onError); };
      const done = (r: Buffer | null) => { if (settled) return; settled = true; cleanup(); resolve(r); };
      const onData = (c: Buffer) => { chunks.push(c); total += c.length; const combined = Buffer.concat(chunks); combined.includes(delimiter) || total >= maxBytes ? done(combined) : undefined; };
      const onEnd = () => done(chunks.length === 0 ? null : Buffer.concat(chunks));
      const onError = () => done(null);
      s.on("data", onData); s.once("end", onEnd); s.once("error", onError);
    });
  }

  private async collectBytes(s: tls.TLSSocket | DuplexStream, remaining: number): Promise<Buffer> {
    if (remaining <= 0) return Buffer.alloc(0);
    return new Promise((resolve, reject) => {
      const chunks: Buffer[] = [];
      let collected = 0;
      const onData = (c: Buffer) => { chunks.push(c); collected += c.length; if (collected >= remaining) { s.removeListener("data", onData); resolve(Buffer.concat(chunks)); } };
      const onEnd = () => { s.removeListener("data", onData); resolve(Buffer.concat(chunks)); };
      const onError = () => { s.removeListener("data", onData); reject(new Error("socket closed")); };
      s.on("data", onData); s.once("end", onEnd); s.once("error", onError);
    });
  }
}

// ── Re-exports ────────────────────────────────────────────────────────

export { CertManager } from "./certs.js";
export type { GenerateCACertsOptions, CACertResult } from "./certs.js";
export { extractSNI } from "./sni.js";
export { matchRule, loadJsonConfig, loadTsConfig } from "./config.js";
export type { ServerConfig, Rule } from "./config.js";
export type { MitmHandler, MitmRequest, MitmResponse } from "./types.js";
