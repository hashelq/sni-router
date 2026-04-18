import * as fs from "node:fs";
import * as path from "node:path";
import { execFile } from "node:child_process";

interface CertPaths {
  certPath: string;
  keyPath: string;
}

interface CAHandles {
  caCertPath: string;
  caKeyPath: string;
  hasCA: boolean;
}

export interface GenerateCACertsOptions {
  certPath: string;
  keyPath: string;
  commonName: string;
  days?: number;
}

export interface CACertResult {
  certPath: string;
  keyPath: string;
  commonName: string;
}

function execOpenSSL(args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile("openssl", args, { maxBuffer: 10 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) {
        reject(new Error(`openssl ${args.join(" ")} failed: ${stderr || err.message}`));
      } else {
        resolve(stdout);
      }
    });
  });
}

export class CertManager {
  private certDir: string;
  private ca: CAHandles;
  private certCache = new Map<string, CertPaths>();

  constructor(certDir: string, caCertPath: string, caKeyPath: string) {
    this.certDir = certDir;
    const hasCA = fs.existsSync(caCertPath) && fs.existsSync(caKeyPath);
    this.ca = { caCertPath, caKeyPath, hasCA };
  }

  async getCert(hostname: string): Promise<CertPaths> {
    const cached = this.certCache.get(hostname);
    if (cached) return cached;

    const certPath = path.join(this.certDir, `${sanitizeFilename(hostname)}.pem`);
    const keyPath = path.join(this.certDir, `${sanitizeFilename(hostname)}.key`);

    if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
      this.certCache.set(hostname, { certPath, keyPath });
      return { certPath, keyPath };
    }

    ensureDir(this.certDir);

    if (this.ca.hasCA) {
      await generateDomainCert(hostname, certPath, keyPath, this.ca);
    } else {
      await generateSelfSignedCert(hostname, certPath, keyPath);
    }

    const result = { certPath, keyPath };
    this.certCache.set(hostname, result);
    return result;
  }

  clearCache(): void {
    this.certCache.clear();
  }

  hasCA(): boolean {
    return this.ca.hasCA;
  }

  async generateCACerts(opts: GenerateCACertsOptions): Promise<CACertResult> {
    const { certPath, keyPath, commonName, days = 3650 } = opts;

    ensureDir(path.dirname(certPath));
    ensureDir(path.dirname(keyPath));

    const keyArgs = ["genrsa", "4096"];
    const keyPem = await execOpenSSL(keyArgs);
    fs.writeFileSync(keyPath, keyPem);

    const subject = `/CN=${commonName}`;

    const reqArgs = [
      "req", "-x509", "-new", "-nodes",
      "-key", keyPath,
      "-sha256",
      "-days", String(days),
      "-subj", subject,
      "-addext", "basicConstraints=critical,CA:TRUE",
      "-addext", "keyUsage=critical,keyCertSign,cRLSign",
      "-out", certPath,
    ];
    await execOpenSSL(reqArgs);

    this.ca = { caCertPath: opts.certPath, caKeyPath: opts.keyPath, hasCA: true };

    return { certPath, keyPath, commonName };
  }
}

async function generateDomainCert(
  hostname: string,
  certPath: string,
  keyPath: string,
  ca: CAHandles,
): Promise<void> {
  const keyPem = await execOpenSSL(["genrsa", "2048"]);
  const tmpKeyPath = keyPath + ".tmp";
  const tmpCsrPath = certPath + ".csr.tmp";

  try {
    fs.writeFileSync(tmpKeyPath, keyPem);

    const subject = `/CN=${hostname}`;
    await execOpenSSL([
      "req", "-new",
      "-key", tmpKeyPath,
      "-subj", subject,
      "-addext", `subjectAltName=DNS:${hostname}`,
      "-out", tmpCsrPath,
    ]);

    const extFile = certPath + ".ext.tmp";
    fs.writeFileSync(extFile, [
      "basicConstraints=CA:FALSE",
      "keyUsage=digitalSignature,keyEncipherment",
      `subjectAltName=DNS:${hostname}`,
    ].join("\n"));

    await execOpenSSL([
      "x509", "-req",
      "-in", tmpCsrPath,
      "-CA", ca.caCertPath,
      "-CAkey", ca.caKeyPath,
      "-CAcreateserial",
      "-days", "365",
      "-sha256",
      "-extfile", extFile,
      "-out", certPath,
    ]);

    fs.renameSync(tmpKeyPath, keyPath);
  } finally {
    safeUnlink(tmpKeyPath);
    safeUnlink(tmpCsrPath);
    safeUnlink(certPath + ".ext.tmp");
    safeUnlink(ca.caCertPath + ".srl");
  }
}

async function generateSelfSignedCert(
  hostname: string,
  certPath: string,
  keyPath: string,
): Promise<void> {
  const keyPem = await execOpenSSL(["genrsa", "2048"]);
  fs.writeFileSync(keyPath, keyPem);

  const subject = `/CN=${hostname}`;
  await execOpenSSL([
    "req", "-x509", "-new", "-nodes",
    "-key", keyPath,
    "-sha256",
    "-days", "365",
    "-subj", subject,
    "-addext", `subjectAltName=DNS:${hostname}`,
    "-addext", "basicConstraints=CA:FALSE",
    "-out", certPath,
  ]);
}

function ensureDir(dir: string): void {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function sanitizeFilename(name: string): string {
  return name.replace(/[^a-zA-Z0-9._-]/g, "_");
}

function safeUnlink(p: string): void {
  try { fs.unlinkSync(p); } catch {}
}
