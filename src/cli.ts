#!/usr/bin/env tsx
/**
 * SNI Router — standalone executable.
 *
 * Usage:
 *   npx tsx src/cli.ts --config sni-router.json     # start with JSON config
 *   npx tsx src/cli.ts --ts-config sni-router.ts     # start with TypeScript config
 *   npx tsx src/cli.ts --generate-ca --config ...    # generate CA cert
 *
 * --config and --ts-config are mutually exclusive.
 */

process.on("uncaughtException", (err) => {
  console.error(`[FATAL] Uncaught exception: ${err.message}\n${err.stack}`);
});
process.on("unhandledRejection", (err) => {
  console.error(`[FATAL] Unhandled rejection: ${err}`);
});

import { SniRouter } from "./index.js";
import { loadJsonConfig, loadTsConfig } from "./config.js";

// ── Parse args ────────────────────────────────────────────────────────

const args = process.argv.slice(2);

const jsonConfigPath = args.find((a) => a.startsWith("--config="))?.split("=")[1]
  ?? (args.includes("--config") ? args[args.indexOf("--config") + 1] : undefined);

const tsConfigPath = args.find((a) => a.startsWith("--ts-config="))?.split("=")[1]
  ?? (args.includes("--ts-config") ? args[args.indexOf("--ts-config") + 1] : undefined);

if (jsonConfigPath && tsConfigPath) {
  console.error("Error: --config and --ts-config are mutually exclusive");
  process.exit(1);
}

const generateCA = args.includes("--generate-ca");

async function getConfig() {
  if (tsConfigPath) {
    console.log(`Loading TypeScript config from ${tsConfigPath}`);
    return loadTsConfig(tsConfigPath);
  }
  const configPath = jsonConfigPath ?? "sni-router.json";
  console.log(`Loading config from ${configPath}`);
  return loadJsonConfig(configPath);
}

if (generateCA) {
  const config = await getConfig();

  const cn = process.argv.find((a) => a.startsWith("--cn="))?.split("=")[1]
    ?? process.env.CA_CN
    ?? "SNI Router CA";

  const certPath = process.argv.find((a) => a.startsWith("--cert="))?.split("=")[1]
    ?? config.mitm.caCertPath;

  const keyPath = process.argv.find((a) => a.startsWith("--key="))?.split("=")[1]
    ?? config.mitm.caKeyPath;

  const days = parseInt(process.env.CA_DAYS ?? "3650", 10);

  console.log(`Generating CA certificate: ${cn}`);
  console.log(`  cert: ${certPath}`);
  console.log(`  key:  ${keyPath}`);
  console.log(`  validity: ${days} days`);

  const router = new SniRouter({ config });

  try {
    await router.generateCA({
      certPath,
      keyPath,
      commonName: cn,
      days,
    });
    console.log("Done.");
  } catch (err) {
    console.error(`Failed: ${(err as Error).message}`);
    process.exit(1);
  }

  process.exit(0);
}

// ── Start proxy server ────────────────────────────────────────────────

const config = await getConfig();

const router = new SniRouter({ config });

process.on("SIGINT", async () => {
  console.log("\nShutting down...");
  await router.stop();
  process.exit(0);
});

process.on("SIGTERM", async () => {
  await router.stop();
  process.exit(0);
});

try {
  await router.start();
} catch (err) {
  console.error(`Failed to start: ${(err as Error).message}`);
  process.exit(1);
}
