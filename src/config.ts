import { z } from "zod";
import * as fs from "node:fs";
import * as path from "node:path";
import { pathToFileURL } from "node:url";

const RuleSchema = z.discriminatedUnion("type", [
  z.object({
    type: z.literal("serve-static"),
    value: z.string(),
    fallback: z.string().optional(),
  }),
  z.object({
    type: z.literal("redirect"),
    value: z.string(),
  }),
  z.object({
    type: z.literal("handle"),
    value: z.function(),
  }),
]);

export type Rule = z.infer<typeof RuleSchema>;

const MITMSchema = z.object({
  enabled: z.boolean().default(true),
  certDir: z.string().default("./certs"),
  caCertPath: z.string().default("./ca-final.pem"),
  caKeyPath: z.string().default("./ca-key-only.pem"),
  rules: z.record(z.string(), RuleSchema).default({}),
});

const ProxySchema = z.object({
  host: z.string().default("0.0.0.0"),
  port: z.coerce.number().int().min(1).max(65535).default(8080),
});

const ConfigSchema = z.object({
  proxy: ProxySchema,
  mitm: MITMSchema,
});

export type ServerConfig = z.infer<typeof ConfigSchema>;

export function loadJsonConfig(configPath: string): ServerConfig {
  const resolved = path.resolve(configPath);
  const raw = JSON.parse(fs.readFileSync(resolved, "utf-8"));
  return ConfigSchema.parse(raw);
}

export async function loadTsConfig(configPath: string): Promise<ServerConfig> {
  const resolved = path.resolve(configPath);
  const mod = await import(pathToFileURL(resolved).href);
  const raw = mod.default ?? mod;
  return ConfigSchema.parse(raw);
}

export function matchRule(host: string, rules: Record<string, Rule>): Rule | null {
  const h = host.toLowerCase();

  if (h in rules) return rules[h];

  for (const [pattern, rule] of Object.entries(rules)) {
    if (!pattern.startsWith("*.")) continue;
    const suffix = pattern.slice(1);
    if (h.endsWith(suffix)) return rule;
  }

  return null;
}
