import path from "node:path";

export function requiredEnv(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) {
    throw new Error(`Missing required environment variable ${name}`);
  }
  return value;
}

export function optionalEnv(name: string): string | undefined {
  const value = process.env[name]?.trim();
  return value ? value : undefined;
}

export function solandBaseUrl(): string {
  return requiredEnv("COTEST_SOLAND_BASE_URL").replace(/\/$/, "");
}

export function solandServiceDid(): string {
  return optionalEnv("COTEST_SOLAND_SERVICE_DID") ?? "did:web:soland.joint-e2e.local";
}

export function coauthBaseUrl(): string | undefined {
  return optionalEnv("COTEST_COAUTH_BASE_URL")?.replace(/\/$/, "");
}

export function coauthServiceDid(): string {
  return optionalEnv("COTEST_COAUTH_SERVICE_DID") ?? "did:web:coauth.joint-e2e.local";
}

export function diagnosticsRoot(): string {
  return path.join(
    optionalEnv("COTEST_JOINT_RUN_DIR") ?? path.resolve(process.cwd(), "..", "artifacts", "joint-e2e-local"),
    "diagnostics",
  );
}

export function screenshotRoot(): string {
  return (
    optionalEnv("COTEST_UI_SCREENSHOT_DIR") ??
    path.resolve(process.cwd(), "..", "artifacts", "joint-e2e-local", "screenshots")
  );
}
