import { expect, test } from "../../helpers/arkret-test";

function requiredEnv(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) {
    throw new Error(`PRECONDITION_MISSING lane=platform-live name=${name}`);
  }
  return value;
}

test(
  "configured provider accepts an authentic live webhook delivery",
  { tag: "@platform-live" },
  async ({ request }) => {
    const provider = requiredEnv("COTEST_PLATFORM_PROVIDER");
    const baseUrl = requiredEnv("COTEST_PLATFORM_LIVE_BASE_URL").replace(/\/$/, "");
    const webhookPath = requiredEnv("COTEST_PLATFORM_WEBHOOK_PATH");
    const body = Buffer.from(requiredEnv("COTEST_PLATFORM_WEBHOOK_BODY_BASE64"), "base64");
    const headersValue = JSON.parse(requiredEnv("COTEST_PLATFORM_WEBHOOK_HEADERS_JSON")) as unknown;
    if (!headersValue || typeof headersValue !== "object" || Array.isArray(headersValue)) {
      throw new Error(
        "PRECONDITION_INVALID lane=platform-live name=COTEST_PLATFORM_WEBHOOK_HEADERS_JSON",
      );
    }
    const headers = Object.fromEntries(
      Object.entries(headersValue).map(([name, value]) => {
        if (typeof value !== "string") {
          throw new Error(
            `PRECONDITION_INVALID lane=platform-live name=header:${name}`,
          );
        }
        return [name, value];
      }),
    );

    const health = await request.get(`${baseUrl}/health`);
    expect(health.ok(), `${provider} bridge health`).toBeTruthy();

    const response = await request.post(
      `${baseUrl}/${webhookPath.replace(/^\//, "")}`,
      { data: body, headers },
    );
    expect(response.ok(), `${provider} authentic webhook delivery`).toBeTruthy();
  },
);
