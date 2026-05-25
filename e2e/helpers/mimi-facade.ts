import type { APIRequestContext } from "@playwright/test";
import { mockMimiFacadeBaseUrl, mockMimiFacadeDid } from "./env";

export type MimiFacadeClient = {
  baseUrl: string;
  facadeDid?: string;
  reset(): Promise<void>;
  configure(input: { unavailable?: boolean; force_deferred?: boolean }): Promise<unknown>;
  createJoinRequest(input: {
    room_binding_id: string;
    mimi_handle?: string;
  }): Promise<Record<string, unknown>>;
  approveJoin(input: {
    realm_id: string;
    room_binding_id?: string;
    join_request_id?: string;
    mimi_handle?: string;
  }): Promise<Record<string, unknown>>;
  sendOutbound(input: {
    realm_id: string;
    room_binding_id: string;
    sender_did?: string;
    content_kind?: string;
    content?: unknown;
    reply_to_mimi_event_id?: string;
  }): Promise<{ status: number; body: Record<string, unknown> }>;
  injectInbound(input: {
    room_binding_id: string;
    realm_id?: string;
    mimi_handle?: string;
    content_kind?: string;
    content?: unknown;
    mimi_event_id?: string;
  }): Promise<{ status: number; body: Record<string, unknown> }>;
  inspect(): Promise<Record<string, unknown>>;
};

async function jsonBody(response: Awaited<ReturnType<APIRequestContext["get"]>>) {
  return (await response.json()) as Record<string, unknown>;
}

export function mockMimiFacadeBaseUrlRequired(): string {
  const baseUrl = mockMimiFacadeBaseUrl();
  if (!baseUrl) {
    throw new Error("COTEST_MOCK_MIMI_FACADE_BASE_URL is required");
  }
  return baseUrl;
}

export function createMimiFacadeClient(request: APIRequestContext): MimiFacadeClient | undefined {
  const baseUrl = mockMimiFacadeBaseUrl();
  if (!baseUrl) return undefined;
  const facadeDid = mockMimiFacadeDid();
  return {
    baseUrl,
    facadeDid,
    async reset() {
      await request.delete(`${baseUrl}/scenarios`);
    },
    async configure(input) {
      return jsonBody(await request.post(`${baseUrl}/scenarios`, { data: input }));
    },
    async createJoinRequest(input) {
      return jsonBody(await request.post(`${baseUrl}/api/v1/mimi/join-requests`, { data: input }));
    },
    async approveJoin(input) {
      return jsonBody(await request.post(`${baseUrl}/api/v1/mimi/approve`, { data: input }));
    },
    async sendOutbound(input) {
      const response = await request.post(`${baseUrl}/api/v1/mimi/outbound`, { data: input });
      return { status: response.status(), body: await jsonBody(response) };
    },
    async injectInbound(input) {
      const response = await request.post(`${baseUrl}/api/v1/mimi/inbound`, { data: input });
      return { status: response.status(), body: await jsonBody(response) };
    },
    async inspect() {
      return jsonBody(await request.get(`${baseUrl}/inspect`));
    },
  };
}
