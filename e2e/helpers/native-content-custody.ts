// Private test custody for the original canonical registration. The Rust
// bridge independently verifies its real receipts and key bindings before use.
import { ProvisioningBridge } from "./provisioning-bridge";

export type NativeContentCustody = {
  principal: Record<string, unknown>;
  stationBaseUrl: string;
  coauthBaseUrl: string;
  trustDomain: string;
  sessionSigningSeedB64url: string;
};

const authors = new Map<string, NativeContentCustody>();

export function registerNativeContentCustody(token: string, custody: NativeContentCustody): void {
  authors.set(token, custody);
}

export async function sealNativeContentMessage(
  token: string,
  groupState: string,
  groupStateRef: string,
  event: Record<string, unknown>,
): Promise<{ event: Record<string, unknown>; groupState: string }> {
  const custody = authors.get(token);
  if (!custody) throw new Error("Encrypted API content requires its actual canonical registration custody");
  // This process imports an existing registration; it never creates another
  // Coauth account, handoff, Device, session holder or MLS group.
  const bridge = ProvisioningBridge.start();
  try {
    return await bridge.sealNativeMessage({ custody, sourceCredential: token, groupState, groupStateRef, event });
  } finally {
    await bridge.dispose();
  }
}
