// The router may preserve percent encoding or render the decoded Realm ID.
// Match one complete path component, never a prefix or a decoded separator.
export function matchesRealmChatRoute(url: URL, realmId: string): boolean {
  const prefix = "/chat/";
  if (!url.pathname.startsWith(prefix)) return false;
  try {
    return decodeURIComponent(url.pathname.slice(prefix.length)) === realmId;
  } catch {
    return false;
  }
}
