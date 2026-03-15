export type ResetPasswordMode = "capture" | "throw";
export type OAuthRefreshMode = "success" | "error";

async function postControl(baseURL: string, path: string, body: unknown) {
  const response = await fetch(`${baseURL}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      connection: "close",
    },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`${path} failed for ${baseURL}: ${response.status} ${text}`);
  }

  return response.json().catch(() => null);
}

export async function resetServerState(baseURL: string) {
  return postControl(baseURL, "/__test/reset-state", {});
}

export async function setResetPasswordMode(baseURL: string, mode: ResetPasswordMode) {
  return postControl(baseURL, "/__test/set-reset-password-mode", { mode });
}

export async function seedResetPasswordToken(
  baseURL: string,
  {
    email,
    token,
    expiresAt,
  }: {
    email: string;
    token: string;
    expiresAt: string;
  },
) {
  return postControl(baseURL, "/__test/seed-reset-password-token", {
    email,
    token,
    expiresAt,
  });
}

export async function setOAuthRefreshMode(baseURL: string, mode: OAuthRefreshMode) {
  return postControl(baseURL, "/__test/set-oauth-refresh-mode", { mode });
}

export async function seedOAuthAccount(
  baseURL: string,
  {
    email,
    providerId = "mock",
    accountId = crypto.randomUUID(),
    accessToken = "stale-access-token",
    refreshToken = "seed-refresh-token",
    idToken = "seed-id-token",
    accessTokenExpiresAt = "2000-01-01T00:00:00Z",
    refreshTokenExpiresAt = "2099-01-01T00:00:00Z",
    scope = "openid,email,profile",
  }: {
    email: string;
    providerId?: string;
    accountId?: string;
    accessToken?: string | null;
    refreshToken?: string | null;
    idToken?: string | null;
    accessTokenExpiresAt?: string | null;
    refreshTokenExpiresAt?: string | null;
    scope?: string | null;
  },
) {
  await postControl(baseURL, "/__test/seed-oauth-account", {
    email,
    providerId,
    accountId,
    accessToken,
    refreshToken,
    idToken,
    accessTokenExpiresAt,
    refreshTokenExpiresAt,
    scope,
  });

  return accountId;
}
