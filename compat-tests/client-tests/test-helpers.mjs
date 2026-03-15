import assert from "node:assert/strict";
import { BASE_URL, createTestClient } from "./auth-client.mjs";

export async function requireServerHealthy() {
  const res = await fetch(`${BASE_URL}/__health`).catch(() => null);
  if (!res?.ok) {
    throw new Error(`Server not reachable at ${BASE_URL}`);
  }
}

export async function resetServerState() {
  const response = await fetch(`${BASE_URL}/__test/reset-state`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: "{}",
  });
  assert.equal(response.status, 200, "reset-state should return 200");
  const body = await response.json();
  assert.equal(body.status, true);
}

export async function setResetPasswordMode(mode) {
  const response = await fetch(`${BASE_URL}/__test/set-reset-password-mode`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify({ mode }),
  });
  assert.equal(response.status, 200, "set-reset-password-mode should return 200");
  const body = await response.json();
  assert.equal(body.status, true);
}

export async function setOAuthRefreshMode(mode) {
  const response = await fetch(`${BASE_URL}/__test/set-oauth-refresh-mode`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify({ mode }),
  });
  assert.equal(response.status, 200, "set-oauth-refresh-mode should return 200");
  const body = await response.json();
  assert.equal(body.status, true);
}

export async function fetchResetToken(email) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const response = await fetch(
      `${BASE_URL}/__test/reset-password-token?email=${encodeURIComponent(email)}`,
    );
    if (response.status === 200) {
      const body = await response.json();
      assert.equal(typeof body.token, "string");
      return body.token;
    }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  assert.fail("reset token helper should return 200");
}

export async function seedResetPasswordToken({ email, token, expiresAt }) {
  const response = await fetch(`${BASE_URL}/__test/seed-reset-password-token`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify({ email, token, expiresAt }),
  });
  assert.equal(response.status, 200, "seed-reset-password-token should return 200");
  const body = await response.json();
  assert.equal(body.status, true);
}

export async function seedOAuthAccount({
  email,
  providerId = "mock",
  accountId = `mock-account-${Date.now()}-${Math.random().toString(16).slice(2)}`,
  accessToken = "stale-access-token",
  refreshToken = "seed-refresh-token",
  idToken = "seed-id-token",
  accessTokenExpiresAt = "2000-01-01T00:00:00Z",
  refreshTokenExpiresAt = "2099-01-01T00:00:00Z",
  scope = "openid,email,profile",
} = {}) {
  const response = await fetch(`${BASE_URL}/__test/seed-oauth-account`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify({
      email,
      providerId,
      accountId,
      accessToken,
      refreshToken,
      idToken,
      accessTokenExpiresAt,
      refreshTokenExpiresAt,
      scope,
    }),
  });
  assert.equal(response.status, 200, "seed-oauth-account should return 200");
  const body = await response.json();
  assert.equal(body.status, true);
}

export async function signUpClient(email, password = "password123", name = "Test User") {
  const session = createTestClient();
  const signup = await session.client.signUp.email({ email, password, name });
  assert.equal(signup.error, null);
  return session;
}
