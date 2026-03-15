import { before, beforeEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import { createTestClient } from "../auth-client.mjs";
import {
  requireServerHealthy,
  resetServerState,
  seedOAuthAccount,
  setOAuthRefreshMode,
} from "../test-helpers.mjs";

describe("phase1-oauth", () => {
  before(async () => {
    await requireServerHealthy();
  });

  beforeEach(async () => {
    await resetServerState();
  });

  it("get access token returns stored unexpired token", async () => {
    const email = `phase1-oauth-valid-${Date.now()}@test.com`;
    const { client } = createTestClient();

    const signup = await client.signUp.email({
      email,
      password: "password123",
      name: "OAuth Access User",
    });
    assert.equal(signup.error, null);

    await seedOAuthAccount({
      email,
      accessToken: "still-valid-access-token",
      refreshToken: "seed-refresh-token",
      accessTokenExpiresAt: "2099-01-01T00:00:00Z",
      refreshTokenExpiresAt: "2099-01-01T00:00:00Z",
    });

    const result = await client.getAccessToken({
      providerId: "mock",
    });

    assert.equal(result.error, null);
    assert.equal(result.data?.accessToken, "still-valid-access-token");
  });

  it("get access token refreshes expired token", async () => {
    const email = `phase1-oauth-refresh-${Date.now()}@test.com`;
    const { client } = createTestClient();

    const signup = await client.signUp.email({
      email,
      password: "password123",
      name: "OAuth Refresh User",
    });
    assert.equal(signup.error, null);

    await seedOAuthAccount({
      email,
      accessToken: "stale-access-token",
      refreshToken: "seed-refresh-token",
      accessTokenExpiresAt: "2000-01-01T00:00:00Z",
      refreshTokenExpiresAt: "2099-01-01T00:00:00Z",
    });

    const result = await client.getAccessToken({
      providerId: "mock",
    });

    assert.equal(result.error, null);
    assert.equal(result.data?.accessToken, "new-access-token");
  });

  it("refresh token returns a fresh token set", async () => {
    const email = `phase1-refresh-token-${Date.now()}@test.com`;
    const { client } = createTestClient();

    const signup = await client.signUp.email({
      email,
      password: "password123",
      name: "Refresh Token User",
    });
    assert.equal(signup.error, null);

    await seedOAuthAccount({
      email,
      accessToken: "stale-access-token",
      refreshToken: "seed-refresh-token",
      accessTokenExpiresAt: "2000-01-01T00:00:00Z",
      refreshTokenExpiresAt: "2099-01-01T00:00:00Z",
    });

    const result = await client.refreshToken({
      providerId: "mock",
    });

    assert.equal(result.error, null);
    assert.equal(result.data?.accessToken, "new-access-token");
    assert.equal(result.data?.refreshToken, "new-refresh-token");
  });

  it("refresh token surfaces provider refresh failure", async () => {
    const email = `phase1-refresh-fail-${Date.now()}@test.com`;
    const { client } = createTestClient();

    const signup = await client.signUp.email({
      email,
      password: "password123",
      name: "Refresh Failure User",
    });
    assert.equal(signup.error, null);

    await seedOAuthAccount({
      email,
      accessToken: "stale-access-token",
      refreshToken: "seed-refresh-token",
      accessTokenExpiresAt: "2000-01-01T00:00:00Z",
      refreshTokenExpiresAt: "2099-01-01T00:00:00Z",
    });
    await setOAuthRefreshMode("error");

    const result = await client.refreshToken({
      providerId: "mock",
    });

    assert.ok(result.error);
    assert.equal(result.data, null);
  });
});
