import { before, beforeEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import { createTestClient } from "../auth-client.mjs";
import {
  requireServerHealthy,
  resetServerState,
  seedResetPasswordToken,
  setResetPasswordMode,
} from "../test-helpers.mjs";

describe("phase1", () => {
  before(async () => {
    await requireServerHealthy();
  });

  beforeEach(async () => {
    await resetServerState();
  });

  it("request password reset then reset password updates credentials", async () => {
    const { client } = createTestClient();
    const email = `phase1-reset-${Date.now()}@test.com`;

    const signup = await client.signUp.email({
      email,
      password: "password123",
      name: "Reset User",
    });
    assert.equal(signup.error, null);

    const requestReset = await client.requestPasswordReset({
      email,
      redirectTo: "/reset",
    });
    assert.equal(requestReset.error, null);
    assert.equal(requestReset.data?.status, true);

    const token = `reset-token-${Date.now()}`;
    await seedResetPasswordToken({
      email,
      token,
      expiresAt: "2099-01-01T00:00:00Z",
    });
    const reset = await client.resetPassword({
      newPassword: "newPassword123!",
      token,
    });
    assert.equal(reset.error, null);
    assert.equal(reset.data?.status, true);

    const { client: freshClient } = createTestClient();
    const signIn = await freshClient.signIn.email({
      email,
      password: "newPassword123!",
    });
    assert.equal(signIn.error, null);
    assert.ok(signIn.data?.user);
  });

  it("request password reset masks nonexistent email", async () => {
    const { client } = createTestClient();

    const result = await client.requestPasswordReset({
      email: `missing-${Date.now()}@test.com`,
      redirectTo: "/reset",
    });

    assert.equal(result.error, null);
    assert.equal(result.data?.status, true);
    assert.equal(
      result.data?.message,
      "If this email exists in our system, check your email for the reset link",
    );
  });

  it("request password reset masks sender failure", async () => {
    await setResetPasswordMode("throw");

    const email = `phase1-mask-${Date.now()}@test.com`;
    const { client } = createTestClient();
    const signup = await client.signUp.email({
      email,
      password: "password123",
      name: "Mask Sender Failure",
    });
    assert.equal(signup.error, null);

    const result = await client.requestPasswordReset({
      email,
      redirectTo: "/reset",
    });

    assert.equal(result.error, null);
    assert.equal(result.data?.status, true);
    assert.equal(
      result.data?.message,
      "If this email exists in our system, check your email for the reset link",
    );
  });

  it("reset password rejects invalid token", async () => {
    const { client } = createTestClient();

    const reset = await client.resetPassword({
      newPassword: "newPassword123!",
      token: "invalid-reset-token",
    });

    assert.ok(reset.error);
    assert.equal(reset.data, null);
  });

  it("reset password token cannot be reused", async () => {
    const { client } = createTestClient();
    const email = `phase1-reuse-${Date.now()}@test.com`;

    const signup = await client.signUp.email({
      email,
      password: "password123",
      name: "Reuse Token User",
    });
    assert.equal(signup.error, null);

    const requestReset = await client.requestPasswordReset({
      email,
      redirectTo: "/reset",
    });
    assert.equal(requestReset.error, null);

    const token = `reuse-token-${Date.now()}`;
    await seedResetPasswordToken({
      email,
      token,
      expiresAt: "2099-01-01T00:00:00Z",
    });
    const first = await client.resetPassword({
      newPassword: "newPassword123!",
      token,
    });
    assert.equal(first.error, null);
    assert.equal(first.data?.status, true);

    const second = await client.resetPassword({
      newPassword: "anotherPassword123!",
      token,
    });
    assert.ok(second.error);
    assert.equal(second.data, null);
  });

  it("list sessions and revoke a session through the SDK", async () => {
    const email = `phase1-sessions-${Date.now()}@test.com`;
    const password = "password123";

    const first = createTestClient();
    const second = createTestClient();

    const signup = await first.client.signUp.email({
      email,
      password,
      name: "Sessions User",
    });
    assert.equal(signup.error, null);

    const secondSignIn = await second.client.signIn.email({ email, password });
    assert.equal(secondSignIn.error, null);

    const sessions = await first.client.listSessions();
    assert.equal(sessions.error, null);
    assert.ok(Array.isArray(sessions.data));
    assert.ok(sessions.data.length >= 2);

    const currentSession = await first.client.getSession();
    assert.equal(currentSession.error, null);
    const currentToken = currentSession.data?.session?.token;
    assert.equal(typeof currentToken, "string");

    const revoke = await first.client.revokeSession({ token: currentToken });
    assert.equal(revoke.error, null);
    assert.equal(revoke.data?.status, true);

    const firstAfter = await first.client.getSession();
    assert.equal(firstAfter.data, null);

    const secondAfter = await second.client.getSession();
    assert.ok(secondAfter.data);
  });

  it("revoke sessions logs out all active clients", async () => {
    const email = `phase1-revoke-all-${Date.now()}@test.com`;
    const password = "password123";

    const first = createTestClient();
    const second = createTestClient();

    const signup = await first.client.signUp.email({
      email,
      password,
      name: "Revoke All User",
    });
    assert.equal(signup.error, null);

    const secondSignIn = await second.client.signIn.email({ email, password });
    assert.equal(secondSignIn.error, null);

    const revoke = await first.client.revokeSessions();
    assert.equal(revoke.error, null);
    assert.equal(revoke.data?.status, true);

    const firstAfter = await first.client.getSession();
    const secondAfter = await second.client.getSession();
    assert.equal(firstAfter.data, null);
    assert.equal(secondAfter.data, null);
  });

  it("change password with revokeOtherSessions invalidates the other client", async () => {
    const email = `phase1-change-${Date.now()}@test.com`;
    const password = "password123";

    const primary = createTestClient();
    const secondary = createTestClient();

    const signup = await primary.client.signUp.email({
      email,
      password,
      name: "Change Password User",
    });
    assert.equal(signup.error, null);

    const secondarySignIn = await secondary.client.signIn.email({ email, password });
    assert.equal(secondarySignIn.error, null);

    const change = await primary.client.changePassword({
      currentPassword: password,
      newPassword: "newPassword123!",
      revokeOtherSessions: true,
    });
    assert.equal(change.error, null);
    assert.ok(change.data?.user);

    const primarySession = await primary.client.getSession();
    assert.ok(primarySession.data);

    const secondarySession = await secondary.client.getSession();
    assert.equal(secondarySession.data, null);
  });

  it("revoke other sessions keeps the caller alive", async () => {
    const email = `phase1-other-${Date.now()}@test.com`;
    const password = "password123";

    const primary = createTestClient();
    const secondary = createTestClient();

    const signup = await primary.client.signUp.email({
      email,
      password,
      name: "Revoke Other Sessions User",
    });
    assert.equal(signup.error, null);

    const secondSignIn = await secondary.client.signIn.email({ email, password });
    assert.equal(secondSignIn.error, null);

    const revoke = await primary.client.revokeOtherSessions();
    assert.equal(revoke.error, null);
    assert.equal(revoke.data?.status, true);

    const primarySession = await primary.client.getSession();
    const secondarySession = await secondary.client.getSession();
    assert.ok(primarySession.data);
    assert.equal(secondarySession.data, null);
  });
});
