import { compatScenario } from "../../support/scenario";

compatScenario("set password is not exposed over the public HTTP surface", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("phase2-set-password-http");

  const signup = await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Set Password HTTP User",
  });
  const setPassword = await ctx.rawRequest({
    path: "/api/auth/set-password",
    method: "POST",
    json: {
      newPassword: "newPassword123!",
    },
  });

  return {
    signup: ctx.snapshot(signup),
    setPassword: ctx.snapshot(setPassword),
  };
});
