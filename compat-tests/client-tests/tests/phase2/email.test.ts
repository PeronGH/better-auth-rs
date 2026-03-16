import { compatScenario } from "../../support/scenario";

compatScenario("send verification email then verify marks the user verified", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("phase2-verify");

  const signup = await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Verify User",
  });
  const send = await primary.client.sendVerificationEmail({
    email,
  });
  const record = await ctx.readVerificationEmail({ email }) as { token: string };
  const verify = await primary.client.verifyEmail({
    query: {
      token: record.token,
    },
  });
  const session = await primary.client.getSession();

  return {
    signup: ctx.snapshot(signup),
    send: ctx.snapshot(send),
    verify: ctx.snapshot(verify),
    session: ctx.snapshot(session),
  };
});
