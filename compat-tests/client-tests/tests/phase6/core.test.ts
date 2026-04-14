import { compatScenario } from "../../support/scenario";
import { signUpUser } from "./helpers";

compatScenario("organization core lifecycle matches TS", async (ctx) => {
  const owner = await signUpUser(ctx, "owner", "phase6-core-owner", "Org Owner");
  const firstSlug = ctx.uniqueToken("phase6-first-org");
  const secondSlug = ctx.uniqueToken("phase6-second-org");
  const availableSlug = ctx.uniqueToken("phase6-available-org");

  const checkAvailable = await owner.orgClient.organization.checkSlug({
    slug: availableSlug,
  });

  const firstOrganization = await owner.orgClient.organization.create({
    name: "Alpha Org",
    slug: firstSlug,
  });
  const secondOrganization = await owner.orgClient.organization.create({
    name: "Beta Org",
    slug: secondSlug,
  });

  const checkTaken = await owner.orgClient.organization.checkSlug({
    slug: firstSlug,
  });

  const listedOrganizations = await owner.orgClient.organization.list();
  const updateFirst = await owner.orgClient.organization.update({
    organizationId: firstOrganization.data?.id ?? "",
    data: {
      name: "Alpha Org Renamed",
      metadata: {
        tier: "gold",
      },
    },
  });
  const activeSecondBySlug = await owner.orgClient.organization.setActive({
    organizationSlug: secondSlug,
  });
  const fullOrganizationBySlugPrecedence =
    await owner.orgClient.organization.getFullOrganization({
      query: {
        organizationId: firstOrganization.data?.id,
        organizationSlug: secondSlug,
      },
    });
  const clearActiveOrganization = await owner.orgClient.organization.setActive({
    organizationId: null,
  });
  const fullOrganizationWithoutActive =
    await owner.orgClient.organization.getFullOrganization();

  return {
    checkAvailable: ctx.snapshot(checkAvailable),
    firstOrganization: ctx.snapshot(firstOrganization),
    secondOrganization: ctx.snapshot(secondOrganization),
    checkTaken: ctx.snapshot(checkTaken),
    listedOrganizations: ctx.snapshot(listedOrganizations),
    updateFirst: ctx.snapshot(updateFirst),
    activeSecondBySlug: ctx.snapshot(activeSecondBySlug),
    fullOrganizationBySlugPrecedence: ctx.snapshot(fullOrganizationBySlugPrecedence),
    clearActiveOrganization: ctx.snapshot(clearActiveOrganization),
    fullOrganizationWithoutActive: ctx.snapshot(fullOrganizationWithoutActive),
  };
});

compatScenario("organization delete returns the deleted org and clears active state", async (ctx) => {
  const owner = await signUpUser(ctx, "owner", "phase6-delete-owner", "Delete Owner");
  const slug = ctx.uniqueToken("phase6-delete-org");

  const created = await owner.orgClient.organization.create({
    name: "Delete Me",
    slug,
  });
  const deleted = await owner.orgClient.organization.delete({
    organizationId: created.data?.id ?? "",
  });
  const fullOrganizationAfterDelete = await owner.orgClient.organization.getFullOrganization();

  return {
    created: ctx.snapshot(created),
    deleted: ctx.snapshot(deleted),
    fullOrganizationAfterDelete: ctx.snapshot(fullOrganizationAfterDelete),
  };
});
