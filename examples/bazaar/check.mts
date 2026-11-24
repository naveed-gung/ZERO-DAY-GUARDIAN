import assert from "node:assert/strict";
import { SYSTEM_ROLES, hasAllPermissions } from "./permissions.ts";

for (const [roleKey, expected] of [["customer", false], ["ops", true]] as const) {
  const role = SYSTEM_ROLES.find(({ key }) => key === roleKey);
  assert.ok(role);
  const allowed = hasAllPermissions(role.permissions, ["inventory:manage"]);
  assert.equal(allowed, expected);
  console.log(`      ${roleKey} → inventory:manage → ${allowed ? "ALLOWED" : "DENIED"}`);
}
