/**
 * The single source of truth for authorization, imported by both the API and the web app so
 * the two can never drift. Roles are data (stored in the `roles` collection and editable at
 * runtime); permissions are code, because every server route names one literally.
 */

export const PERMISSIONS = [
  "catalog:read",
  "catalog:write",
  "orders:read",
  "orders:manage",
  "returns:manage",
  "reviews:moderate",
  "promos:manage",
  "inventory:manage",
  "customers:read",
  "users:manage",
  "analytics:read",
] as const;

export type Permission = (typeof PERMISSIONS)[number];

const PERMISSION_SET: ReadonlySet<string> = new Set(PERMISSIONS);

export function isPermission(value: unknown): value is Permission {
  return typeof value === "string" && PERMISSION_SET.has(value);
}

/** Human labels for the role editor's permission matrix. */
export const PERMISSION_LABELS: Record<Permission, string> = {
  "catalog:read": "View catalogue",
  "catalog:write": "Edit products, categories and media",
  "orders:read": "View orders",
  "orders:manage": "Advance order state and refund",
  "returns:manage": "Approve, reject and close returns",
  "reviews:moderate": "Publish and reject reviews",
  "promos:manage": "Create and retire promotions",
  "inventory:manage": "Adjust stock levels",
  "customers:read": "View customer records",
  "users:manage": "Assign roles and edit the permission matrix",
  "analytics:read": "View revenue and performance reporting",
};

/**
 * Seeded roles. `system` roles cannot be deleted; `owner` additionally cannot have
 * `users:manage` revoked, which is what stops an administrator locking everyone out.
 */
export const SYSTEM_ROLES = [
  {
    key: "owner",
    name: "Owner",
    description: "Unrestricted access, including the permission matrix itself.",
    permissions: [...PERMISSIONS],
  },
  {
    key: "ops",
    name: "Operations",
    description: "Runs the store day to day: catalogue, stock, orders, returns, promotions.",
    permissions: [
      "catalog:read",
      "catalog:write",
      "orders:read",
      "orders:manage",
      "returns:manage",
      "reviews:moderate",
      "promos:manage",
      "inventory:manage",
      "analytics:read",
    ],
  },
  {
    key: "support",
    name: "Support",
    description: "Handles customer contact. Can act on orders and returns, cannot edit the catalogue.",
    permissions: [
      "catalog:read",
      "orders:read",
      "orders:manage",
      "returns:manage",
      "reviews:moderate",
      "customers:read",
    ],
  },
  {
    key: "customer",
    name: "Customer",
    description: "Default role for shoppers. No administrative access.",
    permissions: [],
  },
] as const satisfies readonly {
  key: string;
  name: string;
  description: string;
  permissions: readonly Permission[];
}[];

export type SystemRoleKey = (typeof SYSTEM_ROLES)[number]["key"];

/** Roles that unlock any part of the admin console — used to decide whether to show its nav entry. */
export const ADMIN_PERMISSIONS: readonly Permission[] = PERMISSIONS.filter(
  (permission) => permission !== "catalog:read",
);

export function hasAnyPermission(held: readonly string[], required: readonly Permission[]): boolean {
  return required.some((permission) => held.includes(permission));
}

export function hasAllPermissions(held: readonly string[], required: readonly Permission[]): boolean {
  return required.every((permission) => held.includes(permission));
}
