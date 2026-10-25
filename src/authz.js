"use strict";

// Actions a caller can hold on a document.
const PERM = Object.freeze({
  READ: "read",         // see the file and its metadata, download it
  EDIT: "edit",         // change title and category
  DELETE: "delete",     // soft-delete (owner only)
  RESTORE: "restore",   // undo a soft delete (owner only)
  SHARE: "share",       // manage grants and share links (owner only)
  ACTIVITY: "activity", // read the document's audit trail (owner and admins)
});

/**
 * Returns the set of permissions `user` holds on `doc`.
 *
 * Rules, in one place:
 *  - Inactive users hold nothing.
 *  - The owner holds everything. A deleted document offers the owner only RESTORE.
 *  - Admins hold ACTIVITY on every document (they see who did what) but NO content access
 *    unless they are explicitly granted. Admins never download by default.
 *  - Anyone else holds READ or READ+EDIT only through an active grant.
 *  - Deleted documents are invisible to everyone except the owner.
 *
 * The database is queried on every call, so a revoked grant or a deactivated user
 * takes effect on the next request.
 */
function permissionsFor(db, user, doc) {
  const perms = new Set();
  if (!user || !user.active || !doc) return perms;

  if (user.id === doc.owner_id) {
    if (doc.deleted_at) {
      // In the trash the owner can see the record and restore it, and nothing else.
      perms.add(PERM.READ);
      perms.add(PERM.RESTORE);
      return perms;
    }
    for (const p of Object.values(PERM)) perms.add(p);
    return perms;
  }

  if (user.role === "admin") perms.add(PERM.ACTIVITY);
  if (doc.deleted_at) return perms;

  const grants = db
    .prepare("SELECT permission FROM grants WHERE document_id = ? AND user_id = ? AND revoked_at IS NULL")
    .all(doc.id, user.id);
  if (grants.some((g) => g.permission === "edit")) {
    perms.add(PERM.READ);
    perms.add(PERM.EDIT);
  } else if (grants.length > 0) {
    perms.add(PERM.READ);
  }
  return perms;
}

module.exports = { PERM, permissionsFor };
