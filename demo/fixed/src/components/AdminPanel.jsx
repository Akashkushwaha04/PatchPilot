import { API_BASE_URL } from "../config";

// `user` comes from GET /api/me (server-verified). The server enforces
// requireAdmin on every admin route; this check only hides UI.
export default function AdminPanel({ user, users, token }) {
  const canManageUsers = user.permissions.includes("users:delete");
  if (!canManageUsers) return null;

  async function removeUser(id) {
    await fetch(`${API_BASE_URL}/api/admin/users/${id}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${token}` },
    });
  }

  return (
    <section>
      <h2>Admin</h2>
      {user.role === "admin" && <p>Signed in as administrator</p>}
      {users.map((u) => (
        <button key={u.id} onClick={() => removeUser(u.id)}>Remove {u.email}</button>
      ))}
    </section>
  );
}
