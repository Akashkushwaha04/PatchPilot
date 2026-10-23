import { API_BASE_URL } from "../config";

export default function AdminPanel({ user, users }) {
  const isAdmin = localStorage.getItem("role") === "admin";

  if (!isAdmin) return null;

  async function removeUser(id) {
    await fetch(`${API_BASE_URL}/api/admin/users/${id}?isAdmin=true`, { method: "DELETE" });
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
