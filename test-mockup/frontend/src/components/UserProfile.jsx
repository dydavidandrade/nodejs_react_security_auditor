import React, { useState, useEffect } from 'react';

/**
 * Componente de perfil de usuario.
 * PASS: Validación client-side de longitud de bio.
 * PASS: Texto renderizado de forma segura (React auto-escaping).
 * FAIL: Sin token CSRF en las peticiones mutantes (PUT).
 * FAIL: Email sin validación de formato en client ni server.
 */
function UserProfile({ token, apiBase }) {
  const [profile, setProfile] = useState(null);
  const [bio, setBio]         = useState('');
  const [email, setEmail]     = useState('');
  const [message, setMessage] = useState('');
  const [saving, setSaving]   = useState(false);

  useEffect(() => {
    fetch(`${apiBase}/users/profile`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then(r => r.json())
      .then(data => {
        setProfile(data);
        setBio(data.bio || '');
        setEmail(data.email || '');
      });
  }, [apiBase, token]);

  const handleSave = async () => {
    // PASS: Validación client-side de longitud
    if (bio.length > 500) {
      setMessage('Error: La bio no puede superar 500 caracteres');
      return;
    }

    setSaving(true);
    setMessage('');

    const res = await fetch(`${apiBase}/users/profile`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
        // FAIL: Sin header X-CSRF-Token ni token en body
      },
      body: JSON.stringify({ bio, email }),
    });

    const data = await res.json();
    setSaving(false);

    if (res.ok) {
      setProfile(data);
      // PASS: Mensaje de éxito renderizado de forma segura (texto plano)
      setMessage('Perfil actualizado correctamente');
    } else {
      setMessage(`Error: ${data.error}`);
    }
  };

  if (!profile) {
    return <div>Cargando perfil...</div>;
  }

  return (
    <div style={{ maxWidth: 600 }}>
      <h2>Mi Perfil</h2>

      {/* PASS: Datos renderizados de forma segura por React (auto-escaping) */}
      <p><strong>Usuario:</strong> {profile.username}</p>
      <p><strong>Rol:</strong> {profile.role}</p>

      <div style={{ marginBottom: 16 }}>
        <label><strong>Email:</strong></label>
        <input
          type="email"
          value={email}
          onChange={e => setEmail(e.target.value)}
          style={{ display: 'block', width: '100%', padding: 8, marginTop: 4 }}
        />
      </div>

      <div style={{ marginBottom: 16 }}>
        <label>
          <strong>Bio</strong> ({bio.length}/500):
        </label>
        <textarea
          value={bio}
          onChange={e => setBio(e.target.value)}
          maxLength={500}
          rows={4}
          style={{ display: 'block', width: '100%', padding: 8, marginTop: 4 }}
        />
      </div>

      <button onClick={handleSave} disabled={saving}>
        {saving ? 'Guardando...' : 'Guardar cambios'}
      </button>

      {/* PASS: Mensaje renderizado de forma segura */}
      {message && (
        <p style={{ marginTop: 12, color: message.startsWith('Error') ? 'red' : 'green' }}>
          {message}
        </p>
      )}
    </div>
  );
}

export default UserProfile;
