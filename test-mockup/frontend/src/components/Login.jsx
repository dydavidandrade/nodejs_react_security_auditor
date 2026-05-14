import React, { useState } from 'react';

/**
 * Componente de Login.
 * PASS: Validación client-side de username y password.
 * FAIL: Open redirect — el parámetro `redirect` de la URL no es validado contra allowlist.
 * FAIL: Credenciales viajan por HTTP (sin HTTPS).
 */
function Login({ onLogin, apiBase }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError]       = useState('');
  const [loading, setLoading]   = useState(false);

  // PASS: Validación client-side (también existe server-side)
  const validate = () => {
    if (!username || username.trim().length < 3) return 'El username debe tener al menos 3 caracteres';
    if (!password || password.length < 6)        return 'La contraseña debe tener al menos 6 caracteres';
    return null;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const validationError = validate();
    if (validationError) { setError(validationError); return; }

    setLoading(true);
    setError('');

    try {
      const res  = await fetch(`${apiBase}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username.trim(), password }),
      });
      const data = await res.json();

      if (!res.ok) {
        setError(data.error || 'Error de autenticación');
        return;
      }

      onLogin(data.token);

      // FAIL: Open redirect — redirige al parámetro `redirect` sin validar el dominio
      const params   = new URLSearchParams(window.location.search);
      const redirect = params.get('redirect');
      if (redirect) {
        window.location.href = redirect;   // FAIL: sin allowlist — permite redirect externo
      }
    } catch {
      setError('Error de conexión con el servidor');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ maxWidth: 360, margin: '80px auto', padding: 24, border: '1px solid #ddd', borderRadius: 8 }}>
      <h2>Iniciar sesión</h2>
      {error && <p style={{ color: 'red', margin: '8px 0' }}>{error}</p>}
      <form onSubmit={handleSubmit}>
        <div style={{ marginBottom: 12 }}>
          <label>Usuario</label>
          <input
            type="text"
            value={username}
            onChange={e => setUsername(e.target.value)}
            style={{ display: 'block', width: '100%', padding: 8, marginTop: 4 }}
            autoComplete="username"
          />
        </div>
        <div style={{ marginBottom: 16 }}>
          <label>Contraseña</label>
          <input
            type="password"
            value={password}
            onChange={e => setPassword(e.target.value)}
            style={{ display: 'block', width: '100%', padding: 8, marginTop: 4 }}
            autoComplete="current-password"
          />
        </div>
        <button type="submit" disabled={loading} style={{ width: '100%', padding: 10 }}>
          {loading ? 'Autenticando...' : 'Entrar'}
        </button>
      </form>
      <p style={{ marginTop: 12, fontSize: 12, color: '#666' }}>
        Demo: admin / Admin@1234
      </p>
    </div>
  );
}

export default Login;
