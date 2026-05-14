import React, { useState, useEffect } from 'react';

// FAIL: Claves de pago hardcodeadas en código frontend público
const STRIPE_PUBLIC_KEY  = 'pk_live_51234abcdefghijklmnopqr';   // FAIL: clave LIVE hardcodeada
const ANALYTICS_WRITE_KEY = 'UA-987654321-2';                    // FAIL

/**
 * Componente Dashboard.
 * FAIL: dangerouslySetInnerHTML con contenido no sanitizado → XSS almacenado.
 * PASS: Resultados de búsqueda renderizados de forma segura (texto plano).
 * FAIL: Claves de API hardcodeadas.
 */
function Dashboard({ token, apiBase, apiKey }) {
  const [announcements, setAnnouncements] = useState([]);
  const [searchQuery, setSearchQuery]     = useState('');
  const [searchResults, setSearchResults] = useState([]);
  const [searchMeta, setSearchMeta]       = useState(null);

  useEffect(() => {
    fetch(`${apiBase}/admin/dashboard`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then(r => r.json())
      .then(data => setAnnouncements(data.announcements || []))
      .catch(() => {});
  }, [apiBase, token]);

  const handleSearch = async () => {
    if (!searchQuery.trim()) return;
    const res  = await fetch(`${apiBase}/users/search?q=${encodeURIComponent(searchQuery)}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const data = await res.json();
    setSearchResults(data.results || []);
    setSearchMeta(data.query); // contiene el query tal cual fue devuelto
  };

  return (
    <div>
      <h1>Dashboard</h1>

      {/* FAIL: dangerouslySetInnerHTML con contenido del servidor sin sanitizar → XSS */}
      <section style={{ marginBottom: 24 }}>
        <h2>Anuncios</h2>
        {announcements.map(a => (
          <div
            key={a.id}
            style={{ padding: 12, border: '1px solid #eee', marginBottom: 8 }}
            // FAIL: XSS almacenado — el contenido viene del servidor sin sanitización
            dangerouslySetInnerHTML={{ __html: a.content }}
          />
        ))}
      </section>

      {/* PASS: Resultados de búsqueda renderizados con texto plano (React auto-escaping) */}
      <section>
        <h2>Buscar Usuarios</h2>
        <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
          <input
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleSearch()}
            placeholder="Buscar por username o email..."
            style={{ flex: 1, padding: 8 }}
          />
          <button onClick={handleSearch}>Buscar</button>
        </div>

        {/* PASS: Texto renderizado de forma segura por React */}
        <ul>
          {searchResults.map(u => (
            <li key={u.id}>{u.username} — {u.email} [{u.role}]</li>
          ))}
        </ul>
      </section>

      {/* Info de debug — usa la apiKey pasada como prop */}
      <details style={{ marginTop: 24, fontSize: 12, color: '#999' }}>
        <summary>Debug info</summary>
        <pre>API Key: {apiKey} | Analytics: {ANALYTICS_WRITE_KEY} | Stripe: {STRIPE_PUBLIC_KEY}</pre>
      </details>
    </div>
  );
}

export default Dashboard;
