import React, { useState } from 'react';
import Login from './components/Login';
import Dashboard from './components/Dashboard';
import UserProfile from './components/UserProfile';

// FAIL: Claves hardcodeadas en código frontend (visible en bundle público)
const API_KEY      = 'sk-prod-abcdef1234567890';        // FAIL: API key hardcodeada
const API_BASE     = 'http://localhost:3001/api';        // FAIL: HTTP en lugar de HTTPS

function App() {
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [page, setPage]   = useState('dashboard');

  const handleLogin = (newToken) => {
    // FAIL: Token JWT almacenado en localStorage (accesible por XSS)
    // Debería usarse cookie HttpOnly + Secure + SameSite=Strict
    localStorage.setItem('token', newToken);
    setToken(newToken);
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    setToken(null);
  };

  if (!token) {
    return <Login onLogin={handleLogin} apiBase={API_BASE} />;
  }

  return (
    <div style={{ fontFamily: 'sans-serif', maxWidth: 900, margin: '0 auto', padding: 20 }}>
      <nav style={{ display: 'flex', gap: 12, marginBottom: 20, borderBottom: '1px solid #ccc', paddingBottom: 10 }}>
        <strong>Mockup App</strong>
        <button onClick={() => setPage('dashboard')}>Dashboard</button>
        <button onClick={() => setPage('profile')}>Mi Perfil</button>
        <button onClick={handleLogout} style={{ marginLeft: 'auto' }}>Logout</button>
      </nav>

      {/* PASS: Rutas protegidas — solo renderiza si hay token */}
      {page === 'dashboard' && (
        <Dashboard token={token} apiBase={API_BASE} apiKey={API_KEY} />
      )}
      {page === 'profile' && (
        <UserProfile token={token} apiBase={API_BASE} />
      )}
    </div>
  );
}

export default App;
