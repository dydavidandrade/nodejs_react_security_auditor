// VULNERABILIDAD: Secretos hardcodeados — nunca hacer esto en producción
// Gitleaks / SecretsAnalyzer debe detectar estos patrones

module.exports = {
  jwt: {
    secret: "my_super_secret_jwt_key_2024_hardcoded", // FAIL: hardcoded secret
    expiresIn: "7d", // FAIL: debería ser ≤15min
  },
  database: {
    host: "localhost",
    port: 5432,
    name: "myapp_db",
    user: "postgres",
    password: process.env.BD_PASSWORD, // FAIL: hardcoded DB password
  },
  stripe: {
    secretKey: process.env.SECRET_KEY, // FAIL: clave producción hardcodeada
    webhookSecret: process.env.WEBHOOK_SECRET,
  },
  sendgrid: {
    apiKey: process.env.SENDGRID_APIKEY, // FAIL: API key hardcodeada
  },
  server: {
    port: process.env.PORT || 3001,
    env: process.env.NODE_ENV || "development",
  },
};
