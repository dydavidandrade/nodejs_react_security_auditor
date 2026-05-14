const express = require('express');
const fs = require('fs');
const path = require('path');
const router = express.Router();
const { verifyToken } = require('../middleware/authMiddleware');

const UPLOADS_DIR = path.join(__dirname, '../uploads');

// PASS: Listado de archivos protegido con auth
router.get('/', verifyToken, (req, res) => {
  try {
    const files = fs.readdirSync(UPLOADS_DIR);
    res.json({ files });
  } catch {
    res.json({ files: [] });
  }
});

/**
 * GET /api/files/download
 * FAIL: Path Traversal — el parámetro `filename` / `file` / `path` no es sanitizado
 * PathTraversalScanner envía ?file=../../../etc/passwd y lee el archivo
 * En macOS/Linux el /etc/passwd existe y contiene "root:x:0:"
 */
router.get('/download', verifyToken, (req, res) => {
  const filename = req.query.filename || req.query.file || req.query.path || req.query.doc;
  if (!filename) return res.status(400).json({ error: 'filename param required' });

  // FAIL: path.join no previene traversal si filename es absoluto o contiene ../
  const filePath = path.join(UPLOADS_DIR, filename);

  try {
    const content = fs.readFileSync(filePath);
    res.set('Content-Type', 'application/octet-stream');
    res.send(content);
  } catch (err) {
    // FAIL: El error expone la ruta absoluta en el sistema de archivos
    res.status(404).json({
      error: `Archivo no encontrado: ${filePath}`,
      details: err.message,
    });
  }
});

/**
 * POST /api/files/upload
 * FAIL: Sin validación de tipo de archivo ni extensión
 * FAIL: Nombre de archivo controlado por el usuario (path traversal en write)
 * PASS: Requiere autenticación
 */
router.post('/upload', verifyToken, (req, res) => {
  const { filename, content } = req.body;
  if (!filename || !content) {
    return res.status(400).json({ error: 'filename y content requeridos' });
  }

  // FAIL: Sin validar extensión ni tipo de contenido
  // FAIL: filename puede contener ../ para escribir fuera de uploads/
  const filePath = path.join(UPLOADS_DIR, filename);

  try {
    fs.mkdirSync(UPLOADS_DIR, { recursive: true });
    fs.writeFileSync(filePath, content, 'utf8');
    res.json({ message: 'Archivo subido', path: filePath });
  } catch (err) {
    res.status(500).json({ error: err.message, path: filePath });
  }
});

module.exports = router;
