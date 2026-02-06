const express = require('express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: async (req, file) => {
        const timestamp = Date.now();
        const cleanName = file.originalname.split('.')[0].replace(/\s+/g, '_').replace(/[^a-zA-Z0-9_]/g, '').toLowerCase();
        return {
            folder: 'sistema_vehicular',
            format: 'pdf',
            public_id: `${cleanName}_${timestamp}`
        };
    }
});

const upload = multer({ 
    storage: storage,
    fileFilter: (req, file, cb) => {
        if (file.mimetype === "application/pdf") {
            cb(null, true);
        } else {
            cb(new Error("SOLO_PDF_PERMITIDO"), false);
        }
    }
});

const verificarToken = (req, res, next) => {
    const token = req.header('Authorization');
    if (!token) return res.status(401).json({ error: 'Acceso denegado' });
    try {
        const verificado = jwt.verify(token.replace('Bearer ', ''), process.env.JWT_SECRET);
        req.user = verificado;
        next();
    } catch (err) {
        res.status(400).json({ error: 'Token no válido' });
    }
};

// --- RUTAS DE ACCESO ---
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM usuarios WHERE username = $1', [username]);
        if (result.rows.length === 0 || password !== result.rows[0].password_hash) {
            return res.status(400).json({ error: 'Credenciales incorrectas' });
        }
        const user = result.rows[0];
        const token = jwt.sign({ id: user.id, rol: user.rol }, process.env.JWT_SECRET, { expiresIn: '8h' });
        res.json({ token, rol: user.rol, nombre: user.nombre_completo });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- RUTAS ADMINISTRATIVAS DE USUARIOS ---
app.post('/api/admin/crear-usuario', verificarToken, async (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ error: 'No autorizado' });
    const { username, password, nombre_completo } = req.body;
    try {
        await pool.query(
            'INSERT INTO usuarios (username, password_hash, nombre_completo, rol) VALUES ($1, $2, $3, $4)',
            [username, password, nombre_completo, 'user']
        );
        res.json({ message: 'Usuario creado con éxito' });
    } catch (err) { res.status(500).json({ error: 'El usuario ya existe o error en DB' }); }
});

app.get('/api/admin/empleados', verificarToken, async (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ error: 'No autorizado' });
    const result = await pool.query("SELECT id, nombre_completo FROM usuarios WHERE rol = 'user' ORDER BY nombre_completo ASC");
    res.json(result.rows);
});

// --- GESTIÓN DE DOCUMENTOS POR USUARIO (ADMIN) ---
app.get('/api/admin/documentos/:id', verificarToken, async (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ error: 'No autorizado' });
    const result = await pool.query('SELECT * FROM documentos WHERE usuario_id = $1', [req.params.id]);
    res.json(result.rows);
});

app.post('/api/admin/subir-a-usuario', verificarToken, upload.single('archivo'), async (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ error: 'No autorizado' });
    const { tipo_documento, usuario_id, nombre_user } = req.body;
    try {
        await pool.query(
            'INSERT INTO documentos (usuario_id, tipo_documento, url_cloudinary, nombre_user) VALUES ($1, $2, $3, $4)', 
            [usuario_id, tipo_documento, req.file.path, nombre_user]
        );
        res.json({ message: 'Documento cargado correctamente' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/admin/documentos/:id', verificarToken, async (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ error: 'No autorizado' });
    try {
        await pool.query('DELETE FROM documentos WHERE id = $1', [req.params.id]);
        res.json({ message: 'Eliminado' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- DOCUMENTOS EMPRESA ---
app.get('/api/admin/documentos-empresa', verificarToken, async (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ error: 'No autorizado' });
    const result = await pool.query('SELECT * FROM documentos_empresa ORDER BY id DESC');
    res.json(result.rows);
});

app.post('/api/subir-empresa', verificarToken, upload.single('archivo'), async (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ error: 'No autorizado' });
    const { tipo_documento } = req.body;
    try {
        await pool.query('INSERT INTO documentos_empresa (tipo_documento, url_cloudinary) VALUES ($1, $2)', [tipo_documento, req.file.path]);
        res.json({ message: 'Ok' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/admin/documentos-empresa/:id', verificarToken, async (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ error: 'No autorizado' });
    try {
        await pool.query('DELETE FROM documentos_empresa WHERE id = $1', [req.params.id]);
        res.json({ message: 'Eliminado' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.use((err, req, res, next) => {
    if (err.message === 'SOLO_PDF_PERMITIDO') return res.status(400).json({ error: 'Solo PDFs' });
    res.status(500).json({ error: err.message });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Servidor en puerto ${PORT}`));