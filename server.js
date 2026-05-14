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

// Configuración de la base de datos PostgreSQL
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

pool.query('SELECT NOW()', (err, res) => {
    if (err) console.error('❌ Error DB:', err.stack);
    else console.log('✅ DB Conectada');
});

// Configuración de Cloudinary
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: async (req, file) => ({
        folder: 'isertel_gestion',
        format: file.mimetype === 'application/pdf' ? 'pdf' : 'jpg',
        public_id: `${Date.now()}_${file.originalname.split('.')[0]}`
    })
});

const upload = multer({ storage: storage });

const SECRET_KEY = process.env.JWT_SECRET || 'isertel_secret_key';

// Middleware de autenticación
function verificarToken(req, res, next) {
    const header = req.headers['authorization'];
    if (!header) return res.status(403).json({ error: 'Token requerido' });
    const token = header.split(' ')[1];
    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(401).json({ error: 'Token inválido' });
        req.user = decoded;
        next();
    });
}

// --- RUTAS DE AUTENTICACIÓN ---

app.post('/api/login', async (req, res) => {
    const { usuario, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM usuarios WHERE usuario = $1', [usuario]);
        const user = result.rows[0];
        if (user && user.password === password) {
            const token = jwt.sign({ id: user.id, rol: user.rol }, SECRET_KEY, { expiresIn: '8h' });
            res.json({ token, rol: user.rol });
        } else {
            res.status(401).json({ error: 'Credenciales incorrectas' });
        }
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- RUTAS DE EMPLEADOS ---

app.get('/api/activos', verificarToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM activos ORDER BY nombres ASC');
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/pasivos', verificarToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM pasivos ORDER BY nombres ASC');
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- RUTAS DE GESTIÓN DE EXPEDIENTES (ADMIN Y DOCTOR) ---

// Obtener documentos de un empleado específico
app.get('/api/documentos/:tipo_tabla/:usuario_id', verificarToken, async (req, res) => {
    const { tipo_tabla, usuario_id } = req.params;
    const tabla = tipo_tabla === 'activo' ? 'documentos_activos' : 'documentos_pasivos';
    try {
        const result = await pool.query(`SELECT * FROM ${tabla} WHERE usuario_id = $1 ORDER BY created_at DESC`, [usuario_id]);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Subir documento al expediente (Ruta mejorada para Doctor y Admin)
app.post('/api/subir-documento', verificarToken, upload.single('archivo'), async (req, res) => {
    const { usuario_id, tipo_documento, tipo_tabla } = req.body;
    const tabla = tipo_tabla === 'activo' ? 'documentos_activos' : 'documentos_pasivos';
    try {
        await pool.query(
            `INSERT INTO ${tabla} (usuario_id, tipo_documento, url_cloudinary) VALUES ($1, $2, $3)`,
            [usuario_id, tipo_documento, req.file.path]
        );
        res.json({ message: 'Documento subido con éxito' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Eliminar un documento por ID
app.delete('/api/documentos/:tipo_tabla/:id', verificarToken, async (req, res) => {
    const { tipo_tabla, id } = req.params;
    const tabla = tipo_tabla === 'activo' ? 'documentos_activos' : 'documentos_pasivos';
    try {
        await pool.query(`DELETE FROM ${tabla} WHERE id = $1`, [id]);
        res.json({ message: 'Documento eliminado' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- RUTAS ESPECÍFICAS PANEL MÉDICO (BACKWARD COMPATIBILITY) ---

app.post('/api/doctor/subir-expediente', verificarToken, upload.single('archivo'), async (req, res) => {
    const { usuario_id, tipo_documento, tipo_tabla } = req.body;
    const tabla = tipo_tabla === 'activo' ? 'documentos_activos' : 'documentos_pasivos';
    try {
        await pool.query(`INSERT INTO ${tabla} (usuario_id, tipo_documento, url_cloudinary) VALUES ($1, $2, $3)`,
            [usuario_id, tipo_documento, req.file.path]);
        res.json({ message: 'Ok' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Obtener Certificados Médicos (Para compatibilidad con vistas antiguas si existieran)
app.get('/api/doctor/certificados', verificarToken, async (req, res) => {
    try {
        const query = `
            SELECT da.*, a.nombres as empleado FROM documentos_activos da
            JOIN activos a ON da.usuario_id = a.id
            WHERE da.tipo_documento ILIKE '%Certificado médico%' OR da.tipo_documento ILIKE '%Reposo%'
            UNION ALL
            SELECT dp.*, p.nombres as empleado FROM documentos_pasivos dp
            JOIN pasivos p ON dp.usuario_id = p.id
            WHERE dp.tipo_documento ILIKE '%Certificado médico%' OR dp.tipo_documento ILIKE '%Reposo%'
            ORDER BY created_at DESC
        `;
        const result = await pool.query(query);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- GESTIÓN EMPRESARIAL (ADMIN) ---

app.post('/api/subir-empresa', verificarToken, upload.single('archivo'), async (req, res) => {
    const { tipo_documento } = req.body;
    try {
        await pool.query('INSERT INTO documentos_empresa (tipo_documento, url_cloudinary) VALUES ($1, $2)', 
            [tipo_documento, req.file.path]);
        res.json({ message: 'Ok' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/admin/documentos-empresa', verificarToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM documentos_empresa ORDER BY id DESC');
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/admin/documentos-empresa/:id', verificarToken, async (req, res) => {
    const { id } = req.params;
    try {
        await pool.query('DELETE FROM documentos_empresa WHERE id = $1', [id]);
        res.json({ message: 'Ok' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Servidor en puerto ${PORT}`));