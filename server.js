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
    params: async (req, file) => ({
        folder: 'sistema_vehicular',
        format: 'pdf',
        public_id: `${Date.now()}_${file.originalname.split('.')[0]}`
    })
});

const upload = multer({ storage });

const verificarToken = (req, res, next) => {
    const token = req.header('Authorization');
    if (!token) return res.status(401).json({ error: 'Acceso denegado' });
    try {
        const verificado = jwt.verify(token.replace('Bearer ', ''), process.env.JWT_SECRET);
        req.user = verificado;
        next();
    } catch (err) { res.status(400).json({ error: 'Token no válido' }); }
};

// --- ENDPOINT DE INDICADORES ---
app.get('/api/admin/estadisticas', verificarToken, async (req, res) => {
    try {
        const totalTrabajadores = await pool.query("SELECT COUNT(*) FROM usuarios WHERE rol = 'user'");
        const conteoDocs = await pool.query(`
            SELECT tipo_documento, COUNT(*) as cantidad 
            FROM documentos 
            GROUP BY tipo_documento
        `);
        res.json({
            totalTrabajadores: parseInt(totalTrabajadores.rows[0].count),
            detalles: conteoDocs.rows
        });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// LOGIN
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM usuarios WHERE username = $1', [username]);
        if (result.rows.length === 0 || password !== result.rows[0].cedula) {
            return res.status(400).json({ error: 'Credenciales incorrectas' });
        }
        const user = result.rows[0];
        const token = jwt.sign({ id: user.id, rol: user.rol }, process.env.JWT_SECRET, { expiresIn: '8h' });
        res.json({ token, rol: user.rol, nombre: user.nombre_completo });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// CREAR USUARIO (ACTUALIZADO CON FECHA_INGRESO)
app.post('/api/admin/crear-usuario', verificarToken, async (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ error: 'No autorizado' });
    const { cedula, nombre_completo, fecha_ingreso } = req.body;
    try {
        await pool.query(
            'INSERT INTO usuarios (username, cedula, nombre_completo, rol, fecha_ingreso) VALUES ($1, $2, $3, $4, $5)',
            [cedula, cedula, nombre_completo, 'user', fecha_ingreso || null]
        );
        res.json({ message: 'Ok' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// LISTAR EMPLEADOS (ACTIVOS)
app.get('/api/admin/empleados', verificarToken, async (req, res) => {
    const result = await pool.query("SELECT * FROM usuarios WHERE rol = 'user' ORDER BY nombre_completo ASC");
    res.json(result.rows);
});

// LISTAR PASIVOS
app.get('/api/admin/pasivos', verificarToken, async (req, res) => {
    const result = await pool.query("SELECT * FROM pasivos ORDER BY nombre_completo ASC");
    res.json(result.rows);
});

// MOVER A PASIVO (ACTUALIZADO PARA TRANSFERIR FECHA_INGRESO)
app.post('/api/admin/mover-a-pasivo/:id', verificarToken, async (req, res) => {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const userRes = await client.query('SELECT * FROM usuarios WHERE id = $1', [req.params.id]);
        if (userRes.rows.length === 0) throw new Error("Usuario no encontrado");
        const u = userRes.rows[0];

        const insertPasivo = await client.query(
            'INSERT INTO pasivos (username, cedula, nombre_completo, rol, fecha_ingreso) VALUES ($1, $2, $3, $4, $5) RETURNING id',
            [u.username, u.cedula, u.nombre_completo, u.rol, u.fecha_ingreso]
        );
        const nuevoId = insertPasivo.rows[0].id;

        await client.query(
            'INSERT INTO documentos_pasivos (usuario_id, tipo_documento, url_cloudinary, nombre_user, fecha_caducidad) ' +
            'SELECT $1, tipo_documento, url_cloudinary, nombre_user, fecha_caducidad FROM documentos WHERE usuario_id = $2',
            [nuevoId, u.id]
        );

        await client.query('DELETE FROM documentos WHERE usuario_id = $1', [u.id]);
        await client.query('DELETE FROM usuarios WHERE id = $1', [u.id]);

        await client.query('COMMIT');
        res.json({ message: 'Ok' });
    } catch (err) {
        await client.query('ROLLBACK');
        res.status(500).json({ error: err.message });
    } finally { client.release(); }
});

// SUBIR DOCS TRABAJADOR
app.post('/api/admin/subir-a-usuario', verificarToken, upload.single('archivo'), async (req, res) => {
    const { tipo_documento, usuario_id, nombre_user, fecha_caducidad, es_pasivo } = req.body;
    const tabla = es_pasivo === 'true' ? 'documentos_pasivos' : 'documentos';
    try {
        await pool.query(
            `INSERT INTO ${tabla} (usuario_id, tipo_documento, url_cloudinary, nombre_user, fecha_caducidad) VALUES ($1, $2, $3, $4, $5)`, 
            [usuario_id, tipo_documento, req.file.path, nombre_user, fecha_caducidad || null]
        );
        res.json({ message: 'Ok' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// GESTIÓN DOCUMENTOS EMPRESA
app.get('/api/admin/documentos-empresa', verificarToken, async (req, res) => {
    const result = await pool.query('SELECT * FROM documentos_empresa ORDER BY id DESC');
    res.json(result.rows);
});

app.post('/api/subir-empresa', verificarToken, upload.single('archivo'), async (req, res) => {
    const { tipo_documento, fecha_caducidad } = req.body;
    try {
        await pool.query('INSERT INTO documentos_empresa (tipo_documento, url_cloudinary, fecha_caducidad) VALUES ($1, $2, $3)', 
            [tipo_documento, req.file.path, fecha_caducidad || null]);
        res.json({ message: 'Ok' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/admin/documentos/:id', verificarToken, async (req, res) => {
    const esPasivo = req.query.pasivo === 'true';
    const tabla = esPasivo ? 'documentos_pasivos' : 'documentos';
    await pool.query(`DELETE FROM ${tabla} WHERE id = $1`, [req.params.id]);
    res.json({ message: 'Ok' });
});

app.delete('/api/admin/documentos-empresa/:id', verificarToken, async (req, res) => {
    await pool.query('DELETE FROM documentos_empresa WHERE id = $1', [req.params.id]);
    res.json({ message: 'Ok' });
});

app.get('/api/admin/documentos/:id', verificarToken, async (req, res) => {
    const esPasivo = req.query.pasivo === 'true';
    const tabla = esPasivo ? 'documentos_pasivos' : 'documentos';
    const result = await pool.query(`SELECT * FROM ${tabla} WHERE usuario_id = $1`, [req.params.id]);
    res.json(result.rows);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Servidor listo en puerto ${PORT}`));