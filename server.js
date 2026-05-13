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

// Verificación de conexión inicial
pool.query('SELECT NOW()', (err, res) => {
    if (err) {
        console.error('❌ Error de conexión a la DB:', err.stack);
    } else {
        console.log('✅ Conexión exitosa a la base de datos');
    }
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
        folder: 'sistema_vehicular',
        format: file.mimetype === 'application/pdf' ? 'pdf' : 'jpg',
        public_id: `${Date.now()}_${file.originalname.split('.')[0]}`
    })
});

const upload = multer({ storage });

// Middleware para verificar JWT
const verificarToken = (req, res, next) => {
    const token = req.header('Authorization');
    if (!token) return res.status(401).json({ error: 'Acceso denegado' });
    try {
        const verificado = jwt.verify(token.replace('Bearer ', ''), process.env.JWT_SECRET);
        req.user = verificado;
        next();
    } catch (err) { res.status(400).json({ error: 'Token no válido' }); }
};

// Middleware para permisos de ADMIN y DOC
const permisoAdminDoc = (req, res, next) => {
    if (req.user.rol === 'admin' || req.user.rol === 'doc') {
        next();
    } else {
        res.status(403).json({ error: 'No tienes permisos para esta acción' });
    }
};

// --- RUTAS DE AUTENTICACIÓN ---

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

// --- RUTAS DE GESTIÓN DE USUARIOS (ACTIVOS Y PASIVOS) ---

// Obtener empleados activos (Solo rol 'user', excluye admin y doc)
app.get('/api/admin/empleados', verificarToken, permisoAdminDoc, async (req, res) => {
    try {
        const result = await pool.query("SELECT * FROM usuarios WHERE rol = 'user' ORDER BY nombre_completo ASC");
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Obtener empleados pasivos
app.get('/api/admin/pasivos', verificarToken, permisoAdminDoc, async (req, res) => {
    try {
        const result = await pool.query("SELECT * FROM pasivos ORDER BY nombre_completo ASC");
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/crear-usuario', verificarToken, upload.single('foto'), async (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ error: 'Solo el admin crea usuarios' });
    const { cedula, nombre_completo, fecha_ingreso, correo, celular, direccion } = req.body;
    const foto_url = req.file ? req.file.path : null;
    try {
        await pool.query(
            'INSERT INTO usuarios (username, cedula, nombre_completo, rol, fecha_ingreso, correo, celular, direccion, foto_url) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)',
            [cedula, cedula, nombre_completo, 'user', fecha_ingreso || null, correo, celular, direccion, foto_url]
        );
        res.json({ message: 'Ok' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/mover-a-pasivo/:id', verificarToken, async (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ error: 'Acción restringida' });
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const userRes = await client.query('SELECT * FROM usuarios WHERE id = $1', [req.params.id]);
        if (userRes.rows.length === 0) throw new Error("Usuario no encontrado");
        const u = userRes.rows[0];
        
        const insertPasivo = await client.query(
            'INSERT INTO pasivos (username, cedula, nombre_completo, rol, fecha_ingreso, correo, celular, direccion, foto_url) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id',
            [u.username, u.cedula, u.nombre_completo, u.rol, u.fecha_ingreso, u.correo, u.celular, u.direccion, u.foto_url]
        );
        const nuevoId = insertPasivo.rows[0].id;

        await client.query(
            'INSERT INTO documentos_pasivos (usuario_id, tipo_documento, url_cloudinary, nombre_user) SELECT $1, tipo_documento, url_cloudinary, nombre_user FROM documentos WHERE usuario_id = $2',
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

// --- RUTAS DE DOCUMENTOS ---

// Subida de documentos (Permite Admin y Doc)
app.post('/api/admin/subir-a-usuario', verificarToken, permisoAdminDoc, upload.single('archivo'), async (req, res) => {
    const { tipo_documento, usuario_id, nombre_user, es_pasivo } = req.body;
    const tabla = es_pasivo === 'true' ? 'documentos_pasivos' : 'documentos';
    try {
        await pool.query(
            `INSERT INTO ${tabla} (usuario_id, tipo_documento, url_cloudinary, nombre_user) VALUES ($1, $2, $3, $4)`, 
            [usuario_id, tipo_documento, req.file.path, nombre_user]
        );
        res.json({ message: 'Ok' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Obtener documentos de un usuario específico
app.get('/api/admin/documentos/:id', verificarToken, permisoAdminDoc, async (req, res) => {
    const esPasivo = req.query.pasivo === 'true';
    const tabla = esPasivo ? 'documentos_pasivos' : 'documentos';
    try {
        const result = await pool.query(`SELECT * FROM ${tabla} WHERE usuario_id = $1`, [req.params.id]);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Eliminar documentos
app.delete('/api/admin/documentos/:id', verificarToken, async (req, res) => {
    const esPasivo = req.query.pasivo === 'true';
    const tabla = esPasivo ? 'documentos_pasivos' : 'documentos';
    try {
        await pool.query(`DELETE FROM ${tabla} WHERE id = $1`, [req.params.id]);
        res.json({ message: 'Ok' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- RUTA REFLEJO PARA DOCTOR ---

// Obtener todos los certificados médicos (Activos y Pasivos unidos)
app.get('/api/doctor/certificados-globales', verificarToken, permisoAdminDoc, async (req, res) => {
    try {
        const query = `
            SELECT d.id, d.tipo_documento, d.url_cloudinary, d.created_at, u.nombre_completo as empleado_nombre, 'Activo' as estado_empleado
            FROM documentos d
            JOIN usuarios u ON d.usuario_id = u.id
            WHERE d.tipo_documento ILIKE '%Certificado médico%' OR d.tipo_documento ILIKE '%Reposo%'
            UNION ALL
            SELECT dp.id, dp.tipo_documento, dp.url_cloudinary, dp.created_at, p.nombre_completo as empleado_nombre, 'Pasivo' as estado_empleado
            FROM documentos_pasivos dp
            JOIN pasivos p ON dp.usuario_id = p.id
            WHERE dp.tipo_documento ILIKE '%Certificado médico%' OR dp.tipo_documento ILIKE '%Reposo%'
            ORDER BY created_at DESC
        `;
        const result = await pool.query(query);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- GESTIÓN EMPRESARIAL ---

app.get('/api/admin/documentos-empresa', verificarToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM documentos_empresa ORDER BY id DESC');
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/subir-empresa', verificarToken, upload.single('archivo'), async (req, res) => {
    const { tipo_documento } = req.body;
    try {
        await pool.query('INSERT INTO documentos_empresa (tipo_documento, url_cloudinary) VALUES ($1, $2)', 
            [tipo_documento, req.file.path]);
        res.json({ message: 'Ok' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/admin/documentos-empresa/:id', verificarToken, async (req, res) => {
    try {
        await pool.query('DELETE FROM documentos_empresa WHERE id = $1', [req.params.id]);
        res.json({ message: 'Ok' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- GESTIÓN DE CERTIFICADOS DE APTITUD (MÉDICO) ---

// Obtener todos los documentos de aptitud
app.get('/api/medico/certificados-aptitud', verificarToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM certificados_aptitud ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Subir nuevo documento de aptitud
app.post('/api/medico/subir-aptitud', verificarToken, upload.single('archivo'), async (req, res) => {
    const { usuario_id, tipo_usuario, nombre_user, tipo_documento, periodo_mes } = req.body;
    try {
        await pool.query(
            'INSERT INTO certificados_aptitud (usuario_id, tipo_usuario, nombre_user, tipo_documento, periodo_mes, url_cloudinary) VALUES ($1, $2, $3, $4, $5, $6)',
            [usuario_id, tipo_usuario, nombre_user, tipo_documento, periodo_mes, req.file.path]
        );
        res.json({ message: 'Ok' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Eliminar documento de aptitud
app.delete('/api/medico/certificados-aptitud/:id', verificarToken, async (req, res) => {
    try {
        await pool.query('DELETE FROM certificados_aptitud WHERE id = $1', [req.params.id]);
        res.json({ message: 'Ok' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});




const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Servidor Isertel corriendo en puerto ${PORT}`));