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
        format: 'pdf', // Forzamos PDF para consistencia médica y administrativa
        resource_type: 'raw',
        public_id: Date.now() + '-' + file.originalname.split('.')[0]
    })
});

const upload = multer({ storage: storage });

// Middleware de autenticación
const verificarToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Acceso denegado, token no proporcionado' });

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ error: 'Token inválido o expirado' });
        req.user = decoded;
        next();
    });
};

// --- ENDPOINTS DE AUTENTICACIÓN ---

app.post('/api/login', async (req, res) => {
    const { usuario, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM credenciales WHERE usuario = $1 AND password = $2', [usuario, password]);
        if (result.rows.length > 0) {
            const user = result.rows[0];
            const token = jwt.sign({ id: user.id, rol: user.rol }, process.env.JWT_SECRET, { expiresIn: '8h' });
            res.json({ token, rol: user.rol, nombre: user.nombre });
        } else {
            res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
        }
    } catch (err) {
        res.status(500).json({ error: 'Error en el servidor' });
    }
});

// --- ENDPOINTS ADMINISTRADOR (GESTIÓN DE PERSONAL) ---

app.get('/api/admin/empleados', verificarToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM usuarios ORDER BY nombre_completo ASC');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/admin/pasivos', verificarToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM pasivos ORDER BY nombre_completo ASC');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/admin/documentos/:id', verificarToken, async (req, res) => {
    const { id } = req.params;
    const esPasivo = req.query.pasivo === 'true';
    const tabla = esPasivo ? 'documentos_pasivos' : 'documentos_personal';
    const fk = esPasivo ? 'pasivo_id' : 'usuario_id';

    try {
        const result = await pool.query(`SELECT * FROM ${tabla} WHERE ${fk} = $1 ORDER BY created_at DESC`, [id]);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/admin/subir-a-usuario', verificarToken, upload.single('archivo'), async (req, res) => {
    const { usuario_id, nombre_user, tipo_documento, es_pasivo } = req.body;
    const tabla = es_pasivo === 'true' ? 'documentos_pasivos' : 'documentos_personal';
    const fk = es_pasivo === 'true' ? 'pasivo_id' : 'usuario_id';

    try {
        await pool.query(
            `INSERT INTO ${tabla} (${fk}, nombre_user, tipo_documento, url_cloudinary) VALUES ($1, $2, $3, $4)`,
            [usuario_id, nombre_user, tipo_documento, req.file.path]
        );
        res.json({ message: 'Documento subido con éxito' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/admin/documentos/:id', verificarToken, async (req, res) => {
    const { id } = req.params;
    const esPasivo = req.query.pasivo === 'true';
    const tabla = esPasivo ? 'documentos_pasivos' : 'documentos_personal';

    try {
        await pool.query(`DELETE FROM ${tabla} WHERE id = $1`, [id]);
        res.json({ message: 'Documento eliminado' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- ENDPOINTS MÉDICOS (CERTIFICADOS EXISTENTES) ---

app.get('/api/doctor/certificados-globales', verificarToken, async (req, res) => {
    try {
        const query = `
            SELECT dp.*, 'Activo' as estado_empleado, u.nombre_completo as empleado_nombre
            FROM documentos_personal dp
            JOIN usuarios u ON dp.usuario_id = u.id
            WHERE dp.tipo_documento ILIKE '%Certificado médico%' OR dp.tipo_documento ILIKE '%Reposo%'
            UNION ALL
            SELECT dp.*, 'Pasivo' as estado_empleado, p.nombre_completo as empleado_nombre
            FROM documentos_pasivos dp
            JOIN pasivos p ON dp.pasivo_id = p.id
            WHERE dp.tipo_documento ILIKE '%Certificado médico%' OR dp.tipo_documento ILIKE '%Reposo%'
            ORDER BY created_at DESC
        `;
        const result = await pool.query(query);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- NUEVA GESTIÓN: CERTIFICADOS DE APTITUD (Para doctor.html) ---

// Obtener documentos de aptitud por usuario
app.get('/api/doctor/aptitud/:id', verificarToken, async (req, res) => {
    const { id } = req.params;
    const esPasivo = req.query.pasivo === 'true';
    try {
        const result = await pool.query(
            `SELECT * FROM certificados_aptitud WHERE usuario_id = $1 AND es_pasivo = $2 ORDER BY created_at DESC`, 
            [id, esPasivo]
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Subir nuevo certificado de aptitud
app.post('/api/doctor/subir-aptitud', verificarToken, upload.single('archivo'), async (req, res) => {
    const { usuario_id, nombre_user, tipo_documento, es_pasivo } = req.body;
    try {
        await pool.query(
            `INSERT INTO certificados_aptitud (usuario_id, nombre_user, tipo_documento, url_cloudinary, es_pasivo) VALUES ($1, $2, $3, $4, $5)`,
            [usuario_id, nombre_user, tipo_documento, req.file.path, es_pasivo === 'true']
        );
        res.json({ message: 'Certificado de aptitud guardado con éxito' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Eliminar certificado de aptitud
app.delete('/api/doctor/aptitud/:id', verificarToken, async (req, res) => {
    const { id } = req.params;
    try {
        await pool.query(`DELETE FROM certificados_aptitud WHERE id = $1`, [id]);
        res.json({ message: 'Certificado eliminado con éxito' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- GESTIÓN EMPRESARIAL (ADMIN) ---

app.get('/api/admin/documentos-empresa', verificarToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM documentos_empresa ORDER BY id DESC');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/subir-empresa', verificarToken, upload.single('archivo'), async (req, res) => {
    const { tipo_documento } = req.body;
    try {
        await pool.query('INSERT INTO documentos_empresa (tipo_documento, url_cloudinary) VALUES ($1, $2)', 
            [tipo_documento, req.file.path]);
        res.json({ message: 'Documento empresarial subido' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/admin/documentos-empresa/:id', verificarToken, async (req, res) => {
    const { id } = req.params;
    try {
        await pool.query('DELETE FROM documentos_empresa WHERE id = $1', [id]);
        res.json({ message: 'Documento eliminado' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Iniciar servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Servidor corriendo en el puerto ${PORT}`);
});