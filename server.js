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

// ==========================================
// MIDDLEWARES DE CONTROL DE ACCESO INTERNO
// ==========================================

function verificarToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ error: 'Acceso denegado, falta token' });

    const token = authHeader.split(' ')[1];
    try {
        const verificado = jwt.verify(token, process.env.JWT_SECRET || 'SECRET_KEY_PROVISIONAL');
        req.user = verificado;
        next();
    } catch (err) {
        res.status(403).json({ error: 'Token inválido o expirado' });
    }
}

// Permitir accesos compartidos entre administrador y médico
function permisoAdminDoc(req, res, next) {
    if (req.user.rol === 'admin' || req.user.rol === 'doc') {
        next();
    } else {
        res.status(403).json({ error: 'Permisos insuficientes para este módulo médico/admin' });
    }
}

// Permitir acceso estricto a Administrador
function permisoSoloAdmin(req, res, next) {
    if (req.user.rol === 'admin') {
        next();
    } else {
        res.status(403).json({ error: 'Operación restringida exclusivamente para Administradores' });
    }
}

// Permitir accesos compartidos donde Kelvin interactúa
function permisoKelvin(req, res, next) {
    if (req.user.rol === 'kelvin' || req.user.rol === 'admin') {
        next();
    } else {
        res.status(403).json({ error: 'Acceso denegado para este rol técnico' });
    }
}

// ==========================================
// ENDPOINT DE AUTENTICACIÓN (LOGIN)
// ==========================================
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM usuarios WHERE username = $1', [username]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });

        const usuario = result.rows[0];

        // Comparación de contraseña en plano (según tu base actual)
        if (password !== usuario.password) {
            return res.status(401).json({ error: 'Contraseña incorrecta' });
        }

        // Generación del Payload del Token JWT
        const token = jwt.sign(
            { id: usuario.id, username: usuario.username, rol: usuario.rol, nombre: usuario.nombre },
            process.env.JWT_SECRET || 'SECRET_KEY_PROVISIONAL',
            { expiresIn: '8h' }
        );

        res.json({
            token,
            rol: usuario.rol,
            nombre: usuario.nombre,
            message: 'Login Exitoso'
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==========================================
// ENDPOINTS GENERALES DEL SISTEMA
// ==========================================

// Listar empleados (Accesible por los 3 roles para buscar expedientes)
app.get('/api/admin/empleados', verificarToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT id, nombre, es_pasivo FROM lista_empleados ORDER BY nombre ASC');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Dar de baja a un empleado (Exclusivo Admin)
app.post('/api/admin/mover-a-pasivo/:id', verificarToken, permisoSoloAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        await pool.query('UPDATE lista_empleados SET es_pasivo = true WHERE id = $1', [id]);
        res.json({ message: 'Empleado movido a pasivo con éxito' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Ver todos los documentos unificados de un empleado específico
app.get('/api/admin/documentos/:id', verificarToken, async (req, res) => {
    const { id } = req.params;
    try {
        const query = `
            SELECT id, tipo_documento, url_cloudinary, nombre_user, created_at FROM documentos_admin WHERE usuario_id = $1
            UNION ALL
            SELECT id, tipo_documento, url_cloudinary, nombre_user, created_at FROM documentos_doctor WHERE usuario_id = $1
            UNION ALL
            SELECT id, tipo_documento, url_cloudinary, nombre_user, created_at FROM certifi_competencia WHERE usuario_id = $1
            UNION ALL
            SELECT id, tipo_documento, url_cloudinary, nombre_user, created_at FROM acta_epps WHERE usuario_id = $1
            ORDER BY created_at DESC
        `;
        const result = await pool.query(query, [id]);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Eliminar un archivo físico de los expedientes (Exclusivo Admin)
app.delete('/api/admin/documentos/:id', verificarToken, permisoSoloAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        // Ejecutar eliminación en las tablas correspondientes
        await pool.query('DELETE FROM documentos_admin WHERE id = $1', [id]);
        await pool.query('DELETE FROM documentos_doctor WHERE id = $1', [id]);
        await pool.query('DELETE FROM certifi_competencia WHERE id = $1', [id]);
        await pool.query('DELETE FROM acta_epps WHERE id = $1', [id]);
        res.json({ message: 'Documento eliminado del expediente global' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==========================================
// SUBIDA DE ARCHIVOS POR SEGMENTOS / ROLES
// ==========================================

// 1. CARGA ADMINISTRADOR
app.post('/api/admin/subir', verificarToken, permisoSoloAdmin, upload.single('archivo'), async (req, res) => {
    const { usuario_id, tipo_documento } = req.body;
    if (!req.file) return res.status(400).json({ error: 'Falta el archivo digital' });

    try {
        await pool.query(
            'INSERT INTO documentos_admin (usuario_id, tipo_documento, url_cloudinary, nombre_user) VALUES ($1, $2, $3, $4)',
            [usuario_id, tipo_documento, req.file.path, req.user.nombre]
        );
        res.json({ message: 'Documento Administrativo Guardado' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 2. CARGA MÉDICO (DOC)
app.post('/api/doctor/subir-aptitud', verificarToken, permisoAdminDoc, upload.single('archivo'), async (req, res) => {
    const { usuario_id, tipo_documento } = req.body;
    if (!req.file) return res.status(400).json({ error: 'Falta el archivo médico' });

    try {
        await pool.query(
            'INSERT INTO documentos_doctor (usuario_id, tipo_documento, url_cloudinary, nombre_user) VALUES ($1, $2, $3, $4)',
            [usuario_id, tipo_documento, req.file.path, req.user.nombre]
        );
        res.json({ message: 'Documento Médico Guardado con Éxito' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 3. CARGA TÉCNICA (KELVIN)
app.post('/api/kelvin/subir-certificados', verificarToken, permisoKelvin, upload.single('archivo'), async (req, res) => {
    const { usuario_id, tipo_documento } = req.body;
    if (!req.file) return res.status(400).json({ error: 'No se cargó ningún archivo' });

    let tabla = '';
    if (tipo_documento.toLowerCase().includes('competencia')) {
        tabla = 'certifi_competencia';
    } else if (tipo_documento.toLowerCase().includes('epp')) {
        tabla = 'acta_epps';
    } else {
        return res.status(400).json({ error: "Tipo de documento no reconocido para este panel técnico" });
    }

    try {
        await pool.query(
            `INSERT INTO ${tabla} (usuario_id, tipo_documento, url_cloudinary, nombre_user) VALUES ($1, $2, $3, $4)`,
            [usuario_id, tipo_documento, req.file.path, req.user.nombre]
        );
        res.json({ message: 'Documentación Técnica Guardada' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==========================================
// DOCUMENTOS GENERALES DE LA EMPRESA
// ==========================================
app.get('/api/admin/documentos-empresa', verificarToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT id, tipo_documento, url_cloudinary FROM documentos_empresa ORDER BY id DESC');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/admin/subir-empresa', verificarToken, permisoSoloAdmin, upload.single('archivo'), async (req, res) => {
    const { tipo_documento } = req.body;
    if (!req.file) return res.status(400).json({ error: 'Falta archivo' });
    try {
        await pool.query('INSERT INTO documentos_empresa (tipo_documento, url_cloudinary) VALUES ($1, $2)', [tipo_documento, req.file.path]);
        res.json({ message: 'Ok' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/admin/documentos-empresa/:id', verificarToken, permisoSoloAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        await pool.query('DELETE FROM documentos_empresa WHERE id = $1', [id]);
        res.json({ message: 'Ok' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Inicialización del Servidor
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`🚀 Servidor en ejecución sobre el puerto ${PORT}`);
});