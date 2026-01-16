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

// --- 1. CONEXIÓN A BASE DE DATOS ---
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

pool.connect((err) => {
    if (err) console.error("❌ [DB ERROR]:", err.message);
    else console.log("🐘 [DB]: Conectado a PostgreSQL correctamente.");
});

// --- 2. CONFIGURACIÓN DE CLOUDINARY ---
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// --- 3. CONFIGURACIÓN DE STORAGE CON LOGS ---
const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: async (req, file) => {
        const timestamp = Date.now();
        const cleanName = file.originalname.split('.')[0].replace(/\s+/g, '_').replace(/[^a-zA-Z0-9_]/g, '').toLowerCase();
        
        console.log(`☁️  [CLOUDINARY]: Preparando subida de "${file.originalname}"...`);

        if (file.mimetype === 'application/pdf') {
            return {
                folder: 'sistema_vehicular',
                resource_type: 'image',
                format: 'pdf',
                public_id: `${cleanName}_${timestamp}`
            };
        } else {
            return {
                folder: 'sistema_vehicular',
                resource_type: 'raw',
                public_id: `${cleanName}_${timestamp}`
            };
        }
    }
});
const upload = multer({ storage: storage });

// --- 4. MIDDLEWARE DE SEGURIDAD CON LOGS ---
const verificarToken = (req, res, next) => {
    const token = req.header('Authorization');
    if (!token) {
        console.warn("⚠️  [AUTH]: Intento de acceso sin token.");
        return res.status(401).json({ error: 'No se proporcionó token' });
    }
    
    try {
        const verificado = jwt.verify(token.replace('Bearer ', ''), process.env.JWT_SECRET);
        req.user = verificado;
        next();
    } catch (err) {
        console.error("🚫 [AUTH]: Token inválido o expirado.");
        res.status(400).json({ error: 'Sesión expirada' });
    }
};

// --- 5. RUTA: LOGIN ---
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    console.log(`🔑 [LOGIN]: Intento de inicio de sesión para el usuario: "${username}"`);
    
    try {
        const result = await pool.query('SELECT * FROM usuarios WHERE username = $1', [username]);
        if (result.rows.length === 0 || password !== result.rows[0].password_hash) {
            console.warn(`❌ [LOGIN]: Credenciales fallidas para: "${username}"`);
            return res.status(400).json({ error: 'Credenciales inválidas' });
        }
        
        const user = result.rows[0];
        const token = jwt.sign({ id: user.id, rol: user.rol }, process.env.JWT_SECRET, { expiresIn: '8h' });
        
        console.log(`✅ [LOGIN]: Usuario "${username}" autenticado con éxito. Rol: ${user.rol}`);
        res.json({ token, rol: user.rol, nombre: user.nombre_completo });
    } catch (err) {
        console.error("💥 [LOGIN ERROR]:", err.message);
        res.status(500).json({ error: err.message });
    }
});

// --- 6. RUTA: SUBIR ARCHIVO ---
app.post('/api/subir', verificarToken, upload.single('archivo'), async (req, res) => {
    const { tipo_documento } = req.body;
    const usuarioId = req.user.id;
    
    try {
        if (!req.file) {
            console.warn(`📁 [UPLOAD]: El usuario ID ${usuarioId} intentó subir un archivo vacío.`);
            return res.status(400).json({ error: "Sin archivo" });
        }

        const query = 'INSERT INTO documentos (usuario_id, tipo_documento, url_cloudinary) VALUES ($1, $2, $3)';
        await pool.query(query, [usuarioId, tipo_documento, req.file.path]);
        
        console.log(`📤 [UPLOAD]: Archivo "${tipo_documento}" guardado en DB para usuario ID ${usuarioId}. URL: ${req.file.path}`);
        res.json({ message: 'Éxito' });
    } catch (err) {
        console.error("💥 [UPLOAD ERROR]:", err.message);
        res.status(500).json({ error: err.message });
    }
});

// --- 7. RUTAS: ADMINISTRACIÓN ---
app.get('/api/admin/empleados', verificarToken, async (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ error: 'No autorizado' });
    
    console.log(`👥 [ADMIN]: Administrador consultando lista de empleados.`);
    const result = await pool.query("SELECT id, nombre_completo FROM usuarios WHERE rol = 'user'");
    res.json(result.rows);
});

app.get('/api/admin/documentos/:id', verificarToken, async (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ error: 'No autorizado' });
    
    console.log(`📂 [ADMIN]: Consultando expediente del usuario ID: ${req.params.id}`);
    const result = await pool.query('SELECT * FROM documentos WHERE usuario_id = $1', [req.params.id]);
    res.json(result.rows);
});

app.delete('/api/admin/documentos/:id', verificarToken, async (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ error: 'No autorizado' });
    
    try {
        await pool.query('DELETE FROM documentos WHERE id = $1', [req.params.id]);
        console.log(`🗑️  [ADMIN]: Documento ID ${req.params.id} eliminado de la base de datos.`);
        res.json({ message: 'Borrado' });
    } catch (err) {
        console.error("💥 [DELETE ERROR]:", err.message);
        res.status(500).json({ error: err.message });
    }
});

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`\n🚀 ==========================================`);
    console.log(`🚀 SERVIDOR CORRIENDO EN PUERTO: ${PORT}`);
    console.log(`🚀 SISTEMA VEHICULAR LISTO PARA OPERAR`);
    console.log(`==========================================\n`);
});