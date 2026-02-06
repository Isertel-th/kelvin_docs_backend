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

// --- LOGIN ---
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

// --- RUTA CRÍTICA: CREAR USUARIO CON LOGS ---
app.post('/api/admin/crear-usuario', verificarToken, async (req, res) => {
    console.log("--- INICIO DE CREACIÓN DE USUARIO ---");
    console.log("Datos recibidos:", req.body);
    
    if (req.user.rol !== 'admin') {
        console.log("FALLO: El usuario no es admin");
        return res.status(403).json({ error: 'No autorizado' });
    }

    const { username, password_hash, nombre_completo } = req.body;

    try {
        console.log("Ejecutando Query en DB...");
        const query = 'INSERT INTO usuarios (username, password_hash, nombre_completo, rol) VALUES ($1, $2, $3, $4) RETURNING id';
        const values = [username, password_hash, nombre_completo, 'user'];
        
        const result = await pool.query(query, values);
        console.log("USUARIO CREADO EXITOSAMENTE. ID:", result.rows[0].id);
        
        res.json({ message: 'Usuario creado', id: result.rows[0].id });
    } catch (err) {
        console.error("!!! ERROR EN DB !!!");
        console.error("Mensaje de error:", err.message);
        console.error("Código de error:", err.code); // Ayuda a saber si es duplicado o falta columna
        res.status(500).json({ 
            error: 'Error interno de DB', 
            detalle: err.message,
            codigo: err.code 
        });
    }
});

// --- LISTA DE EMPLEADOS ---
app.get('/api/admin/empleados', verificarToken, async (req, res) => {
    const result = await pool.query("SELECT id, nombre_completo FROM usuarios WHERE rol = 'user' ORDER BY nombre_completo ASC");
    res.json(result.rows);
});

// --- SUBIDA DE DOCUMENTOS (ADMIN) ---
app.post('/api/admin/subir-a-usuario', verificarToken, upload.single('archivo'), async (req, res) => {
    const { tipo_documento, usuario_id, nombre_user } = req.body;
    try {
        await pool.query(
            'INSERT INTO documentos (usuario_id, tipo_documento, url_cloudinary, nombre_user) VALUES ($1, $2, $3, $4)', 
            [usuario_id, tipo_documento, req.file.path, nombre_user]
        );
        res.json({ message: 'Documento cargado' });
    } catch (err) { 
        console.error("Error al subir:", err.message);
        res.status(500).json({ error: err.message }); 
    }
});

// --- DOCUMENTOS POR USUARIO ---
app.get('/api/admin/documentos/:id', verificarToken, async (req, res) => {
    const result = await pool.query('SELECT * FROM documentos WHERE usuario_id = $1', [req.params.id]);
    res.json(result.rows);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Servidor listo en puerto ${PORT}`));