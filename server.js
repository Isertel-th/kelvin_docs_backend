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

const upload = multer({ storage });

// --- FUNCIONES DE VALIDACIÓN ---
const esCorreoValido = (email) => {
    const dominiosPermitidos = ['gmail.com', 'gmail.es', 'outlook.com', 'outlook.es', 'hotmail.com', 'hotmail.es', 'isertel.com.ec']; 
    const regexBase = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!regexBase.test(email)) return false;
    const dominio = email.split('@')[1].toLowerCase();
    return dominiosPermitidos.includes(dominio);
};

const verificarToken = (req, res, next) => {
    const token = req.header('Authorization');
    if (!token) return res.status(401).json({ error: 'Acceso denegado' });
    try {
        const verificado = jwt.verify(token.replace('Bearer ', ''), process.env.JWT_SECRET);
        req.user = verificado;
        next();
    } catch (err) { res.status(400).json({ error: 'Token no válido' }); }
};

// Úsalo para lo que SOLO ven el Admin y el Médico (ej. Certificados médicos)
const permisoAdminDoc = (req, res, next) => {
    if (req.user && (req.user.rol === 'admin' || req.user.rol === 'doc')) next();
    else res.status(403).json({ error: 'No tienes permisos: Solo Admin y Doc' });
};

const permisoGeneralPersonal = (req, res, next) => {
    const rolesAutorizados = ['admin', 'doc', 'kelvin'];
    if (req.user && rolesAutorizados.includes(req.user.rol)) next();
    else res.status(403).json({ error: 'Acceso denegado: Se requiere rol Admin, Doc o Kelvin' });
};


// --- RUTAS ---

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        // 1. Buscar en la tabla de Administradores
        let result = await pool.query('SELECT * FROM usuarios WHERE username = $1', [username]);
        
        // 2. Si no es admin, buscar en la tabla de Nomina (Empleados)
        if (result.rows.length === 0) {
            result = await pool.query('SELECT * FROM nomina WHERE username = $1', [username]);
        }

        if (result.rows.length === 0 || password !== result.rows[0].cedula) {
            return res.status(400).json({ error: 'Credenciales incorrectas' });
        }

        const user = result.rows[0];
        const token = jwt.sign({ id: user.id, rol: user.rol }, process.env.JWT_SECRET, { expiresIn: '8h' });
        res.json({ token, rol: user.rol, nombre: user.nombre_completo });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/admin/empleados', verificarToken, permisoAdminDoc, async (req, res) => {
    try {
        // Ahora consultamos la tabla 'nomina'
        const result = await pool.query("SELECT * FROM nomina ORDER BY nombre_completo ASC");
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

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

    // Se mantienen tus validaciones originales
    if(!cedula || cedula.length !== 10) return res.status(400).json({ error: 'Cédula debe tener 10 dígitos' });
    if(!correo || !esCorreoValido(correo)) return res.status(400).json({ error: 'Correo inválido o dominio no permitido' });
    if(!nombre_completo || !foto_url) return res.status(400).json({ error: 'Faltan campos obligatorios o la foto' });

    try {
        await pool.query(
            'INSERT INTO nomina (username, cedula, nombre_completo, rol, fecha_ingreso, correo, celular, direccion, foto_url) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)',
            [cedula, cedula, nombre_completo, 'user', fecha_ingreso || null, correo, celular, direccion, foto_url]
        );
        res.json({ message: 'Ok' });
    } catch (err) { 
        res.status(500).json({ error: "Error al guardar en Nomina. Verifique duplicados." }); 
    }
});

app.post('/api/admin/mover-a-pasivo/:id', verificarToken, async (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ error: 'Acción restringida' });
    
    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // 1. Obtener los datos actuales desde la tabla 'nomina'
        const userRes = await client.query('SELECT * FROM nomina WHERE id = $1', [req.params.id]);
        if (userRes.rows.length === 0) throw new Error("Empleado no encontrado en nómina");
        const u = userRes.rows[0];
        
        // 2. Insertar en la tabla 'pasivos' y obtener el nuevo ID generado
        const insertPasivo = await client.query(
            `INSERT INTO pasivos (username, cedula, nombre_completo, rol, fecha_ingreso, correo, celular, direccion, foto_url) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
            [u.username, u.cedula, u.nombre_completo, u.rol, u.fecha_ingreso, u.correo, u.celular, u.direccion, u.foto_url]
        );
        const nuevoId = insertPasivo.rows[0].id;

        // 3. Mover los documentos generales a la tabla de pasivos
        await client.query(
            `INSERT INTO documentos_pasivos (usuario_id, tipo_documento, url_cloudinary, nombre_user) 
             SELECT $1, tipo_documento, url_cloudinary, nombre_user FROM documentos WHERE usuario_id = $2`,
            [nuevoId, u.id]
        );

        // 4. Actualizar carpetas médicas y de aptitud para que apunten al nuevo ID del pasivo
        await client.query('UPDATE docus_medicos SET usuario_id = $1 WHERE usuario_id = $2', [nuevoId, u.id]);
        await client.query('UPDATE certificados_aptitud SET usuario_id = $1 WHERE usuario_id = $2', [nuevoId, u.id]);

        // 5. Eliminar los registros de las tablas de activos
        await client.query('DELETE FROM documentos WHERE usuario_id = $1', [u.id]);
        await client.query('DELETE FROM nomina WHERE id = $1', [u.id]);

        await client.query('COMMIT');
        res.json({ message: 'Ok' });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error(err);
        res.status(500).json({ error: err.message });
    } finally {
        client.release();
    }
});

app.post('/api/admin/subir-a-usuario', verificarToken, permisoAdminDoc, upload.single('archivo'), async (req, res) => {
    const { tipo_documento, usuario_id, nombre_user, es_pasivo } = req.body;
    
    // Lógica para determinar la tabla de destino
    let tabla;
    if (tipo_documento.includes("Certificado médico") || tipo_documento.includes("Reposo médico")) {
        tabla = 'docus_medicos';
    } else {
        tabla = es_pasivo === 'true' ? 'documentos_pasivos' : 'documentos';
    }

    try {
        await pool.query(
            `INSERT INTO ${tabla} (usuario_id, tipo_documento, url_cloudinary, nombre_user) VALUES ($1, $2, $3, $4)`, 
            [usuario_id, tipo_documento, req.file.path, nombre_user]
        );
        res.json({ message: 'Ok' });
    } catch (err) { 
        res.status(500).json({ error: err.message }); 
    }
});

// En server.js busca esta ruta y reemplázala:
// server.js - Asegúrate de que la consulta sea robusta
app.get('/api/admin/documentos/:id', verificarToken, permisoAdminDoc, async (req, res) => {
    const esPasivo = req.query.pasivo === 'true';
    const tablaPrincipal = esPasivo ? 'documentos_pasivos' : 'documentos';
    
    try {
        // Seleccionamos columnas explícitamente para asegurar que el UNION funcione siempre
        const query = `
            SELECT id, usuario_id, tipo_documento, url_cloudinary, nombre_user, created_at FROM ${tablaPrincipal} WHERE usuario_id = $1
            UNION ALL
            SELECT id, usuario_id, tipo_documento, url_cloudinary, nombre_user, created_at FROM docus_medicos WHERE usuario_id = $1
            ORDER BY created_at DESC
        `;
        const result = await pool.query(query, [req.params.id]);
        res.json(result.rows);
    } catch (err) { 
        console.error("Error al obtener documentos:", err.message);
        res.status(500).json({ error: err.message }); 
    }
});

app.delete('/api/admin/documentos/:id', verificarToken, async (req, res) => {
    try {
        // Intenta borrar en las tres tablas
        await pool.query(`DELETE FROM documentos WHERE id = $1`, [req.params.id]);
        await pool.query(`DELETE FROM documentos_pasivos WHERE id = $1`, [req.params.id]);
        await pool.query(`DELETE FROM docus_medicos WHERE id = $1`, [req.params.id]);
        
        res.json({ message: 'Ok' });
    } catch (err) { 
        res.status(500).json({ error: err.message }); 
    }
});

app.get('/api/doctor/certificados-globales', verificarToken, permisoAdminDoc, async (req, res) => {
    try {
        const query = `
            SELECT d.id, d.tipo_documento, d.url_cloudinary, d.created_at, n.nombre_completo as empleado_nombre, 'Activo' as estado_empleado
            FROM documentos d
            JOIN nomina n ON d.usuario_id = n.id
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
    try {
        await pool.query('DELETE FROM documentos_empresa WHERE id = $1', [req.params.id]);
        res.json({ message: 'Ok' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});


// --- NUEVAS RUTAS PARA APTITUD MÉDICA CON LOGS ---

// server.js - Ruta corregida con UNION balanceado
app.get('/api/doctor/aptitud/:id', verificarToken, permisoAdminDoc, async (req, res) => {
    const esPasivo = req.query.pasivo === 'true';
    const tablaPrincipal = esPasivo ? 'documentos_pasivos' : 'documentos';
    
    try {
        const query = `
            SELECT id, usuario_id, tipo_documento, url_cloudinary, nombre_user, created_at FROM ${tablaPrincipal} WHERE usuario_id = $1
            UNION ALL
            SELECT id, usuario_id, tipo_documento, url_cloudinary, nombre_user, created_at FROM docus_medicos WHERE usuario_id = $1
            UNION ALL
            SELECT id, usuario_id, tipo_documento, url_cloudinary, nombre_user, created_at FROM certificados_aptitud WHERE usuario_id = $1
            ORDER BY created_at DESC
        `;
        const result = await pool.query(query, [req.params.id]);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
// server.js - Localiza esta ruta y reemplázala

app.post('/api/doctor/subir-aptitud', verificarToken, permisoAdminDoc, upload.single('archivo'), async (req, res) => {
    const { tipo_documento, usuario_id, es_pasivo } = req.body;
    
    let tabla;
    
    // 1. Si es médico o reposo, va a docus_medicos
    if (tipo_documento.includes("Certificado médico") || tipo_documento.includes("Reposo médico")) {
        tabla = 'docus_medicos';
    } 
    // 2. Si es Aptitud o Ficha, va a la NUEVA tabla certificados_aptitud
    else if (tipo_documento.includes("Aptitud Médica") || tipo_documento.includes("Ficha Médica")) {
        tabla = 'certificados_aptitud';
    }
    // 3. Respaldo para otros casos (documentos generales)
    else {
        tabla = es_pasivo === 'true' ? 'documentos_pasivos' : 'documentos';
    }
    
    try {
        await pool.query(
            `INSERT INTO ${tabla} (usuario_id, tipo_documento, url_cloudinary, nombre_user) VALUES ($1, $2, $3, $4)`, 
            [usuario_id, tipo_documento, req.file.path, req.body.nombre_user || 'Servicio Médico']
        );
        res.json({ message: 'Ok' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Ruta para eliminar aptitud (usando la tabla correcta según lógica de doctor)
app.delete('/api/doctor/aptitud/:id', verificarToken, permisoAdminDoc, async (req, res) => {
    try {
        await pool.query("DELETE FROM documentos WHERE id = $1", [req.params.id]);
        await pool.query("DELETE FROM documentos_pasivos WHERE id = $1", [req.params.id]);
        await pool.query("DELETE FROM docus_medicos WHERE id = $1", [req.params.id]);
        await pool.query("DELETE FROM certificados_aptitud WHERE id = $1", [req.params.id]); // <--- Nueva línea
        res.json({ message: 'Ok' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});


// ... (Tus imports y config de Cloudinary se mantienen igual)

// --- RUTAS CON LOGS ---

// 2. Nueva ruta de subida adaptada para Kelvin (CON LOGS)
app.post('/api/kelvin/subir-certificados', verificarToken, permisoGeneralPersonal, upload.single('archivo'), async (req, res) => {
    const { tipo_documento, usuario_id, es_pasivo } = req.body;
    
    console.log("--- INTENTO DE SUBIDA (KELVIN) ---");
    console.log("Tipo Doc:", tipo_documento);
    console.log("ID Usuario:", usuario_id);
    console.log("Es Pasivo:", es_pasivo);

    let tabla;
    // Normalizamos a minúsculas para evitar errores de escritura
    const tipoLower = tipo_documento.toLowerCase();

    if (tipoLower.includes("competencia")) {
        tabla = 'certifi_competencia';
    } else if (tipoLower.includes("acta de epp") || tipoLower.includes("epp")) {
        tabla = 'acta_epps';
    } else {
        tabla = es_pasivo === 'true' ? 'documentos_pasivos' : 'documentos';
    }

    console.log("Tabla seleccionada para guardar:", tabla);

    try {
        if (!req.file) {
            console.error("❌ No se recibió archivo de Cloudinary");
            return res.status(400).json({ error: "No hay archivo" });
        }

        await pool.query(
            `INSERT INTO ${tabla} (usuario_id, tipo_documento, url_cloudinary, nombre_user) VALUES ($1, $2, $3, $4)`, 
            [usuario_id, tipo_documento, req.file.path, 'Gestión Kelvin']
        );
        console.log("✅ Guardado exitoso en DB");
        res.json({ message: 'Ok' });
    } catch (err) { 
        console.error("❌ ERROR EN SUBIDA:", err.message);
        res.status(500).json({ error: err.message }); 
    }
});

// 3. Nueva ruta de consulta adaptada para Kelvin (CON LOGS)
app.get('/api/kelvin/documentos/:id', verificarToken, permisoGeneralPersonal, async (req, res) => {
    const esPasivo = req.query.pasivo === 'true';
    const { id } = req.params;
    
    console.log(`--- CONSULTA DE DOCUMENTOS (KELVIN) ---`);
    console.log(`ID buscado: ${id}, Es Pasivo: ${esPasivo}`);

    const tablaPrincipal = esPasivo ? 'documentos_pasivos' : 'documentos';
    
    try {
        const query = `
            SELECT id, usuario_id, tipo_documento, url_cloudinary, nombre_user, created_at FROM ${tablaPrincipal} WHERE usuario_id = $1
            UNION ALL
            SELECT id, usuario_id, tipo_documento, url_cloudinary, nombre_user, created_at FROM certifi_competencia WHERE usuario_id = $1
            UNION ALL
            SELECT id, usuario_id, tipo_documento, url_cloudinary, nombre_user, created_at FROM acta_epps WHERE usuario_id = $1
            ORDER BY created_at DESC
        `;
        
        const result = await pool.query(query, [id]);
        console.log(`✅ Documentos encontrados: ${result.rows.length}`);
        res.json(result.rows);
    } catch (err) { 
        console.error("❌ ERROR EN CONSULTA:", err.message);
        res.status(500).json({ error: err.message }); 
    }
});

// Ruta de Empleados Activos
// Estas dos rutas reemplazan a todas las versiones repetidas que tenías de empleados/pasivos
app.get('/api/admin/empleados', verificarToken, permisoGeneralPersonal, async (req, res) => {
    try {
        const result = await pool.query("SELECT * FROM nomina ORDER BY nombre_completo ASC");
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Ruta de Empleados Pasivos
app.get('/api/admin/pasivos', verificarToken, permisoGeneralPersonal, async (req, res) => {
    try {
        const result = await pool.query("SELECT * FROM pasivos ORDER BY nombre_completo ASC");
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Servidor Isertel corriendo en puerto ${PORT}`));