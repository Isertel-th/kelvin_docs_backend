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

// NUEVO: Almacenamiento dinámico exclusivo para Docs Empresa que usa el campo 'tipo_documento'
const storageEmpresa = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: async (req, file) => {
        // Sanitizar el tipo de documento para transformarlo en un nombre de archivo seguro (ej: "reglamento_interno")
        let nombreLimpio = req.body.tipo_documento ? req.body.tipo_documento : 'documento';
        nombreLimpio = nombreLimpio
            .toLowerCase()
            .normalize("NFD")
            .replace(/[\u0300-\u036f]/g, "") // Remueve tildes
            .replace(/\s+/g, '_')            // Cambia espacios por guión bajo
            .replace(/[^a-z0-9_]/g, '');     // Elimina caracteres especiales

        return {
            folder: 'isertel_empresa',
            format: 'pdf', // Forzamos formato PDF en Cloudinary
            public_id: `${nombreLimpio}` // Se guardará como 'reglamento_interno'
        };
    }
});

// Middleware Multer con filtro estricto de tipo de archivo (Solo PDF)
const uploadEmpresa = multer({ 
    storage: storageEmpresa,
    fileFilter: (req, file, cb) => {
        if (file.mimetype === 'application/pdf') {
            cb(null, true);
        } else {
            cb(new Error('Solo se permiten archivos en formato PDF'), false);
        }
    }
});


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

const permisoAdminDoc = (req, res, next) => {
    // Añadimos 'kelvin' a la lista de roles autorizados
    if (req.user.rol === 'admin' || req.user.rol === 'doc' || req.user.rol === 'kelvin') {
        next();
    } else {
        res.status(403).json({ error: 'No tienes permisos' });
    }
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



app.delete('/api/admin/documentos/:id', verificarToken, async (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ error: 'Acción restringida' });
    
    const { id } = req.params;
    try {
        // Eliminamos puntualmente de las tablas de administración general
        const resActivo = await pool.query("DELETE FROM documentos WHERE id = $1", [id]);
        const resPasivo = await pool.query("DELETE FROM documentos_pasivos WHERE id = $1", [id]);
        
        if (resActivo.rowCount > 0 || resPasivo.rowCount > 0) {
            return res.json({ message: 'Ok' });
        } else {
            return res.status(404).json({ error: 'Documento administrativo no encontrado' });
        }
    } catch (err) {
        res.status(500).json({ error: "Error en la base de datos al eliminar: " + err.message });
    }
});




app.get('/api/admin/empleados', verificarToken, permisoAdminDoc, async (req, res) => {
    try {
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
    
    const { cedula, nombre_completo, fecha_ingreso, correo, celular, direccion, username } = req.body;
    const foto_url = req.file ? req.file.path : null;

    if(!cedula || cedula.length !== 10) return res.status(400).json({ error: 'Cédula debe tener 10 dígitos' });
    if(!correo || !esCorreoValido(correo)) return res.status(400).json({ error: 'Correo inválido o dominio no permitido' });
    if(!nombre_completo || !foto_url) return res.status(400).json({ error: 'Faltan campos obligatorios o la foto' });

    // Si no envías un username personalizado desde el frontend, usamos la cédula por defecto de forma segura
    const usuarioLogin = username || cedula;

    try {
        await pool.query(
            'INSERT INTO nomina (username, cedula, nombre_completo, rol, fecha_ingreso, correo, celular, direccion, foto_url) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)',
            [usuarioLogin, cedula, nombre_completo, 'user', fecha_ingreso || null, correo, celular, direccion, foto_url]
        );
        res.json({ message: 'Ok' });
    } catch (err) { 
        console.error(err);
        res.status(500).json({ error: "Error al guardar en Nómina. Verifique si la cédula o correo ya existen." }); 
    }
});


// ENDPOINT: Modificar datos de un empleado de nómina activa
// ENDPOINT ACTUALIZADO: Modificar datos de un colaborador (Nómina o Pasivos)
app.put('/api/admin/modificar-usuario/:tabla/:id', verificarToken, upload.single('foto'), async (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ error: 'Solo el administrador puede modificar datos' });
    
    const { tabla, id } = req.params;
    const { cedula, nombre_completo, fecha_ingreso, correo, celular, direccion } = req.body;
    const nueva_foto_url = req.file ? req.file.path : null;

    // Validar que solo se apunte a tablas permitidas por seguridad
    if (tabla !== 'nomina' && tabla !== 'pasivos') {
        return res.status(400).json({ error: 'Tabla de destino no válida' });
    }

    if (!cedula || cedula.length !== 10) return res.status(400).json({ error: 'La cédula debe tener exactamente 10 dígitos' });
    if (!correo || !esCorreoValido(correo)) return res.status(400).json({ error: 'Correo inválido o dominio institucional no permitido' });
    if (!nombre_completo) return res.status(400).json({ error: 'El nombre completo es obligatorio' });

    try {
        // 1. Validar si el registro existe en la tabla seleccionada
        const existeUser = await pool.query(`SELECT foto_url FROM ${tabla} WHERE id = $1`, [id]);
        if (existeUser.rows.length === 0) {
            return res.status(404).json({ error: `El colaborador no existe en la tabla de ${tabla}.` });
        }

        // 2. Conservar foto actual si no se sube una nueva
        const fotoFinal = nueva_foto_url ? nueva_foto_url : existeUser.rows[0].foto_url;

        // 3. Ejecutar la actualización dinámica en la tabla correspondiente
        await pool.query(
            `UPDATE ${tabla} 
             SET username = $1, cedula = $2, nombre_completo = $3, fecha_ingreso = $4, correo = $5, celular = $6, direccion = $7, foto_url = $8 
             WHERE id = $9`,
            [cedula, cedula, nombre_completo, fecha_ingreso || null, correo, celular, direccion, fotoFinal, id]
        );

        res.json({ message: 'Ok' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Error al actualizar los datos. Verifique que la cédula o correo no estén duplicados." });
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

// 3. Mover los documentos generales a la tabla de pasivos resguardando la metadata real
await client.query(
    `INSERT INTO documentos_pasivos (usuario_id, tipo_documento, subtipo_documento, url_cloudinary, nombre_user, nombre_archivo, fecha_documento, periodo) 
     SELECT $1, tipo_documento, subtipo_documento, url_cloudinary, nombre_user, nombre_archivo, fecha_documento, periodo FROM documentos WHERE usuario_id = $2`,
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
    const { tipo_documento, subtipo_documento, usuario_id, nombre_user, es_pasivo, nombre_archivo, fecha_documento, periodo } = req.body;

    let tabla;
    
    // Nueva lógica de clasificación
    if (tipo_documento === "Certificado de Competencia") {
        tabla = 'certifi_competencia';
    } else if (tipo_documento === "Acta de EPP's") {
        tabla = 'acta_epps';
    } else if (tipo_documento === "Certificados Médicos") {
        tabla = 'docus_medicos';
    } else if (tipo_documento === "Certificados de Aptitud") {
        tabla = 'certificados_aptitud';
    } else {
        // Para cualquier otro documento general
        tabla = es_pasivo === 'true' ? 'documentos_pasivos' : 'documentos';
    }

    try {
        await pool.query(
            `INSERT INTO ${tabla} (usuario_id, tipo_documento, subtipo_documento, url_cloudinary, nombre_user, nombre_archivo, fecha_documento, periodo) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, 
            [usuario_id, tipo_documento, subtipo_documento || 'General / Único', req.file.path, nombre_user, nombre_archivo, fecha_documento || null, periodo || null]
        );
        res.json({ message: 'Ok' });
    } catch (err) { 
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/admin/documentos/:id', verificarToken, permisoAdminDoc, async (req, res) => {
    const esPasivo = req.query.pasivo === 'true';
    const tablaPrincipal = esPasivo ? 'documentos_pasivos' : 'documentos';
    try {
        const query = `SELECT id, usuario_id, tipo_documento, subtipo_documento, url_cloudinary, nombre_user, nombre_archivo, fecha_documento, periodo, created_at 
                       FROM ${tablaPrincipal} WHERE usuario_id = $1 ORDER BY fecha_documento DESC, created_at DESC`;
        const result = await pool.query(query, [req.params.id]);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
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

// --- ENLACES DE APTITUD MÉDICA ---
app.get('/api/doctor/aptitud/:id', verificarToken, permisoAdminDoc, async (req, res) => {
    try {
        const query = `
            SELECT id, usuario_id, tipo_documento, subtipo_documento, url_cloudinary, nombre_user, nombre_archivo, fecha_documento, periodo, created_at FROM docus_medicos WHERE usuario_id = $1
            UNION ALL
            SELECT id, usuario_id, tipo_documento, subtipo_documento, url_cloudinary, nombre_user, nombre_archivo, fecha_documento, periodo, created_at FROM certificados_aptitud WHERE usuario_id = $1
            ORDER BY fecha_documento DESC, created_at DESC`;
        const result = await pool.query(query, [req.params.id]);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Asegúrate de que este endpoint tenga la lógica completa de clasificación
app.post('/api/doctor/subir-aptitud', verificarToken, permisoAdminDoc, upload.single('archivo'), async (req, res) => {
    const { tipo_documento, subtipo_documento, usuario_id, nombre_user, nombre_archivo, fecha_documento, periodo } = req.body;
    
    // AQUÍ ESTÁ LA CLAVE: Definir la tabla según el tipo
    let tabla = 'documentos'; // Por defecto
    if (tipo_documento === 'Certificados Médicos') {
        tabla = 'docus_medicos';
    } else if (tipo_documento === 'Certificados de Aptitud') {
        tabla = 'certificados_aptitud';
    }

    try {
        await pool.query(
            `INSERT INTO ${tabla} (usuario_id, tipo_documento, subtipo_documento, url_cloudinary, nombre_user, nombre_archivo, fecha_documento, periodo) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, 
            [usuario_id, tipo_documento, subtipo_documento, req.file.path, nombre_user, nombre_archivo, fecha_documento, periodo]
        );
        res.json({ message: 'Ok' });
    } catch (err) { 
        res.status(500).json({ error: err.message });
    }
});
// CORREGIDO: Endpoint del Médico (Ya no borra masivamente por ID duplicado)
app.delete('/api/doctor/aptitud/:id', verificarToken, permisoAdminDoc, async (req, res) => {
    if (req.user.rol !== 'doc' && req.user.rol !== 'admin') {
        return res.status(403).json({ error: 'No tienes permisos para esta acción' });
    }

    const { id } = req.params;
    try {
        const resMedico = await pool.query("DELETE FROM docus_medicos WHERE id = $1", [id]);
        const resAptitud = await pool.query("DELETE FROM certificados_aptitud WHERE id = $1", [id]);
        
        if (resMedico.rowCount > 0 || resAptitud.rowCount > 0) {
            return res.json({ message: 'Ok' });
        } else {
            return res.status(404).json({ error: 'Documento médico no encontrado en los registros de salud' });
        }
    } catch (err) {
        res.status(500).json({ error: "Error en la base de datos al eliminar: " + err.message });
    }
});

// --- ENLACES GESTOR KELVIN ---
app.post('/api/kelvin/subir-certificados', verificarToken, permisoAdminDoc, upload.single('archivo'), async (req, res) => {
    const { tipo_documento, subtipo_documento, usuario_id, nombre_archivo, fecha_documento, periodo } = req.body;
    let tabla = '';

    // Coincidencia exacta con el admin
    if (tipo_documento === "Certificado de Competencia") {
        tabla = 'certifi_competencia';
    } else if (tipo_documento === "Acta de EPP's") {
        tabla = 'acta_epps';
    } else {
        return res.status(400).json({ error: "Tipo de documento no permitido para Kelvin" });
    }

    try {
        await pool.query(
            `INSERT INTO ${tabla} (usuario_id, tipo_documento, subtipo_documento, url_cloudinary, nombre_user, nombre_archivo, fecha_documento, periodo) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, 
            [usuario_id, tipo_documento, subtipo_documento || 'General / Único', req.file.path, 'Gestor Kelvin', nombre_archivo, fecha_documento || null, periodo || null]
        );
        res.json({ message: 'Ok' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/kelvin/documentos/:id', verificarToken, permisoAdminDoc, async (req, res) => {
    try {
        const query = `
            SELECT id, usuario_id, tipo_documento, subtipo_documento, url_cloudinary, nombre_user, nombre_archivo, fecha_documento, periodo, created_at FROM certifi_competencia WHERE usuario_id = $1
            UNION ALL
            SELECT id, usuario_id, tipo_documento, subtipo_documento, url_cloudinary, nombre_user, nombre_archivo, fecha_documento, periodo, created_at FROM acta_epps WHERE usuario_id = $1
            ORDER BY fecha_documento DESC, created_at DESC
        `;
        const result = await pool.query(query, [req.params.id]);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});



// NUEVO: Endpoint para que el Gestor Kelvin pueda eliminar sus documentos técnicos
app.delete('/api/kelvin/documentos/:id', verificarToken, permisoAdminDoc, async (req, res) => {
    // Validamos que sea Kelvin o el administrador general
    if (req.user.rol !== 'kelvin' && req.user.rol !== 'admin') {
        return res.status(403).json({ error: 'No tienes permisos para esta acción' });
    }

    const { id } = req.params;
    try {
        // Borramos estrictamente de las tablas técnicas asignadas a Kelvin
        const resCompetencia = await pool.query("DELETE FROM certifi_competencia WHERE id = $1", [id]);
        const resEpp = await pool.query("DELETE FROM acta_epps WHERE id = $1", [id]);
        
        if (resCompetencia.rowCount > 0 || resEpp.rowCount > 0) {
            return res.json({ message: 'Ok' });
        } else {
            return res.status(404).json({ error: 'Documento técnico no encontrado' });
        }
    } catch (err) {
        res.status(500).json({ error: "Error en la base de datos al eliminar: " + err.message });
    }
});

// 1. SUBIR DOCUMENTO (Solo Admin)
app.post('/api/empresa/documentos', verificarToken, (req, res, next) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ error: 'Acción restringida. Solo el administrador puede subir archivos corporativos.' });
    next();
}, uploadEmpresa.single('archivo'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'Debe adjuntar obligatoriamente un archivo PDF.' });
        }

        const { tipo_documento } = req.body;
        if (!tipo_documento) return res.status(400).json({ error: 'El tipo de documento es obligatorio.' });

        // Sanitizar para guardar el string de archivo exacto en BD: reglamento_interno.pdf
        const nombreFinalArchivo = tipo_documento
            .toLowerCase()
            .normalize("NFD")
            .replace(/[\u0300-\u036f]/g, "")
            .replace(/\s+/g, '_')
            .replace(/[^a-z0-9_]/g, '') + '.pdf';

        const query = `
            INSERT INTO documentos_empresa (tipo_documento, nombre_archivo, url_cloudinary)
            VALUES ($1, $2, $3) RETURNING *
        `;
        const result = await pool.query(query, [tipo_documento, nombreFinalArchivo, req.file.path]);
        
        res.json({ message: 'Ok', documento: result.rows[0] });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 2. LISTAR DOCUMENTOS (Todos los roles autenticados pueden ver)
app.get('/api/empresa/documentos', verificarToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM documentos_empresa ORDER BY id DESC');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 3. ELIMINAR DOCUMENTO (Solo Admin)
app.delete('/api/empresa/documentos/:id', verificarToken, async (req, res) => {
    if (req.user.rol !== 'admin') {
        return res.status(403).json({ error: 'Acción restringida. Solo el administrador puede eliminar archivos corporativos.' });
    }
    
    const { id } = req.params;
    try {
        const result = await pool.query('DELETE FROM documentos_empresa WHERE id = $1', [id]);
        if (result.rowCount > 0) {
            res.json({ message: 'Ok' });
        } else {
            res.status(404).json({ error: 'Documento no encontrado.' });
        }
    } catch (err) {
        res.status(500).json({ error: 'Error al eliminar el documento: ' + err.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Servidor Isertel corriendo en puerto ${PORT}`));