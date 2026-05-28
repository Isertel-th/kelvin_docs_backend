const express = require('express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const msal = require('@azure/msal-node');
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

// Configuración de Microsoft MSAL para OneDrive
const msalConfig = {
    auth: {
        clientId: process.env.MICROSOFT_CLIENT_ID,
        authority: `https://login.microsoftonline.com/${process.env.MICROSOFT_TENANT_ID}`,
        clientSecret: process.env.MICROSOFT_CLIENT_SECRET,
    }
};

const cca = new msal.ConfidentialClientApplication(msalConfig);

// Función auxiliar para subir archivos directos a OneDrive usando Microsoft Graph
async function subirAOneDrive(buffer, originalName, subFolder = '') {
    const tokenRequest = {
        scopes: ['https://graph.microsoft.com/.default']
    };
    
    // 1. Obtener Token de Acceso Dinámico
    const response = await cca.acquireTokenByClientCredential(tokenRequest);
    const token = response.accessToken;

    // 2. Limpiar el nombre original de caracteres conflictivos (ej: acentos, comillas de EPP's)
    const cleanOriginalName = originalName
        .normalize("NFD")
        .replace(/[\u0300-\u036f]/g, "") // Quita acentos
        .replace(/[^a-zA-Z0-9._-]/g, "_"); // Reemplaza espacios y caracteres raros por '_'

    const fileName = `${Date.now()}_${cleanOriginalName}`;
    
    // 3. Construir los segmentos de la ruta de manera segura
    let segmentos = ['Documentos Isertel Sistema'];
    if (subFolder) {
        segmentos.push(subFolder.normalize("NFD").replace(/[\u0300-\u036f]/g, ""));
    }
    segmentos.push(fileName);

    // 4. Codificar CADA segmento por separado y unirlos
    const encodedPath = segmentos.map(segment => encodeURIComponent(segment.trim())).join('/');
    
    // 5. Construir la URL exacta para la API de Graph
    const url = `https://graph.microsoft.com/v1.0/users/talentohumano@isertel.net/drive/root:/${encodedPath}:/content`;

    const res = await fetch(url, {
        method: 'PUT',
        headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/octet-stream'
        },
        body: buffer
    });

    if (!res.ok) {
        const errText = await res.text();
        throw new Error(`Error al subir a OneDrive: ${errText}`);
    }

    const driveItem = await res.json();
    return driveItem["@microsoft.graph.downloadUrl"] || driveItem.webUrl; 
}

// Configuración de Multer para almacenamiento en Memoria (Buffer temporal)
const storage = multer.memoryStorage();
const upload = multer({ storage });

// --- FUNCIONES DE VALIDACIÓN ---
const esCorreoValido = (email) => {
    const dominiosPermitidos = ['gmail.com', 'gmail.es', 'outlook.com', 'outlook.es', 'hotmail.com', 'hotmail.es', 'isertel.com.ec', 'isertel.net']; 
    const regexBase = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!regexBase.test(email)) return false;
    const dominio = email.split('@')[1].toLowerCase();
    return dominiosPermitidos.includes(dominio);
};

// 1. Este se queda EXACTAMENTE IGUAL como lo tienes:
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

// 2. REEMPLAZAS tu antiguo 'permisoAdminDoc' por este dinámico:
const verificarPermisoDocumento = (permisoRequerido) => {
    return (req, res, next) => {
        // Talento Humano sigue teniendo acceso universal automático a todo
        if (req.user.rol === 'Talento Humano') {
            return next(); 
        }
        
        // Cualquier otro rol (Gerencia, Operaciones, Finanzas, etc.) 
        // se valida dinámicamente buscando si tiene el permiso en su lista
        if (req.user.permisos && req.user.permisos.includes(permisoRequerido)) {
            return next();
        }
        
        return res.status(403).json({ error: `No posees permisos de acceso para la categoría: ${permisoRequerido}` });
    };
};

// --- RUTAS ---

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body; 
    try {
        // 1. Buscamos primero en la tabla de administradores/departamentos
        let result = await pool.query('SELECT * FROM usuarios WHERE correo = $1', [username.trim().toLowerCase()]);
        let user = result.rows[0];
        let esPasswordCorrecto = false;
        let permisosUsuario = [];

        if (user) {
            esPasswordCorrecto = (password === user.contrasenia);
            
            // Si es Talento Humano, su acceso es universal por defecto
            if (user.rol === 'Talento Humano') {
                permisosUsuario = [
                    'Contratación', 'vacaciones', 'certificados de competencia', 
                    'actas de epp\'s', 'certificados medicos', 'certificados de aptitud', 
                    'certificados', 'memorandum', 'certificados y cargas familiares', 'desvinculacion'
                ];
            } else {
                // Si la columna en la BD es un array de Postgres, llega como un Array de JS. 
                // Nos aseguramos de que si llega null o no es un array, se inicialice vacío de forma segura.
                permisosUsuario = Array.isArray(user.permisos) ? user.permisos : [];
            }
        } else {
            // 2. Si no es administrador, buscamos en la tabla nomina por su identificador (correo o cédula)
            // NOTA: Ajusta 'correo' o 'cedula' según el nombre exacto de tu columna en la tabla nomina
            result = await pool.query('SELECT * FROM nomina WHERE correo = $1 OR cedula = $1', [username.trim()]);
            user = result.rows[0];
            if (user) {
                esPasswordCorrecto = (password === user.cedula);
                permisosUsuario = []; // Los empleados comunes de nómina no administran carpetas documentales
            }
        }

        // Si no existe el usuario en ninguna tabla o la contraseña está mal
        if (!user || !esPasswordCorrecto) {
            return res.status(400).json({ error: 'Credenciales incorrectas' });
        }

        // Guardamos el ID, Rol y los Permisos Dinámicos dentro del Token para el middleware y el frontend
        const token = jwt.sign(
            { 
                id: user.id, 
                rol: user.rol || 'Empleado', // Si no tiene rol en nómina, le asignamos uno por defecto
                permisos: permisosUsuario 
            }, 
            process.env.JWT_SECRET, 
            { expiresIn: '8h' }
        );
        
        // Respondemos al frontend con todo lo necesario
        res.json({ 
            token, 
            rol: user.rol || 'Empleado', 
            nombre: user.nombre_completo, 
            permisos: permisosUsuario 
        });

    } catch (err) { 
        console.error("❌ Error en el endpoint de login:", err);
        res.status(500).json({ error: 'Error interno del servidor: ' + err.message }); 
    }
});

// RESPALDO ASEGURADO: Solo elimina el registro de PostgreSQL
app.delete('/api/admin/documentos/:id', verificarToken, async (req, res) => {
    // Reemplazado 'admin' por 'Talento Humano'
    if (req.user.rol !== 'Talento Humano') return res.status(403).json({ error: 'Acción restringida' });
    
    const { id } = req.params;
    try {
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
    // Reemplazado 'admin' por 'Talento Humano'
    if (req.user.rol !== 'Talento Humano') return res.status(403).json({ error: 'Solo el personal de Talento Humano crea usuarios' });
    
    const { cedula, nombre_completo, fecha_ingreso, correo, celular, direccion, username } = req.body;

    if(!cedula || cedula.length !== 10) return res.status(400).json({ error: 'Cédula debe tener 10 dígitos' });
    if(!correo || !esCorreoValido(correo)) return res.status(400).json({ error: 'Correo inválido o dominio no permitido' });
    if(!nombre_completo || !req.file) return res.status(400).json({ error: 'Faltan campos obligatorios o la foto' });

    const usuarioLogin = username || cedula;

    try {
        // Subida a OneDrive dentro de la subcarpeta 'Fotos_Perfil'
        const foto_url = await subirAOneDrive(req.file.buffer, req.file.originalname, 'Fotos_Perfil');

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

app.put('/api/admin/modificar-usuario/:tabla/:id', verificarToken, upload.single('foto'), async (req, res) => {
    // Reemplazado 'admin' por 'Talento Humano'
    if (req.user.rol !== 'Talento Humano') return res.status(403).json({ error: 'Solo el personal de Talento Humano puede modificar datos' });
    
    const { tabla, id } = req.params;
    const { cedula, nombre_completo, fecha_ingreso, correo, celular, direccion } = req.body;

    if (tabla === 'pasivos') {
        return res.status(403).json({ error: 'Los registros de personal pasivo son históricos y no se pueden modificar.' });
    }

    if (tabla !== 'nomina') {
        return res.status(400).json({ error: 'Tabla de destino no válida' });
    }

    if (!cedula || cedula.length !== 10) return res.status(400).json({ error: 'La cédula debe tener exactamente 10 dígitos' });
    if (!correo || !esCorreoValido(correo)) return res.status(400).json({ error: 'Correo inválido o dominio institucional no permitido' });
    if (!nombre_completo) return res.status(400).json({ error: 'El nombre completo es obligatorio' });

    try {
        const existeUser = await pool.query(`SELECT foto_url FROM ${tabla} WHERE id = $1`, [id]);
        if (existeUser.rows.length === 0) {
            return res.status(404).json({ error: `El colaborador no existe en la tabla de ${tabla}.` });
        }

        let fotoFinal = existeUser.rows[0].foto_url;
        if (req.file) {
            fotoFinal = await subirAOneDrive(req.file.buffer, req.file.originalname, 'Fotos_Perfil');
        }

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
    // Reemplazado 'admin' por 'Talento Humano'
    if (req.user.rol !== 'Talento Humano') return res.status(403).json({ error: 'Acción restringida' });
    
    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        const userRes = await client.query('SELECT * FROM nomina WHERE id = $1', [req.params.id]);
        if (userRes.rows.length === 0) throw new Error("Empleado no encontrado en nómina");
        const u = userRes.rows[0];
        
        const insertPasivo = await client.query(
            `INSERT INTO pasivos (username, cedula, nombre_completo, rol, fecha_ingreso, correo, celular, direccion, foto_url) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
            [u.username, u.cedula, u.nombre_completo, u.rol, u.fecha_ingreso, u.correo, u.celular, u.direccion, u.foto_url]
        );
        const nuevoId = insertPasivo.rows[0].id;

        // --- ACTUALIZACIÓN DE TABLAS UNIFICADAS ---
        await client.query('UPDATE acta_epps SET usuario_id = $1, estado = $2 WHERE usuario_id = $3', [nuevoId, 'Pasivo', u.id]);
        await client.query('UPDATE certifi_competencia SET usuario_id = $1, estado = $2 WHERE usuario_id = $3', [nuevoId, 'Pasivo', u.id]);
        
        await client.query(
            `INSERT INTO documentos_pasivos (usuario_id, tipo_documento, subtipo_documento, url_cloudinary, nombre_user, nombre_archivo, fecha_documento, periodo) 
             SELECT $1, tipo_documento, subtipo_documento, url_cloudinary, nombre_user, nombre_archivo, fecha_documento, periodo FROM documentos WHERE usuario_id = $2`,
            [nuevoId, u.id]
        );

        await client.query('UPDATE docus_medicos SET usuario_id = $1 WHERE usuario_id = $2', [nuevoId, u.id]);
        await client.query('UPDATE certificados_aptitud SET usuario_id = $1 WHERE usuario_id = $2', [nuevoId, u.id]);

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
    if (!req.file) return res.status(400).json({ error: 'El archivo es obligatorio.' });
    
    const { tipo_documento, subtipo_documento, usuario_id, nombre_user, es_pasivo, nombre_archivo, fecha_documento, periodo } = req.body;

    let tabla;
    if (tipo_documento === "Certificado de Competencia") {
        tabla = 'certifi_competencia';
    } else if (tipo_documento === "Acta de EPP's") {
        tabla = 'acta_epps';
    } else if (tipo_documento === "Certificados Médicos") {
        tabla = 'docus_medicos';
    } else if (tipo_documento === "Certificados de Aptitud") {
        tabla = 'certificados_aptitud';
    } else {
        tabla = es_pasivo === 'true' ? 'documentos_pasivos' : 'documentos';
    }

    const estadoUsuario = es_pasivo === 'true' ? 'Pasivo' : 'Active'; // Mapeo dinámico para la nueva columna

    try {
        const url_onedrive = await subirAOneDrive(req.file.buffer, req.file.originalname, tipo_documento);

        if (tabla === 'acta_epps' || tabla === 'certifi_competencia') {
            await pool.query(
                `INSERT INTO ${tabla} (usuario_id, tipo_documento, subtipo_documento, url_cloudinary, nombre_user, nombre_archivo, fecha_documento, periodo, estado) 
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`, 
                [usuario_id, tipo_documento, subtipo_documento || 'General / Único', url_onedrive, nombre_user, nombre_archivo, fecha_documento || null, periodo || null, estadoUsuario]
            );
        } else {
            await pool.query(
                `INSERT INTO ${tabla} (usuario_id, tipo_documento, subtipo_documento, url_cloudinary, nombre_user, nombre_archivo, fecha_documento, periodo) 
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, 
                [usuario_id, tipo_documento, subtipo_documento || 'General / Único', url_onedrive, nombre_user, nombre_archivo, fecha_documento || null, periodo || null]
            );
        }
        res.json({ message: 'Ok' });
    } catch (err) { 
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/admin/documentos/:id', verificarToken, permisoAdminDoc, async (req, res) => {
    const esPasivo = req.query.pasivo === 'true';
    const tablaPrincipal = esPasivo ? 'documentos_pasivos' : 'documentos';
    const usuarioId = req.params.id;
    
    try {
        const query = `
            SELECT id, usuario_id, tipo_documento, subtipo_documento, url_cloudinary, nombre_user, nombre_archivo, fecha_documento, periodo, created_at 
            FROM ${tablaPrincipal} WHERE usuario_id = $1
            UNION ALL
            SELECT id, usuario_id, tipo_documento, subtipo_documento, url_cloudinary, nombre_user, nombre_archivo, fecha_documento, periodo, created_at 
            FROM acta_epps WHERE usuario_id = $1
            UNION ALL
            SELECT id, usuario_id, tipo_documento, subtipo_documento, url_cloudinary, nombre_user, nombre_archivo, fecha_documento, periodo, created_at 
            FROM certifi_competencia WHERE usuario_id = $1
            ORDER BY fecha_documento DESC, created_at DESC`;
            
        const result = await pool.query(query, [usuarioId]);
        res.json(result.rows);
    } catch (err) { 
        res.status(500).json({ error: err.message }); 
    }
});


app.post('/api/subir-empresa', verificarToken, upload.single('archivo'), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'El archivo es obligatorio.' });
    const { tipo_documento } = req.body;
    try {
        const url_onedrive = await subirAOneDrive(req.file.buffer, req.file.originalname, 'Documentos_Empresa');
        await pool.query('INSERT INTO documentos_empresa (tipo_documento, url_cloudinary) VALUES ($1, $2)', 
            [tipo_documento, url_onedrive]);
        res.json({ message: 'Ok' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/admin/documentos-empresa', verificarToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM documentos_empresa ORDER BY id DESC');
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// RESPALDO ASEGURADO: Solo elimina el registro de PostgreSQL
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

app.post('/api/doctor/subir-aptitud', verificarToken, permisoAdminDoc, upload.single('archivo'), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'El archivo es obligatorio.' });
    const { tipo_documento, subtipo_documento, usuario_id, nombre_user, nombre_archivo, fecha_documento, periodo } = req.body;
    
    let tabla = 'documentos'; 
    if (tipo_documento === 'Certificados Médicos') {
        tabla = 'docus_medicos';
    } else if (tipo_documento === 'Certificados de Aptitud') {
        tabla = 'certificados_aptitud';
    }

    try {
        const url_onedrive = await subirAOneDrive(req.file.buffer, req.file.originalname, tipo_documento);
        await pool.query(
            `INSERT INTO ${tabla} (usuario_id, tipo_documento, subtipo_documento, url_cloudinary, nombre_user, nombre_archivo, fecha_documento, periodo) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, 
            [usuario_id, tipo_documento, subtipo_documento, url_onedrive, nombre_user, nombre_archivo, fecha_documento, periodo]
        );
        res.json({ message: 'Ok' });
    } catch (err) { 
        res.status(500).json({ error: err.message });
    }
});

// RESPALDO ASEGURADO: Solo elimina el registro de PostgreSQL
app.delete('/api/doctor/aptitud/:id', verificarToken, permisoAdminDoc, async (req, res) => {
    // Reemplazado 'admin' por 'Talento Humano'
    if (req.user.rol !== 'doc' && req.user.rol !== 'Talento Humano') {
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
    if (!req.file) return res.status(400).json({ error: 'El archivo es obligatorio.' });
    const { tipo_documento, subtipo_documento, usuario_id, nombre_archivo, fecha_documento, periodo, es_pasivo } = req.body;
    let tabla = '';

    if (tipo_documento === "Certificado de Competencia") {
        tabla = 'certifi_competencia';
    } else if (tipo_documento === "Acta de EPP's") {
        tabla = 'acta_epps';
    } else {
        return res.status(400).json({ error: "Tipo de documento no permitido para Kelvin" });
    }

    const estadoUsuario = es_pasivo === 'true' ? 'Pasivo' : 'Activo';

    try {
        const url_onedrive = await subirAOneDrive(req.file.buffer, req.file.originalname, tipo_documento);
        await pool.query(
            `INSERT INTO ${tabla} (usuario_id, tipo_documento, subtipo_documento, url_cloudinary, nombre_user, nombre_archivo, fecha_documento, periodo, estado) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`, 
            [usuario_id, tipo_documento, subtipo_documento || 'General / Único', url_onedrive, 'Gestor Kelvin', nombre_archivo, fecha_documento || null, periodo || null, estadoUsuario]
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

// RESPALDO ASEGURADO: Solo elimina el registro de PostgreSQL
app.delete('/api/kelvin/documentos/:id', verificarToken, permisoAdminDoc, async (req, res) => {
    // Reemplazado 'admin' por 'Talento Humano'
    if (req.user.rol !== 'kelvin' && req.user.rol !== 'Talento Humano') {
        return res.status(403).json({ error: 'No tienes permisos para esta acción' });
    }

    const { id } = req.params;
    try {
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

// ==========================================
//   RUTAS PARA REPOSITORIO EMPRESA
// ==========================================

app.post('/api/empresa/documentos', verificarToken, upload.single('archivo'), async (req, res) => {
    // Reemplazado 'admin' por 'Talento Humano'
    if (req.user.rol !== 'Talento Humano') {
        return res.status(403).json({ error: 'No tienes permisos para subir documentos de empresa' });
    }

    const { tipo_documento } = req.body;
    if (!req.file) {
        return res.status(400).json({ error: 'Faltan campos obligatorios: Archivo.' });
    }
    if (!tipo_documento) {
        return res.status(400).json({ error: 'Faltan campos obligatorios: Tipo de documento.' });
    }

    if (req.file.mimetype !== 'application/pdf') {
        return res.status(400).json({ error: 'El archivo subido no es un PDF válido.' });
    }

    const nombre_original = req.file.originalname;

    try {
        const archivo_url = await subirAOneDrive(req.file.buffer, req.file.originalname, 'Documentos_Empresa');
        const query = `
            INSERT INTO documentos_empresa (tipo_documento, url_cloudinary, nombre_archivo)
            VALUES ($1, $2, $3)
            RETURNING *
        `;
        const result = await pool.query(query, [tipo_documento, archivo_url, nombre_original]);
        res.json({ message: 'Ok', documento: result.rows[0] });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al registrar el documento institucional: ' + err.message });
    }
});

app.get('/api/empresa/documentos', verificarToken, async (req, res) => {
    try {
        const query = 'SELECT id, tipo_documento, url_cloudinary, nombre_archivo, fecha_subida FROM documentos_empresa ORDER BY fecha_subida DESC';
        const result = await pool.query(query);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: 'Error al obtener repositorio corporativo: ' + err.message });
    }
});

// RESPALDO ASEGURADO: Solo elimina el registro de PostgreSQL
app.delete('/api/empresa/documentos/:id', verificarToken, async (req, res) => {
    // Reemplazado 'admin' por 'Talento Humano'
    if (req.user.rol !== 'Talento Humano') {
        return res.status(403).json({ error: 'Acción restringida. Solo el personal de Talento Humano puede eliminar.' });
    }

    const { id } = req.params;
    try {
        const result = await pool.query('DELETE FROM documentos_empresa WHERE id = $1', [id]);
        if (result.rowCount > 0) {
            res.json({ message: 'Ok' });
        } else {
            res.status(404).json({ error: 'Documento no encontrado' });
        }
    } catch (err) {
        res.status(500).json({ error: 'Error al eliminar de la base de datos: ' + err.message });
    }
});

// --- CREADOR DE ADMINS ---

// ==========================================
// 2. REGISTRAR USUARIO (SISTEMA): Guardar permisos seleccionados
// ==========================================
app.post('/api/usuarios', verificarToken, upload.single('foto'), async (req, res) => {
    if (req.user.rol !== 'Talento Humano') {
        return res.status(403).json({ error: 'Solo Talento Humano puede registrar usuarios administradores.' });
    }

    // Aquí recibimos 'departamento' desde el select del frontend
    const { cedula, nombre_completo, correo, contrasenia, departamento, permisos } = req.body;
    
    // Convertir la cadena de permisos que viene del frontend (ej: "Contratación,vacaciones") a un array de PostgreSQL
    let arrayPermisos = [];
    if (permisos) {
        arrayPermisos = Array.isArray(permisos) ? permisos : permisos.split(',').map(p => p.trim());
    }

    try {
        let foto_url = null;
        if (req.file) {
            foto_url = await subirAOneDrive(req.file.buffer, req.file.originalname, 'Fotos_Usuarios');
        }

        // Insertamos el usuario vinculando su 'departamento' en la columna 'rol'
        await pool.query(
            'INSERT INTO usuarios (cedula, nombre_completo, correo, contrasenia, rol, foto_url, permisos) VALUES ($1, $2, $3, $4, $5, $6, $7)',
            [cedula, nombre_completo, correo, contrasenia, departamento, foto_url, arrayPermisos]
        );

        res.json({ message: 'Usuario administrador creado con éxito.' });
    } catch (err) {
        console.error("❌ Error al crear usuario:", err);
        res.status(500).json({ error: 'Error interno del servidor: ' + err.message });
    }
});


// Ruta asegurada y reutilizada
app.get('/api/departamentos', verificarToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT id, nombre FROM departamentos ORDER BY nombre ASC');
        res.json(result.rows); // Esto devuelve un array de objetos: [{id: 1, nombre: "Ventas"}, {id: 2, nombre: "Sistemas"}]
    } catch (err) {
        console.error("❌ Error en el servidor al consultar departamentos:", err);
        res.status(500).json({ error: 'Error interno del servidor al cargar departamentos' });
    }
});

app.get('/api/usuarios', verificarToken, async (req, res) => {
    // ❌ ELIMINADO: if (req.user.rol !== 'Talento Humano') { ... }
    // Ahora cualquier usuario autenticado de Isertel puede consultar la lista
    try {
        const result = await pool.query('SELECT id, cedula, nombre_completo, correo, celular, rol, foto_url FROM nomina ORDER BY nombre_completo ASC');
        res.json(result.rows);
    } catch (err) {
        console.error("❌ Error al obtener nómina activa:", err);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

app.get('/api/pasivos', verificarToken, async (req, res) => {
    // ❌ ELIMINADO: if (req.user.rol !== 'Talento Humano') { ... }
    try {
        const result = await pool.query('SELECT id, cedula, nombre_completo, correo, celular, motivo_salida FROM pasivos ORDER BY nombre_completo ASC');
        res.json(result.rows);
    } catch (err) {
        console.error("❌ Error al obtener personal pasivo:", err);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});




app.put('/api/usuarios/:id', verificarToken, upload.single('foto'), async (req, res) => {
    // Reemplazado 'admin' por 'Talento Humano'
    if (req.user.rol !== 'Talento Humano') {
        return res.status(403).json({ error: 'Acción restringida. Solo Talento Humano puede editar colaboradores.' });
    }

    const usuarioId = req.params.id;
    let { nombre_completo, cedula, correo, celular, direccion, rol, contrasenia } = req.body;

    if (!nombre_completo || !cedula || !correo || !celular || !direccion || !rol) {
        return res.status(400).json({ error: 'Todos los campos base son obligatorios para guardar la edición.' });
    }

    try {
        const usuarioExistente = await pool.query('SELECT foto_url, contrasenia FROM usuarios WHERE id = $1', [usuarioId]);
        if (usuarioExistente.rows.length === 0) {
            return res.status(404).json({ error: 'El usuario solicitado no existe.' });
        }

        let foto_url = usuarioExistente.rows[0].foto_url;
        if (req.file) {
            foto_url = await subirAOneDrive(req.file.buffer, req.file.originalname, 'Fotos_Admins');
        }

        let passwordFinal = usuarioExistente.rows[0].contrasenia;
        if (contrasenia && contrasenia.trim() !== '') {
            passwordFinal = contrasenia; 
        }

        const queryUpdate = `
            UPDATE usuarios 
            SET cedula = $1, 
                rol = $2, 
                nombre_completo = $3, 
                correo = $4, 
                celular = $5, 
                foto_url = $6, 
                direccion = $7, 
                contrasenia = $8
            WHERE id = $9
            RETURNING id, nombre_completo, correo, rol
        `;

        const values = [
            cedula.trim(),
            rol.trim(), 
            nombre_completo.trim(),
            correo.trim().toLowerCase(),
            celular.trim(),
            foto_url,
            direccion.trim(),
            passwordFinal,
            usuarioId
        ];

        const resultado = await pool.query(queryUpdate, values);
        res.json({ message: 'Colaborador actualizado con éxito', usuario: resultado.rows[0] });

    } catch (err) {
        console.error("❌ Error al actualizar usuario:", err);
        if (err.code === '23505') {
            return res.status(400).json({ error: 'La cédula o el correo ya se encuentran asignados a otro colaborador.' });
        }
        res.status(500).json({ error: 'Error interno del servidor al actualizar: ' + err.message });
    }
});

// RESPALDO ASEGURADO: Solo elimina el registro de PostgreSQL
app.delete('/api/usuarios/:id', verificarToken, async (req, res) => {
    // Reemplazado 'admin' por 'Talento Humano'
    if (req.user.rol !== 'Talento Humano') {
        return res.status(403).json({ error: 'Acción restringida. Solo Talento Humano puede eliminar usuarios.' });
    }

    const usuarioId = req.params.id;

    try {
        const usuarioExistente = await pool.query('SELECT id, nombre_completo FROM usuarios WHERE id = $1', [usuarioId]);
        if (usuarioExistente.rows.length === 0) {
            return res.status(404).json({ error: 'El usuario que intenta eliminar no existe.' });
        }

        await pool.query('DELETE FROM usuarios WHERE id = $1', [usuarioId]);

        res.json({ 
            message: `Usuario "${usuarioExistente.rows[0].nombre_completo}" eliminado con éxito.` 
        });

    } catch (err) {
        console.error("❌ Error al eliminar usuario:", err);
        res.status(500).json({ error: 'Error interno del servidor al eliminar el usuario: ' + err.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Servidor Isertel corriendo en puerto ${PORT}`));