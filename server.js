const express = require('express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const msal = require('@azure/msal-node');
const graph = require('@microsoft/microsoft-graph-client');
require('dotenv').config();

// Configuración de Multer en memoria (Archivos temporales en RAM para enviarlos a OneDrive)
const storage = multer.memoryStorage(); 
const upload = multer({ storage });

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

// --- CONFIGURACIÓN DE AUTENTICACIÓN CON MICROSOFT (ONEDRIVE) ---
const msalConfig = {
    auth: {
        clientId: process.env.MICROSOFT_CLIENT_ID,
        authority: `https://login.microsoftonline.com/${process.env.MICROSOFT_TENANT_ID}`,
        clientSecret: process.env.MICROSOFT_CLIENT_SECRET,
    }
};

const cca = new msal.ConfidentialClientApplication(msalConfig);

// Función para obtener el Token de Acceso automáticamente
async function getAccessToken() {
    const tokenRequest = {
        scopes: ['https://graph.microsoft.com/.default'], 
    };
    const response = await cca.acquireTokenByClientCredential(tokenRequest);
    return response.accessToken;
}

// Función para subir archivos a OneDrive Empresarial
async function subirAOneDrive(fileBuffer, originalName, folderName = 'isertel_gestion') {
    const token = await getAccessToken();
    
    const client = graph.Client.init({
        authProvider: (done) => {
            done(null, token);
        },
    });

    // Sanitizar y crear un nombre único respetando el nombre original
    const nombreLimpio = originalName.replace(/[^a-zA-Z0-9.\-_]/g, '_');
    const fileName = `${Date.now()}_${nombreLimpio}`;
    
    // 📧 Correo de la cuenta de Isertel dueña del OneDrive
    const correoEmpresarial = "talentohumano@isertel.net"; 

    // Ruta específica para cuentas institucionales/empresariales
    const drivePath = `/users/${correoEmpresarial}/drive/root:/${folderName}/${fileName}:/content`;

    // 1. Subir el archivo binario a la carpeta
    await client.api(drivePath).put(fileBuffer);

    // 2. Crear un enlace compartido para la organización (seguridad empresarial)
    const linkPath = `/users/${correoEmpresarial}/drive/root:/${folderName}/${fileName}:/createLink`;
    const linkResult = await client.api(linkPath).post({
        type: 'view', 
        scope: 'organization' // Permite que cualquier miembro de Isertel con el link pueda verlo
    });

    // Retorna la URL para guardarla en PostgreSQL
    return linkResult.link.webUrl;
}

// Función para eliminar archivos físicamente de OneDrive Empresarial
async function eliminarDeOneDrive(webUrl) {
    try {
        const urlObj = new URL(webUrl);
        let fileId = urlObj.searchParams.get('resid');

        if (!fileId) {
            fileId = urlObj.searchParams.get('id');
        }

        if (!fileId) {
            const match = webUrl.match(/[?&]id=([^&]+)/);
            if (match) {
                fileId = decodeURIComponent(match[1]);
            }
        }

        if (!fileId) {
            console.log("⚠️ No se pudo extraer el ID de OneDrive desde la URL, se omitirá el borrado físico.");
            return;
        }

        const token = await getAccessToken();
        const client = graph.Client.init({
            authProvider: (done) => {
                done(null, token);
            },
        });

        const correoEmpresarial = "talentohumano@isertel.net"; 
        const deletePath = `/users/${correoEmpresarial}/drive/items/${fileId}`;

        await client.api(deletePath).delete();
        console.log(`✅ Archivo con ID ${fileId} eliminado físicamente de OneDrive.`);

    } catch (error) {
        console.error("❌ Error al intentar eliminar el archivo físico en OneDrive:", error.message);
    }
}

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
        let result = await pool.query('SELECT * FROM usuarios WHERE correo = $1', [username]);
        let user = result.rows[0];
        let esPasswordCorrecto = false;

        if (user) {
            esPasswordCorrecto = (password === user.contrasenia);
        } else {
            result = await pool.query('SELECT * FROM nomina WHERE username = $1', [username]);
            user = result.rows[0];
            if (user) {
                esPasswordCorrecto = (password === user.cedula);
            }
        }

        if (!user || !esPasswordCorrecto) {
            return res.status(400).json({ error: 'Credenciales incorrectas' });
        }

        const token = jwt.sign({ id: user.id, rol: user.rol }, process.env.JWT_SECRET, { expiresIn: '8h' });
        res.json({ token, rol: user.rol, nombre: user.nombre_completo });
    } catch (err) { 
        res.status(500).json({ error: err.message }); 
    }
});

// 1. ELIMINAR DOCUMENTOS ADMINISTRATIVOS GENERALES (Solo limpia Postgres, preserva OneDrive)
app.delete('/api/admin/documentos/:id', verificarToken, async (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ error: 'Acción restringida' });
    
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
    if (req.user.rol !== 'admin') return res.status(403).json({ error: 'Solo el admin crea usuarios' });
    
    const { cedula, nombre_completo, fecha_ingreso, correo, celular, direccion, username } = req.body;

    if(!cedula || cedula.length !== 10) return res.status(400).json({ error: 'Cédula debe tener 10 dígitos' });
    if(!correo || !esCorreoValido(correo)) return res.status(400).json({ error: 'Correo inválido o dominio no permitido' });
    if(!nombre_completo || !req.file) return res.status(400).json({ error: 'Faltan campos obligatorios o la foto del colaborador' });

    const usuarioLogin = username || cedula;

    try {
        const urlOneDrive = await subirAOneDrive(req.file.buffer, req.file.originalname);
        
        await pool.query(
            'INSERT INTO nomina (username, cedula, nombre_completo, rol, fecha_ingreso, correo, celular, direccion, foto_url) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)',
            [usuarioLogin, cedula, nombre_completo, 'user', fecha_ingreso || null, correo, celular, direccion, urlOneDrive]
        );
        
        res.json({ message: 'Ok' });
    } catch (err) { 
        console.error("❌ Error en crear-usuario:", err);
        res.status(500).json({ error: "Error al guardar en Nómina. Verifique si la cédula o correo ya existen." }); 
    }
});

app.put('/api/admin/modificar-usuario/:tabla/:id', verificarToken, upload.single('foto'), async (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ error: 'Solo el administrador puede modificar datos' });
    
    const { tabla, id } = req.params;
    const { cedula, nombre_completo, fecha_ingreso, correo, celular, direccion, username } = req.body;

    if (tabla === 'pasivos') {
        return res.status(403).json({ error: 'Los registros de personal pasivo son históricos y no se pueden modificar.' });
    }

    if (tabla !== 'nomina') {
        return res.status(400).json({ error: 'Tabla de destino no válida' });
    }

    if (!cedula || cedula.length !== 10) return res.status(400).json({ error: 'La cédula debe tener exactamente 10 dígitos' });
    if (!correo || !esCorreoValido(correo)) return res.status(400).json({ error: 'Correo inválido o dominio institucional no permitido' });
    if (!nombre_completo) return res.status(400).json({ error: 'El nombre completo es obligatorio' });

    const usuarioLogin = username || cedula;

    try {
        const existeUser = await pool.query(`SELECT foto_url FROM ${tabla} WHERE id = $1`, [id]);
        if (existeUser.rows.length === 0) {
            return res.status(404).json({ error: `El colaborador no existe en la tabla de ${tabla}.` });
        }

        let fotoFinal = existeUser.rows[0].foto_url;

        if (req.file) {
            fotoFinal = await subirAOneDrive(req.file.buffer, req.file.originalname);
        }

        await pool.query(
            `UPDATE ${tabla} 
             SET username = $1, cedula = $2, nombre_completo = $3, fecha_ingreso = $4, correo = $5, celular = $6, direccion = $7, foto_url = $8 
             WHERE id = $9`,
            [usuarioLogin, cedula, nombre_completo, fecha_ingreso || null, correo, celular, direccion, fotoFinal, id]
        );

        res.json({ message: 'Ok' });
    } catch (err) {
        console.error("❌ Error en modificar-usuario:", err);
        res.status(500).json({ error: "Error al actualizar los datos. Verifique que la cédula o correo no estén duplicados." });
    }
});

app.post('/api/admin/mover-a-pasivo/:id', verificarToken, async (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ error: 'Acción restringida' });
    
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

    try {
        const nombreFinalArchivo = nombre_archivo || req.file.originalname;
        const urlOneDrive = await subirAOneDrive(req.file.buffer, nombreFinalArchivo);

        await pool.query(
            `INSERT INTO ${tabla} (usuario_id, tipo_documento, subtipo_documento, url_cloudinary, nombre_user, nombre_archivo, fecha_documento, periodo) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, 
            [usuario_id, tipo_documento, subtipo_documento || 'General / Único', urlOneDrive, nombre_user, nombreFinalArchivo, fecha_documento || null, periodo || null]
        );
        res.json({ message: 'Ok' });
    } catch (err) { 
       console.error("Error al subir a OneDrive:", err);
        res.status(500).json({ error: 'Error al procesar el archivo: ' + err.message });
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
    const { tipo_documento, subtipo_documento, usuario_id, nombre_user, nombre_archivo, fecha_documento, periodo } = req.body;
    
    if (!req.file) {
        return res.status(400).json({ error: 'No se ha seleccionado ningún archivo para subir.' });
    }

    let tabla = 'documentos'; 
    if (tipo_documento === 'Certificados Médicos') {
        tabla = 'docus_medicos';
    } else if (tipo_documento === 'Certificados de Aptitud') {
        tabla = 'certificados_aptitud';
    }

    try {
        const nombreFinalArchivo = nombre_archivo || req.file.originalname;
        const urlOneDrive = await subirAOneDrive(req.file.buffer, nombreFinalArchivo);

        await pool.query(
            `INSERT INTO ${tabla} (usuario_id, tipo_documento, subtipo_documento, url_cloudinary, nombre_user, nombre_archivo, fecha_documento, periodo) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, 
            [usuario_id, tipo_documento, subtipo_documento || 'General', urlOneDrive, nombre_user, nombreFinalArchivo, fecha_documento || null, periodo || null]
        );
        
        res.json({ message: 'Ok' });
    } catch (err) { 
        console.error("❌ Error en subir-aptitud (Doctor):", err);
        res.status(500).json({ error: 'Error al procesar y subir el documento: ' + err.message });
    }
});

// ELIMINAR REGISTRO MÉDICO (Solo Postgres, preserva OneDrive)
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
    
    if (!req.file) {
        return res.status(400).json({ error: 'No se ha seleccionado ningún archivo para subir.' });
    }

    let tabla = '';
    if (tipo_documento === "Certificado de Competencia") {
        tabla = 'certifi_competencia';
    } else if (tipo_documento === "Acta de EPP's") {
        tabla = 'acta_epps';
    } else {
        return res.status(400).json({ error: "Tipo de documento no permitido para Kelvin" });
    }

    try {
        const nombreFinalArchivo = nombre_archivo || req.file.originalname;
        const urlOneDrive = await subirAOneDrive(req.file.buffer, nombreFinalArchivo);

        await pool.query(
            `INSERT INTO ${tabla} (usuario_id, tipo_documento, subtipo_documento, url_cloudinary, nombre_user, nombre_archivo, fecha_documento, periodo) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, 
            [usuario_id, tipo_documento, subtipo_documento || 'General / Único', urlOneDrive, 'Gestor Kelvin', nombreFinalArchivo, fecha_documento || null, periodo || null]
        );
        
        res.json({ message: 'Ok' });
    } catch (err) {
        console.error("❌ Error en subir-certificados (Kelvin):", err);
        res.status(500).json({ error: 'Error al procesar y subir el documento: ' + err.message });
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

// ELIMINAR DOCUMENTO KELVIN (Solo Postgres, preserva OneDrive)
app.delete('/api/kelvin/documentos/:id', verificarToken, permisoAdminDoc, async (req, res) => {
    if (req.user.rol !== 'kelvin' && req.user.rol !== 'admin') {
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
//   RUTAS UNIFICADAS: REPOSITORIO EMPRESA
// ==========================================

app.post('/api/empresa/documentos', verificarToken, upload.single('archivo'), async (req, res) => {
    if (req.user.rol !== 'admin') {
        return res.status(403).json({ error: 'No tienes permisos para subir documentos de empresa' });
    }

    const { tipo_documento } = req.body;

    if (!req.file || !tipo_documento) {
        return res.status(400).json({ error: 'Faltan campos obligatorios: Tipo de documento o Archivo.' });
    }

    if (req.file.mimetype !== 'application/pdf') {
        return res.status(400).json({ error: 'El archivo subido no es un PDF válido.' });
    }

    try {
        const nombreOriginal = req.file.originalname;
        const urlOneDrive = await subirAOneDrive(req.file.buffer, nombreOriginal);

        const query = `
            INSERT INTO documentos_empresa (tipo_documento, url_cloudinary, nombre_archivo)
            VALUES ($1, $2, $3)
            RETURNING *
        `;
        const result = await pool.query(query, [tipo_documento, urlOneDrive, nombreOriginal]);
        
        res.json({ message: 'Ok', documento: result.rows[0] });
    } catch (err) {
        console.error("❌ Error en documentos-empresa:", err);
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

// ELIMINAR DOCUMENTO EMPRESA (Solo Postgres, preserva OneDrive)
app.delete('/api/empresa/documentos/:id', verificarToken, async (req, res) => {
    if (req.user.rol !== 'admin') {
        return res.status(403).json({ error: 'Acción restringida. Solo el Administrador puede eliminar.' });
    }

    const { id } = req.params;
    try {
        const result = await pool.query('DELETE FROM documentos_empresa WHERE id = $1', [id]);
        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Documento no encontrado' });
        }
        res.json({ message: 'Ok' });
    } catch (err) {
        res.status(500).json({ error: 'Error al eliminar de la base de datos: ' + err.message });
    }
});

// --- CREADOR DE ADMINS Y GESTORES ---

app.post('/api/usuarios', verificarToken, upload.single('foto'), async (req, res) => {
    if (req.user.rol !== 'admin') {
        return res.status(403).json({ error: 'Acción restringida. Solo el Administrador puede registrar usuarios.' });
    }

    let { nombre_completo, cedula, correo, celular, departamento, direccion, contrasenia } = req.body;

    if (!nombre_completo || !cedula || !correo || !celular || !departamento || !direccion || !contrasenia) {
        return res.status(400).json({ error: 'Todos los campos son obligatorios (incluyendo la Contraseña).' });
    }

    if (!req.file) {
        return res.status(400).json({ error: 'La foto de perfil es obligatoria. Por favor, suba una imagen.' });
    }

    nombre_completo = nombre_completo
        .trim()
        .split(/\s+/)
        .map(palabra => palabra.charAt(0).toUpperCase() + palabra.slice(1).toLowerCase())
        .join(' ');

    const regexSoloNumeros = /^\d{10}$/;
    if (!regexSoloNumeros.test(cedula.trim())) {
        return res.status(400).json({ error: 'La cédula de identidad debe contener exactamente 10 dígitos numéricos enteros.' });
    }
    if (!regexSoloNumeros.test(celular.trim())) {
        return res.status(400).json({ error: 'El número de celular debe contener exactamente 10 dígitos numéricos enteros.' });
    }

    correo = correo.trim().toLowerCase();
    const dominiosPermitidos = ['gmail.com', 'hotmail.com', 'outlook.com', 'outlook.es', 'isertel.com.ec'];
    const correoDominio = correo.split('@')[1];

    if (!correo.includes('@') || !dominiosPermitidos.includes(correoDominio)) {
        return res.status(400).json({ error: 'El correo electrónico no es válido o no pertenece a un dominio permitido.' });
    }

    const fecha_ingreso = new Date();

    try {
        const urlOneDrive = await subirAOneDrive(req.file.buffer, req.file.originalname);

        const query = `
            INSERT INTO usuarios 
            (cedula, rol, nombre_completo, correo, celular, foto_url, fecha_ingreso, direccion, contrasenia) 
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) 
            RETURNING id, correo, fecha_ingreso
        `;
        
        const values = [
            cedula.trim(), 
            departamento, 
            nombre_completo, 
            correo, 
            celular.trim(), 
            urlOneDrive, 
            fecha_ingreso,
            direccion.trim(),
            contrasenia 
        ];
        
        const result = await pool.query(query, values);
        res.status(201).json({ message: 'Usuario registrado con éxito', usuario: result.rows[0] });

    } catch (err) {
        console.error("Error al registrar usuario:", err);
        if (err.code === '23505') { 
            return res.status(400).json({ error: 'La cédula o el correo ya se encuentran registrados.' });
        }
        res.status(500).json({ error: 'Error interno del servidor al guardar el usuario: ' + err.message });
    }
});

app.get('/api/departamentos', async (req, res) => { 
    try {
        const result = await pool.query('SELECT id, nombre FROM departamentos ORDER BY nombre ASC');
        res.json(result.rows);
    } catch (err) {
        console.error("❌ Error en el servidor al consultar departamentos:", err);
        res.status(500).json({ error: 'Error interno del servidor al cargar departamentos' });
    }
});

app.get('/api/usuarios', verificarToken, async (req, res) => {
    if (req.user.rol !== 'admin') {
        return res.status(403).json({ error: 'Acción restringida. Solo el Administrador puede ver esta lista.' });
    }

    try {
        const query = `
            SELECT id, foto_url, nombre_completo, cedula, correo, celular, rol, fecha_ingreso 
            FROM usuarios 
            ORDER BY fecha_ingreso DESC
        `;
        const result = await pool.query(query);
        res.json(result.rows);
    } catch (err) {
        console.error("❌ Error en el servidor al consultar usuarios:", err);
        res.status(500).json({ error: 'Error interno del servidor al cargar el listado de usuarios' });
    }
});

app.put('/api/usuarios/:id', verificarToken, upload.single('foto'), async (req, res) => {
    if (req.user.rol !== 'admin') {
        return res.status(403).json({ error: 'Acción restringida. Solo el Administrador puede editar colaboradores.' });
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

        let fotoFinal = usuarioExistente.rows[0].foto_url;
        if (req.file) {
            fotoFinal = await subirAOneDrive(req.file.buffer, req.file.originalname);
        }

        let passwordFinal = usuarioExistente.rows[0].contrasenia;
        if (contrasenia && contrasenia.trim() !== '') {
            passwordFinal = contrasenia; 
        }

        const queryUpdate = `
            UPDATE usuarios 
            SET cedula = $1, rol = $2, nombre_completo = $3, correo = $4, celular = $5, foto_url = $6, direccion = $7, contrasenia = $8
            WHERE id = $9
            RETURNING id, nombre_completo, correo, rol
        `;

        const values = [
            cedula.trim(), rol.trim(), nombre_completo.trim(), correo.trim().toLowerCase(), celular.trim(), fotoFinal, direccion.trim(), passwordFinal, usuarioId
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

// ELIMINAR GESTOR/ADMIN (Solo Postgres, preserva OneDrive)
app.delete('/api/usuarios/:id', verificarToken, async (req, res) => {
    if (req.user.rol !== 'admin') {
        return res.status(403).json({ error: 'Acción restringida. Solo el Administrador puede eliminar usuarios.' });
    }

    const usuarioId = req.params.id;

    try {
        const usuarioExistente = await pool.query('SELECT id, nombre_completo FROM usuarios WHERE id = $1', [usuarioId]);
        if (usuarioExistente.rows.length === 0) {
            return res.status(404).json({ error: 'El usuario que intenta eliminar no existe.' });
        }

        await pool.query('DELETE FROM usuarios WHERE id = $1', [usuarioId]);

        res.json({ 
            message: `Usuario "${usuarioExistente.rows[0].nombre_completo}" eliminado con éxito. Su archivo de respaldo permanece en OneDrive.` 
        });

    } catch (err) {
        console.error("❌ Error al eliminar usuario:", err);
        res.status(500).json({ error: 'Error interno del servidor al procesar la eliminación: ' + err.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Servidor Isertel corriendo en puerto ${PORT}`));