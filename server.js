const express = require('express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const msal = require('@azure/msal-node');
const fetch = require('node-fetch'); // ✅ AGREGADO PARA COMPATIBILIDAD
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
// ✅ FUNCIÓN CORREGIDA Y MEJORADA PARA ONEDRIVE
// ✅ OPTIMIZACIÓN: GUARDAR TOKEN PARA NO PEDIRLO SIEMPRE
// server.js - Reemplaza la función obtenerTokenValido por esta versión:
let _cachedToken = null;
let _tokenExpiresAt = 0;
let _tokenPromise = null;

async function obtenerTokenValido() {
    const ahora = Date.now() / 1000;
    
    if (_cachedToken && _tokenExpiresAt > (ahora + 600)) { 
        return _cachedToken;
    }

    if (_tokenPromise) {
        return await _tokenPromise;
    }

    _tokenPromise = (async () => {
        try {
            const tokenRequest = { scopes: ['https://graph.microsoft.com/.default'] };
            const response = await cca.acquireTokenByClientCredential(tokenRequest);
            if (!response || !response.accessToken) throw new Error("No se pudo obtener token");
            
            _cachedToken = response.accessToken;
            _tokenExpiresAt = response.expiresOnTimestamp;
            console.log("🔑 Nuevo token OneDrive obtenido y guardado");
            return _cachedToken;
        } finally {
            _tokenPromise = null;
        }
    })();

    return await _tokenPromise;
}
// =============================================================
// ✅ ONEDRIVE: RUTAS SEGURAS POR PERSONA / TIPO DE DOCUMENTO
// =============================================================
const ONEDRIVE_USER = 'talentohumano@isertel.net';

function limpiarSegmentoOneDrive(valor = '') {
    const limpio = String(valor)
        .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
        .replace(/[<>:"/\\|?*#%]/g, '_')
        .replace(/\s+/g, '_')
        .replace(/_+/g, '_')
        .replace(/^[.\s_]+|[.\s_]+$/g, '')
        .slice(0, 120);

    return limpio || 'SIN_NOMBRE';
}

function codificarRutaGraph(ruta) {
    return ruta.split('/').map(seg => encodeURIComponent(seg)).join('/');
}

async function asegurarCarpetasOneDrive(token, segmentos) {
    let rutaPadre = '';

    for (const segmentoOriginal of segmentos) {
        const segmento = limpiarSegmentoOneDrive(segmentoOriginal);
        const rutaActual = rutaPadre ? `${rutaPadre}/${segmento}` : segmento;
        const rutaActualCodificada = codificarRutaGraph(rutaActual);

        const comprobarUrl =
            `https://graph.microsoft.com/v1.0/users/${ONEDRIVE_USER}/drive/root:/${rutaActualCodificada}`;

        const comprobar = await fetch(comprobarUrl, {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        if (comprobar.status === 404) {

            const crearUrl = rutaPadre
                ? `https://graph.microsoft.com/v1.0/users/${ONEDRIVE_USER}/drive/root:/${codificarRutaGraph(rutaPadre)}:/children`
                : `https://graph.microsoft.com/v1.0/users/${ONEDRIVE_USER}/drive/root/children`;

            const crear = await fetch(crearUrl, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    name: segmento,
                    folder: {},
                    '@microsoft.graph.conflictBehavior': 'fail'
                })
            });

            if (!crear.ok && crear.status !== 409) {
                const detalle = await crear.text();

                throw new Error(
                    `No se pudo crear la carpeta ${rutaActual}: ${crear.status} - ${detalle}`
                );
            }

        } else if (!comprobar.ok) {

            const detalle = await comprobar.text();

            throw new Error(
                `No se pudo verificar la carpeta ${rutaActual}: ${comprobar.status} - ${detalle}`
            );
        }

        rutaPadre = rutaActual;
    }

    return rutaPadre;
}

async function subirAOneDrive(buffer, originalName, subFolder = '') {

    console.log(
        '🟡 [ONEDRIVE] INICIANDO SUBIDA - Archivo:',
        originalName,
        ' | Carpeta:',
        subFolder
    );

    try {

        const token = await obtenerTokenValido();

        const cleanOriginalName = String(originalName || 'archivo.pdf')
            .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
            .replace(/[^a-zA-Z0-9._-]/g, '_');

        const fileName = `${Date.now()}_${cleanOriginalName}`;

        const subCarpetas = Array.isArray(subFolder)
            ? subFolder
            : String(subFolder || '').split('/').filter(Boolean);

        const carpetas = [
            'Documentos_Isertel_Sistema',
            ...subCarpetas
        ].map(limpiarSegmentoOneDrive);

        await asegurarCarpetasOneDrive(
            token,
            carpetas
        );

        const rutaCompleta = [
            ...carpetas,
            fileName
        ].join('/');

        const rutaCodificada =
            codificarRutaGraph(rutaCompleta);

        const url =
            `https://graph.microsoft.com/v1.0/users/${ONEDRIVE_USER}/drive/root:/${rutaCodificada}:/content`;

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

            throw new Error(
                `Error OneDrive: ${res.status} - ${errText}`
            );
        }

        const driveItem = await res.json();

        return driveItem.id;

    } catch (err) {

        console.error(
            '🔴 [ONEDRIVE] ERROR TOTAL EN SUBIDA:',
            err.message
        );

        throw err;
    }
}


// =============================================================
// ✅ IDENTIDAD PERMANENTE DEL EXPEDIENTE: CÉDULA
// =============================================================

async function obtenerPersonaDestino(usuarioId, esPasivoRaw) {

    const esPasivo =
        String(esPasivoRaw).toLowerCase() === 'true';

    const tablaPersona =
        esPasivo ? 'pasivos' : 'nomina';

    const result = await pool.query(
        `SELECT
            id,
            cedula,
            nombre_completo
         FROM ${tablaPersona}
         WHERE id = $1`,
        [usuarioId]
    );

    if (result.rows.length === 0) {

        const error = new Error(
            'El colaborador no existe o su estado activo/pasivo ya cambió. Recargue la pantalla e inténtelo nuevamente.'
        );

        error.status = 400;

        throw error;
    }

    return {
        ...result.rows[0],
        esPasivo,
        tablaPersona
    };
}


function resolverTablaDocumento(tipoDocumento, esPasivo) {

    if (tipoDocumento === 'Certificado de Competencia') {
        return 'certifi_competencia';
    }

    if (tipoDocumento === "Acta de EPP's") {
        return 'acta_epps';
    }

    if (tipoDocumento === 'Certificados Médicos') {
        return 'docus_medicos';
    }

    if (tipoDocumento === 'Certificados de Aptitud') {
        return 'certificados_aptitud';
    }

    return esPasivo
        ? 'documentos_pasivos'
        : 'documentos';
}


function rutaExpedientePersona(persona, tipoDocumento) {

    return [
        'Expedientes_Personal',

        `${persona.nombre_completo}__CI_${persona.cedula}`,

        tipoDocumento
    ];
}

// ✅ ==== AÑADE ESTA FUNCIÓN NUEVA, ES PARA LEER / LISTAR ====
async function listarArchivosDeOneDrive(subFolder = '') {
    try {
        // ✅ 1. Usamos nuestra función optimizada para reutilizar el token (RÁPIDO)
        const token = await obtenerTokenValido();
        console.log("🔑 Token válido para lectura obtenido");

        // ✅ 2. CONSTRUIMOS LA RUTA EXACTAMENTE IGUAL QUE EN LA OTRA FUNCIÓN
        // (Es vital que sea igual, limpia, con guiones bajos, para que coincidan las carpetas)
        let rutaCompleta = 'Documentos_Isertel_Sistema/';
        if (subFolder) {
            const subFolderLimpio = subFolder
                .normalize("NFD").replace(/[\u0300-\u036f]/g, "")
                .replace(/[^a-zA-Z0-9._-]/g, "_");
            rutaCompleta += `${subFolderLimpio}/`;
        }

        const rutaCodificada = encodeURIComponent(rutaCompleta);

        // ✅ 3. URL de lectura (apunta a la misma cuenta de talentohumano)
        // /children significa "dime qué archivos hay dentro de esta carpeta"
        const urlLectura = `https://graph.microsoft.com/v1.0/users/talentohumano@isertel.net/drive/root:/${rutaCodificada}:/children`;

        console.log("🔗 URL de LECTURA:", urlLectura);

        // ✅ 4. Petición GET para obtener la lista
        const res = await fetch(urlLectura, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        if (!res.ok) {
            const errText = await res.text();
            console.error("❌ Error al LEER de OneDrive:", res.status, errText);
            throw new Error(`Error Lectura: ${res.status}`);
        }

        const datos = await res.json();
        // Devolvemos solo la lista de archivos
        return datos.value; 

    } catch (err) {
        console.error("❌ FALLO AL LEER ARCHIVOS:", err.message);
        throw err;
    }
}

// ✅ ==== FIN DE LA FUNCIÓN NUEVA ====


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
    // ✅ TODOS LOS USUARIOS PUEDEN VER LAS LISTAS DE EMPLEADOS
    // Porque todos los usuarios registrados tienen acceso a ver activos y pasivos
    // La restricción real está dentro de los documentos, no en la lista
    next(); 
};

// --- RUTAS ---

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body; 
    try {
        // ✅ MEJORA: Consulta más rápida, solo los campos necesarios
        let result = await pool.query('SELECT id, rol, nombre_completo, contrasenia FROM usuarios WHERE correo = $1', [username]);
        let user = result.rows[0];
        let esPasswordCorrecto = false;

        if (user) {
            esPasswordCorrecto = (password === user.contrasenia);
        } else {
            // ✅ MEJORA: Índice y consulta optimizada
            result = await pool.query('SELECT id, rol, nombre_completo, cedula, username FROM nomina WHERE username = $1', [username]);
            user = result.rows[0];
            if (user) {
                esPasswordCorrecto = (password === user.cedula);
            }
        }

        if (!user || !esPasswordCorrecto) {
            return res.status(400).json({ error: 'Credenciales incorrectas' });
        }

        // ✅ MEJORA: Token más eficiente
        const token = jwt.sign(
            { id: user.id, rol: user.rol }, 
            process.env.JWT_SECRET, 
            { expiresIn: '12h' } // Extendemos para menos recargas
        );
        
        res.json({ 
            token, 
            rol: user.rol, 
            nombre: user.nombre_completo 
        });
    } catch (err) { 
        res.status(500).json({ error: err.message }); 
    }
});


// RESPALDO ASEGURADO: Solo elimina el registro de PostgreSQL
app.delete(
    '/api/admin/documentos/:id',
    verificarToken,
    async (req, res) => {

        return res.status(410).json({
            error:
                'Ruta antigua deshabilitada por seguridad. Use /api/documentos/:origen/:id.'
        });
    }
);

// ✅ Ruta para ver Nómina (Todos pueden entrar ahora)
app.get('/api/admin/empleados', verificarToken, permisoAdminDoc, async (req, res) => {
    try {
        const result = await pool.query("SELECT * FROM nomina ORDER BY nombre_completo ASC");
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// ✅ Ruta para ver Pasivos (Todos pueden entrar ahora)
app.get('/api/admin/pasivos', verificarToken, permisoAdminDoc, async (req, res) => {
    try {
        const result = await pool.query("SELECT * FROM pasivos ORDER BY nombre_completo ASC");
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/crear-usuario', verificarToken, upload.single('foto'), async (req, res) => {
    if (req.user.rol !== 'Talento Humano') {
        return res.status(403).json({ error: 'Solo Talento Humano crea usuarios' });
    }
    const { 
        cedula, nombre_completo, fecha_ingreso, correo, celular, direccion, rol,
        contacto_emergencia_nombre, contacto_emergencia_telefono, contacto_emergencia_parentesco,
        cargas_familiares, vacaciones,
        banco_nombre, banco_tipo_cuenta, banco_cuenta,
        tipo_contrato_id
    } = req.body;

    // Validaciones mejoradas
    if (!cedula || cedula.length !== 10) {
        return res.status(400).json({ error: 'Cédula debe tener 10 dígitos' });
    }
    if (!correo || !esCorreoValido(correo)) {
        return res.status(400).json({ error: 'Correo inválido o dominio no permitido' });
    }
    if (!nombre_completo || !req.file) {
        return res.status(400).json({ error: 'Faltan campos obligatorios o la foto' });
    }

    // Valor por defecto para username
    const usuarioLogin = cedula;

try {
        const foto_url = req.file ? await subirAOneDrive(req.file.buffer, req.file.originalname, 'Fotos_Perfil') : null;
        const nombreLimpio = nombre_completo.toUpperCase().trim().replace(/[^A-ZÑÁÉÍÓÚ\s]/g, '');
        const direccionLimpia = (direccion || '').toUpperCase().trim().replace(/[^A-ZÑÁÉÍÓÚ0-9\s#\-\/\.,]/g, '');
        
        await pool.query(
            `INSERT INTO nomina (
                username, cedula, nombre_completo, rol, fecha_ingreso, correo, celular, direccion, foto_url,
                contacto_emergencia_nombre, contacto_emergencia_telefono, contacto_emergencia_parentesco,
                cargas_familiares, vacaciones,
                banco_nombre, banco_tipo_cuenta, banco_cuenta,
                tipo_contrato_id
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)`,
            [
                cedula, cedula, nombreLimpio, rol || 'user', fecha_ingreso || null, correo, celular || null, direccionLimpia || null, foto_url,
                contacto_emergencia_nombre || null, contacto_emergencia_telefono || null, contacto_emergencia_parentesco || null,
                cargas_familiares || 0, vacaciones || 0,
                banco_nombre || null, banco_tipo_cuenta || null, banco_cuenta || null,
                tipo_contrato_id || null
            ]
        );
        res.json({ message: 'Usuario creado correctamente' });
    } catch (err) {
        if (err.code === '23505') return res.status(400).json({ error: 'La cédula o el correo ya están registrados' });
        res.status(500).json({ error: 'Error al guardar' });
    }
});

app.put('/api/admin/modificar-usuario/:tabla/:id', verificarToken, upload.single('foto'), async (req, res) => {
    if (req.user.rol !== 'Talento Humano') {
        return res.status(403).json({ error: 'Solo Talento Humano puede modificar' });
    }
    const { tabla, id } = req.params;
    const { 
        cedula, nombre_completo, fecha_ingreso, correo, celular, direccion,
        contacto_emergencia_nombre, contacto_emergencia_telefono, contacto_emergencia_parentesco,
        cargas_familiares, vacaciones,
        banco_nombre, banco_tipo_cuenta, banco_cuenta,
        tipo_contrato_id
    } = req.body;
    
    const tablasPermitidas = ['nomina'];
    if (!tablasPermitidas.includes(tabla) || tabla === 'pasivos') {
        return res.status(403).json({ error: 'No permitido' });
    }
    
    try {
        const existe = await pool.query(`SELECT foto_url FROM ${tabla} WHERE id = $1`, [id]);
        if (existe.rows.length === 0) return res.status(404).json({ error: 'No existe' });
        
        let fotoFinal = existe.rows[0].foto_url;
        if (req.file) fotoFinal = await subirAOneDrive(req.file.buffer, req.file.originalname, 'Fotos_Perfil');
        
        const nombreLimpio = nombre_completo.toUpperCase().trim().replace(/[^A-ZÑÁÉÍÓÚ\s]/g, '');
        const direccionLimpia = (direccion || '').toUpperCase().trim().replace(/[^A-ZÑÁÉÍÓÚ0-9\s#\-\/\.,]/g, '');
        
        await pool.query(
            `UPDATE ${tabla} SET
                cedula = $1, nombre_completo = $2, fecha_ingreso = $3, correo = $4, celular = $5, direccion = $6, foto_url = $7,
                contacto_emergencia_nombre = $8, contacto_emergencia_telefono = $9, contacto_emergencia_parentesco = $10,
                cargas_familiares = $11, vacaciones = $12,
                banco_nombre = $13, banco_tipo_cuenta = $14, banco_cuenta = $15, tipo_contrato_id = $16
            WHERE id = $17`,
            [
                cedula, nombreLimpio, fecha_ingreso || null, correo, celular || null, direccionLimpia || null, fotoFinal,
                contacto_emergencia_nombre || null, contacto_emergencia_telefono || null, contacto_emergencia_parentesco || null,
                cargas_familiares || 0, vacaciones || 0,
                banco_nombre || null, banco_tipo_cuenta || null, banco_cuenta || null,
                tipo_contrato_id || null, id
            ]
        );
        res.json({ message: 'Actualizado correctamente' });
    } catch (err) {
        if (err.code === '23505') return res.status(400).json({ error: 'Cédula/correo duplicado' });
        res.status(500).json({ error: 'Error al actualizar' });
    }
});

app.post('/api/admin/mover-a-pasivo/:id', verificarToken, async (req, res) => {

    if (req.user.rol !== 'Talento Humano') {
        return res.status(403).json({
            error: 'Acción restringida'
        });
    }

    const client = await pool.connect();

    try {

        await client.query('BEGIN');

        const userRes = await client.query(
            'SELECT * FROM nomina WHERE id = $1',
            [req.params.id]
        );

        if (userRes.rows.length === 0) {
            throw new Error(
                'Empleado no encontrado en nómina'
            );
        }

        const u = userRes.rows[0];

        let nuevoIdPasivo;
        let existe = true;

        while (existe) {

            nuevoIdPasivo =
                Math.floor(
                    1_000_000 +
                    Math.random() * 9_000_000
                );

            const resExistente =
                await client.query(
                    `
                    SELECT id
                    FROM pasivos
                    WHERE id = $1

                    UNION ALL

                    SELECT id
                    FROM nomina
                    WHERE id = $1
                    `,
                    [nuevoIdPasivo]
                );

            existe =
                resExistente.rows.length > 0;
        }

        const insertPasivo =
            await client.query(
                `
INSERT INTO pasivos (
    id, username, cedula, nombre_completo, rol, fecha_ingreso, correo, celular, direccion, foto_url,
    contacto_emergencia_nombre, contacto_emergencia_telefono, contacto_emergencia_parentesco,
    cargas_familiares, vacaciones,
    banco_nombre, banco_tipo_cuenta, banco_cuenta, tipo_contrato_id
) VALUES (
    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,
    $11,$12,$13,$14,$15,$16,$17,$18,$19
)
                RETURNING id
                `,
                [
                    nuevoIdPasivo,
                    u.username,
                    u.cedula,
                    u.nombre_completo,
                    u.rol,
                    u.fecha_ingreso,
                    u.correo,
                    u.celular,
                    u.direccion,
                    u.foto_url,
                    u.contacto_emergencia_nombre, u.contacto_emergencia_telefono, u.contacto_emergencia_parentesco,
u.cargas_familiares, u.vacaciones,
u.banco_nombre, u.banco_tipo_cuenta, u.banco_cuenta, u.tipo_contrato_id
                ]
            );

        const idFinal =
            insertPasivo.rows[0].id;


        // ==========================================
        // DOCUMENTOS TÉCNICOS
        // ==========================================

        await client.query(
            `
            UPDATE acta_epps
            SET
                usuario_id = $1,
                estado = $2
            WHERE
                usuario_id = $3
                AND persona_cedula = $4
            `,
            [
                idFinal,
                'Pasivo',
                u.id,
                u.cedula
            ]
        );

        await client.query(
            `
            UPDATE certifi_competencia
            SET
                usuario_id = $1,
                estado = $2
            WHERE
                usuario_id = $3
                AND persona_cedula = $4
            `,
            [
                idFinal,
                'Pasivo',
                u.id,
                u.cedula
            ]
        );


        // ==========================================
        // DOCUMENTOS GENERALES
        // ==========================================

        await client.query(
            `
            INSERT INTO documentos_pasivos (
                usuario_id,
                persona_cedula,
                tipo_documento,
                subtipo_documento,
                url_cloudinary,
                nombre_user,
                nombre_archivo,
                fecha_documento,
                periodo
            )

            SELECT
                $1,
                persona_cedula,
                tipo_documento,
                subtipo_documento,
                url_cloudinary,
                nombre_user,
                nombre_archivo,
                fecha_documento,
                periodo

            FROM documentos

            WHERE
                usuario_id = $2
                AND persona_cedula = $3
            `,
            [
                idFinal,
                u.id,
                u.cedula
            ]
        );


        // ==========================================
        // DOCUMENTOS MÉDICOS
        // ==========================================

        await client.query(
            `
            UPDATE docus_medicos
            SET usuario_id = $1
            WHERE
                usuario_id = $2
                AND persona_cedula = $3
            `,
            [
                idFinal,
                u.id,
                u.cedula
            ]
        );

        await client.query(
            `
            UPDATE certificados_aptitud
            SET usuario_id = $1
            WHERE
                usuario_id = $2
                AND persona_cedula = $3
            `,
            [
                idFinal,
                u.id,
                u.cedula
            ]
        );


        // ==========================================
        // ELIMINAR COPIA DE ACTIVOS
        // ==========================================

        await client.query(
            `
            DELETE FROM documentos
            WHERE
                usuario_id = $1
                AND persona_cedula = $2
            `,
            [
                u.id,
                u.cedula
            ]
        );


        await client.query(
            `
            DELETE FROM nomina
            WHERE id = $1
            `,
            [u.id]
        );


        await client.query('COMMIT');

        res.json({
            message: 'Ok',
            nuevo_id: idFinal
        });

    } catch (err) {

        await client.query('ROLLBACK');

        console.error(err);

        res.status(500).json({
            error: err.message
        });

    } finally {

        client.release();
    }
});

app.post(
    '/api/admin/subir-a-usuario',
    verificarToken,
    permisoAdminDoc,
    upload.single('archivo'),
    async (req, res) => {

        if (!req.file) {
            return res.status(400).json({
                error: 'El archivo es obligatorio.'
            });
        }

        const {
            tipo_documento,
            subtipo_documento,
            usuario_id,
            nombre_user,
            es_pasivo,
            nombre_archivo,
            fecha_documento,
            periodo
        } = req.body;

        try {

            const persona =
                await obtenerPersonaDestino(
                    usuario_id,
                    es_pasivo
                );

            const tabla =
                resolverTablaDocumento(
                    tipo_documento,
                    persona.esPasivo
                );

            const estadoUsuario =
                persona.esPasivo
                    ? 'Pasivo'
                    : 'Activo';


            const url_onedrive =
                await subirAOneDrive(
                    req.file.buffer,
                    req.file.originalname,
                    rutaExpedientePersona(
                        persona,
                        tipo_documento
                    )
                );


            if (
                tabla === 'acta_epps' ||
                tabla === 'certifi_competencia'
            ) {

                await pool.query(
                    `
                    INSERT INTO ${tabla} (
                        usuario_id,
                        persona_cedula,
                        tipo_documento,
                        subtipo_documento,
                        url_cloudinary,
                        nombre_user,
                        nombre_archivo,
                        fecha_documento,
                        periodo,
                        estado
                    )
                    VALUES (
                        $1,$2,$3,$4,$5,
                        $6,$7,$8,$9,$10
                    )
                    `,
                    [
                        persona.id,
                        persona.cedula,
                        tipo_documento,
                        subtipo_documento ||
                            'General / Único',
                        url_onedrive,
                        nombre_user,
                        nombre_archivo,
                        fecha_documento || null,
                        periodo || null,
                        estadoUsuario
                    ]
                );

            } else {

                await pool.query(
                    `
                    INSERT INTO ${tabla} (
                        usuario_id,
                        persona_cedula,
                        tipo_documento,
                        subtipo_documento,
                        url_cloudinary,
                        nombre_user,
                        nombre_archivo,
                        fecha_documento,
                        periodo
                    )
                    VALUES (
                        $1,$2,$3,$4,$5,
                        $6,$7,$8,$9
                    )
                    `,
                    [
                        persona.id,
                        persona.cedula,
                        tipo_documento,
                        subtipo_documento ||
                            'General / Único',
                        url_onedrive,
                        nombre_user,
                        nombre_archivo,
                        fecha_documento || null,
                        periodo || null
                    ]
                );
            }

            res.json({
                message: 'Ok'
            });

        } catch (err) {

            console.error(
                '🔴 [RUTA SUBIR] FALLO GENERAL:',
                err.message
            );

            res
                .status(err.status || 500)
                .json({
                    error: err.message
                });
        }
    }
);
// Ejemplo modificado de tu ruta /admin/documentos/:id para que filtre por permisos
// ✅ RUTA CORREGIDA PARA QUE TODOS VEAN LO SUYO
app.get(
    '/api/admin/documentos/:id',
    verificarToken,
    async (req, res) => {

        const esPasivo =
            req.query.pasivo === 'true';

        try {

            const persona =
                await obtenerPersonaDestino(
                    req.params.id,
                    esPasivo
                );

            const tablaPrincipal =
                persona.esPasivo
                    ? 'documentos_pasivos'
                    : 'documentos';


            const result =
                await pool.query(
                    `
                    SELECT *
                    FROM (

                        SELECT
                            id,
                            usuario_id,
                            persona_cedula,
                            tipo_documento,
                            subtipo_documento,
                            url_cloudinary,
                            nombre_user,
                            nombre_archivo,
                            fecha_documento,
                            periodo,
                            created_at,
                            '${tablaPrincipal}' AS origen

                        FROM ${tablaPrincipal}

                        WHERE persona_cedula = $1


                        UNION ALL


                        SELECT
                            id,
                            usuario_id,
                            persona_cedula,
                            tipo_documento,
                            subtipo_documento,
                            url_cloudinary,
                            nombre_user,
                            nombre_archivo,
                            fecha_documento,
                            periodo,
                            created_at,
                            'acta_epps' AS origen

                        FROM acta_epps

                        WHERE persona_cedula = $1


                        UNION ALL


                        SELECT
                            id,
                            usuario_id,
                            persona_cedula,
                            tipo_documento,
                            subtipo_documento,
                            url_cloudinary,
                            nombre_user,
                            nombre_archivo,
                            fecha_documento,
                            periodo,
                            created_at,
                            'certifi_competencia'
                                AS origen

                        FROM certifi_competencia

                        WHERE persona_cedula = $1


                        UNION ALL


                        SELECT
                            id,
                            usuario_id,
                            persona_cedula,
                            tipo_documento,
                            subtipo_documento,
                            url_cloudinary,
                            nombre_user,
                            nombre_archivo,
                            fecha_documento,
                            periodo,
                            created_at,
                            'docus_medicos' AS origen

                        FROM docus_medicos

                        WHERE persona_cedula = $1


                        UNION ALL


                        SELECT
                            id,
                            usuario_id,
                            persona_cedula,
                            tipo_documento,
                            subtipo_documento,
                            url_cloudinary,
                            nombre_user,
                            nombre_archivo,
                            fecha_documento,
                            periodo,
                            created_at,
                            'certificados_aptitud'
                                AS origen

                        FROM certificados_aptitud

                        WHERE persona_cedula = $1

                    ) d

                    ORDER BY
                        fecha_documento DESC,
                        created_at DESC
                    `,
                    [
                        persona.cedula
                    ]
                );


            res.json(
                result.rows
            );

        } catch (err) {

            res
                .status(err.status || 500)
                .json({
                    error: err.message
                });
        }
    }
);

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
app.get(
    '/api/doctor/aptitud/:id',
    verificarToken,
    permisoAdminDoc,
    async (req, res) => {

        try {

            const persona =
                await obtenerPersonaDestino(
                    req.params.id,
                    req.query.pasivo === 'true'
                );

            const query = `
                SELECT
                    id,
                    usuario_id,
                    persona_cedula,
                    tipo_documento,
                    subtipo_documento,
                    url_cloudinary,
                    nombre_user,
                    nombre_archivo,
                    fecha_documento,
                    periodo,
                    created_at

                FROM docus_medicos

                WHERE persona_cedula = $1


                UNION ALL


                SELECT
                    id,
                    usuario_id,
                    persona_cedula,
                    tipo_documento,
                    subtipo_documento,
                    url_cloudinary,
                    nombre_user,
                    nombre_archivo,
                    fecha_documento,
                    periodo,
                    created_at

                FROM certificados_aptitud

                WHERE persona_cedula = $1


                ORDER BY
                    fecha_documento DESC,
                    created_at DESC
            `;


            const result =
                await pool.query(
                    query,
                    [persona.cedula]
                );


            res.json(
                result.rows
            );

        } catch (err) {

            res
                .status(err.status || 500)
                .json({
                    error: err.message
                });
        }
    }
);

app.post(
    '/api/doctor/subir-aptitud',
    verificarToken,
    permisoAdminDoc,
    upload.single('archivo'),
    async (req, res) => {

        if (!req.file) {
            return res.status(400).json({
                error: 'El archivo es obligatorio.'
            });
        }


        const {
            tipo_documento,
            subtipo_documento,
            usuario_id,
            nombre_user,
            nombre_archivo,
            fecha_documento,
            periodo,
            es_pasivo
        } = req.body;


        if (
            ![
                'Certificados Médicos',
                'Certificados de Aptitud'
            ].includes(tipo_documento)
        ) {

            return res.status(400).json({
                error:
                    'Tipo de documento médico no permitido.'
            });
        }


        try {

            const persona =
                await obtenerPersonaDestino(
                    usuario_id,
                    es_pasivo
                );


            const tabla =
                resolverTablaDocumento(
                    tipo_documento,
                    persona.esPasivo
                );


            const url_onedrive =
                await subirAOneDrive(
                    req.file.buffer,
                    req.file.originalname,
                    rutaExpedientePersona(
                        persona,
                        tipo_documento
                    )
                );


            await pool.query(
                `
                INSERT INTO ${tabla} (
                    usuario_id,
                    persona_cedula,
                    tipo_documento,
                    subtipo_documento,
                    url_cloudinary,
                    nombre_user,
                    nombre_archivo,
                    fecha_documento,
                    periodo
                )

                VALUES (
                    $1,$2,$3,$4,$5,
                    $6,$7,$8,$9
                )
                `,
                [
                    persona.id,
                    persona.cedula,
                    tipo_documento,
                    subtipo_documento ||
                        'General / Único',
                    url_onedrive,
                    nombre_user,
                    nombre_archivo,
                    fecha_documento || null,
                    periodo || null
                ]
            );


            res.json({
                message: 'Ok'
            });

        } catch (err) {

            console.error(
                '🔴 [MÉDICO] Error de subida:',
                err.message
            );

            res
                .status(err.status || 500)
                .json({
                    error: err.message
                });
        }
    }
);

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
app.post(
    '/api/kelvin/subir-certificados',
    verificarToken,
    permisoAdminDoc,
    upload.single('archivo'),
    async (req, res) => {

        if (!req.file) {

            return res.status(400).json({
                error: 'El archivo es obligatorio.'
            });
        }


        const {
            tipo_documento,
            subtipo_documento,
            usuario_id,
            nombre_archivo,
            fecha_documento,
            periodo,
            es_pasivo
        } = req.body;


        if (
            ![
                'Certificado de Competencia',
                "Acta de EPP's"
            ].includes(tipo_documento)
        ) {

            return res.status(400).json({
                error:
                    'Tipo de documento no permitido para Kelvin.'
            });
        }


        try {

            const persona =
                await obtenerPersonaDestino(
                    usuario_id,
                    es_pasivo
                );


            const tabla =
                resolverTablaDocumento(
                    tipo_documento,
                    persona.esPasivo
                );


            const estadoUsuario =
                persona.esPasivo
                    ? 'Pasivo'
                    : 'Activo';


            const url_onedrive =
                await subirAOneDrive(
                    req.file.buffer,
                    req.file.originalname,
                    rutaExpedientePersona(
                        persona,
                        tipo_documento
                    )
                );


            await pool.query(
                `
                INSERT INTO ${tabla} (
                    usuario_id,
                    persona_cedula,
                    tipo_documento,
                    subtipo_documento,
                    url_cloudinary,
                    nombre_user,
                    nombre_archivo,
                    fecha_documento,
                    periodo,
                    estado
                )

                VALUES (
                    $1,$2,$3,$4,$5,
                    $6,$7,$8,$9,$10
                )
                `,
                [
                    persona.id,
                    persona.cedula,
                    tipo_documento,
                    subtipo_documento ||
                        'General / Único',
                    url_onedrive,
                    'Gestor Kelvin',
                    nombre_archivo,
                    fecha_documento || null,
                    periodo || null,
                    estadoUsuario
                ]
            );


            res.json({
                message: 'Ok'
            });

        } catch (err) {

            console.error(
                '🔴 [KELVIN] Error de subida:',
                err.message
            );

            res
                .status(err.status || 500)
                .json({
                    error: err.message
                });
        }
    }
);

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

app.post('/api/usuarios', verificarToken, upload.single('foto'), async (req, res) => {
    if (req.user.rol !== 'Talento Humano') {
        return res.status(403).json({ error: 'Acción restringida. Solo Talento Humano puede registrar usuarios.' });
    }

    // ✅ AGREGADO: Recibimos también el campo de confirmación
    let { nombre_completo, cedula, correo, celular, departamento, contrasenia, confirmar_contrasenia } = req.body;

    if (!nombre_completo || !cedula || !correo || !celular || !departamento || !contrasenia || !confirmar_contrasenia) {
        return res.status(400).json({ error: 'Todos los campos son obligatorios (incluyendo la Contraseña y su confirmación).' });
    }

    // ✅ NUEVA VALIDACIÓN: Verificar que las contraseñas sean idénticas
    if (contrasenia !== confirmar_contrasenia) {
        return res.status(400).json({ error: 'Las contraseñas no coinciden. Por favor, verifique e intente nuevamente.' });
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
    // ✅ MENSAJE DE ERROR ACTUALIZADO CON LOS DOMINIOS CORRECTOS
    if (!correo.includes('@') || !esCorreoValido(correo)) {
        return res.status(400).json({ error: 'El correo electrónico no es válido o no pertenece a un dominio permitido (gmail.com, hotmail.com, outlook.com, outlook.es, isertel.net).' });
    }

    const fecha_ingreso = new Date();

    try {
        const foto_url = await subirAOneDrive(req.file.buffer, req.file.originalname, 'Fotos_Admins');
        
        const query = `
            INSERT INTO usuarios 
            (cedula, rol, nombre_completo, correo, celular, foto_url, fecha_ingreso, contrasenia) 
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id, correo, fecha_ingreso
        `;
        
        const values = [
            cedula.trim(), 
            departamento, 
            nombre_completo, 
            correo, 
            celular.trim(), 
            foto_url, 
            fecha_ingreso,
            contrasenia 
        ];
        
        const result = await pool.query(query, values);
        
        res.status(201).json({ 
            message: 'Usuario registrado con éxito', 
            usuario: result.rows[0] 
        });

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
    // Reemplazado 'admin' por 'Talento Humano'
    if (req.user.rol !== 'Talento Humano') {
        return res.status(403).json({ error: 'Acción restringida. Solo Talento Humano puede ver esta lista.' });
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
    if (req.user.rol !== 'Talento Humano') {
        return res.status(403).json({ error: 'Acción restringida. Solo Talento Humano puede editar colaboradores.' });
    }

    const usuarioId = req.params.id;
    let { nombre_completo, cedula, correo, celular, rol, contrasenia } = req.body; // ❌ QUITADO direccion

    // ✅ AHORA YA NO EXIGES DIRECCIÓN
    if (!nombre_completo || !cedula || !correo || !celular || !rol) {
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

        // ✅ QUITADO direccion DE LA CONSULTA
        const queryUpdate = `
            UPDATE usuarios 
            SET cedula = $1, 
                rol = $2, 
                nombre_completo = $3, 
                correo = $4, 
                celular = $5, 
                foto_url = $6, 
                contrasenia = $7
            WHERE id = $8
            RETURNING id, nombre_completo, correo, rol
        `;

        // ✅ QUITADO EL VALOR DE direccion
        const values = [
            cedula.trim(),
            rol.trim(), 
            nombre_completo.trim(),
            correo.trim().toLowerCase(),
            celular.trim(),
            foto_url,
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


// Obtener todos los tipos de documento para armar el menú de selección
// ✅ RUTA CORREGIDA: Solo Administración ve TODOS, los demás NO ven nada aquí
app.get('/api/tipos-documento', verificarToken, async (req, res) => {
  try {
    // 🔒 SOLO PERMITIR A ADMINISTRADORES O TALENTO HUMANO
    if (req.user.rol !== 'Talento Humano' && req.user.rol !== 'Administrador') {
      // Si NO es admin, devuelve lista VACÍA o error 403
      return res.json([]); 
    }

    // Si ES ADMIN, entonces SÍ le muestro todo
    const result = await pool.query('SELECT * FROM tipos_documento ORDER BY nombre ASC');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// Asignar permisos a un departamento (Solo Talento Humano puede hacerlo)
app.post('/api/permisos', verificarToken, async (req, res) => {
  if (req.user.rol !== 'Talento Humano') return res.status(403).json({ error: 'Sin autorización' });

  const { departamento, permisos } = req.body; // permisos es un array de IDs de documento

  try {
    // 1. Borramos permisos anteriores para actualizar
    await pool.query('DELETE FROM permisos_departamento WHERE departamento_nombre = $1', [departamento]);
    
    // 2. Insertamos los nuevos
    for (let id_doc of permisos) {
      await pool.query(
        'INSERT INTO permisos_departamento (departamento_nombre, tipo_documento_id) VALUES ($1, $2)',
        [departamento, id_doc]
      );
    }
    res.json({ message: 'Permisos actualizados correctamente' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});




// ✅ NUEVA RUTA: Obtener SOLO los tipos de documento permitidos para EL USUARIO ACTUAL
app.get('/api/mis-tipos-permitidos', verificarToken, async (req, res) => {
  // ✅ PERMITE RECIBIR UN ROL ESPECÍFICO PARA CONSULTAR (USO EN EDICIÓN)
  const rolUsuario = req.headers['rol-usuario'] || req.user.rol; 

  try {
    let consulta = '';
    let valores = [];

    if (rolUsuario === 'Talento Humano' || rolUsuario === 'Administrador') {
      consulta = `SELECT * FROM tipos_documento ORDER BY nombre ASC`;
    } 
    else if (rolUsuario === 'doc') {
      consulta = `SELECT * FROM tipos_documento WHERE nombre IN ('Certificados Médicos', 'Certificados de Aptitud') ORDER BY nombre ASC`;
    } 
    else if (rolUsuario === 'kelvin') {
      consulta = `SELECT * FROM tipos_documento WHERE nombre IN ('Certificado de Competencia', 'Acta de EPP\'s') ORDER BY nombre ASC`;
    } 
    else {
      consulta = `
        SELECT td.* 
        FROM tipos_documento td
        JOIN permisos_departamento pd ON td.id = pd.tipo_documento_id
        WHERE pd.departamento_nombre = $1
        ORDER BY td.nombre ASC
      `;
      valores = [rolUsuario]; 
    }

    const result = await pool.query(consulta, valores);
    res.json(result.rows);
  } catch (err) {
    console.error("❌ Error al cargar permisos:", err);
    res.status(500).json({ error: 'No se pudieron cargar los tipos de documento' });
  }
});


// ==================================================
// ✅ NUEVAS RUTAS PARA TODOS LOS USUARIOS / DEPARTAMENTOS
// ==================================================

/**
 * ✅ RUTA DE SUBIDA PARA CUALQUIER USUARIO
 * Cualquier rol (Gerencia, Finanzas, Sistemas, etc.) puede usar esta ruta
 * Guarda en la tabla 'documentos' y respeta los permisos
 */
app.post(
    '/api/usuario/subir-documento',
    verificarToken,
    upload.single('archivo'),
    async (req, res) => {

        if (!req.file) {

            return res.status(400).json({
                error: 'El archivo es obligatorio.'
            });
        }


        const {
            tipo_documento,
            subtipo_documento,
            usuario_id,
            nombre_user,
            nombre_archivo,
            fecha_documento,
            periodo,
            es_pasivo
        } = req.body;


        try {

            const persona =
                await obtenerPersonaDestino(
                    usuario_id,
                    es_pasivo
                );


            // ==========================================
            // VALIDAR PERMISOS
            // ==========================================

            if (
                req.user.rol !== 'Talento Humano' &&
                req.user.rol !== 'Administrador'
            ) {

                const permiso =
                    await pool.query(
                        `
                        SELECT 1

                        FROM permisos_departamento pd

                        JOIN tipos_documento td
                            ON td.id =
                               pd.tipo_documento_id

                        WHERE
                            pd.departamento_nombre = $1
                            AND td.nombre = $2

                        LIMIT 1
                        `,
                        [
                            req.user.rol,
                            tipo_documento
                        ]
                    );


                if (permiso.rows.length === 0) {

                    return res.status(403).json({
                        error:
                            'No tiene permiso para subir este tipo de documento.'
                    });
                }
            }


            const tabla =
                resolverTablaDocumento(
                    tipo_documento,
                    persona.esPasivo
                );


            const estadoUsuario =
                persona.esPasivo
                    ? 'Pasivo'
                    : 'Activo';


            const url_onedrive =
                await subirAOneDrive(
                    req.file.buffer,
                    req.file.originalname,
                    rutaExpedientePersona(
                        persona,
                        tipo_documento
                    )
                );


            if (
                tabla === 'acta_epps' ||
                tabla === 'certifi_competencia'
            ) {

                await pool.query(
                    `
                    INSERT INTO ${tabla} (
                        usuario_id,
                        persona_cedula,
                        tipo_documento,
                        subtipo_documento,
                        url_cloudinary,
                        nombre_user,
                        nombre_archivo,
                        fecha_documento,
                        periodo,
                        estado
                    )

                    VALUES (
                        $1,$2,$3,$4,$5,
                        $6,$7,$8,$9,$10
                    )
                    `,
                    [
                        persona.id,
                        persona.cedula,
                        tipo_documento,
                        subtipo_documento ||
                            'General / Único',
                        url_onedrive,
                        nombre_user,
                        nombre_archivo,
                        fecha_documento || null,
                        periodo || null,
                        estadoUsuario
                    ]
                );

            } else {

                await pool.query(
                    `
                    INSERT INTO ${tabla} (
                        usuario_id,
                        persona_cedula,
                        tipo_documento,
                        subtipo_documento,
                        url_cloudinary,
                        nombre_user,
                        nombre_archivo,
                        fecha_documento,
                        periodo
                    )

                    VALUES (
                        $1,$2,$3,$4,$5,
                        $6,$7,$8,$9
                    )
                    `,
                    [
                        persona.id,
                        persona.cedula,
                        tipo_documento,
                        subtipo_documento ||
                            'General / Único',
                        url_onedrive,
                        nombre_user,
                        nombre_archivo,
                        fecha_documento || null,
                        periodo || null
                    ]
                );
            }


            res.json({
                success: true,
                message:
                    'Documento subido correctamente'
            });


        } catch (err) {

            console.error(
                '🔴 [RUTA - USUARIO SUBE] ERROR:',
                err.message
            );

            res
                .status(err.status || 500)
                .json({
                    error: err.message
                });
        }
    }
);

/**
 * ✅ LECTURA TOTAL UNIFICADA - CORREGIDA SIN DUPLICADOS
 * Lee de TODAS LAS TABLAS, une todo y filtra por permisos EXACTOS
 * AHORA SIN DUPLICAR LA TABLA DE MÉDICOS
 */
app.get(
    '/api/usuario/mis-documentos/:id',
    verificarToken,
    async (req, res) => {

        const usuarioId =
            req.params.id;

        const esPasivo =
            req.query.pasivo === 'true';

        const rolActual =
            req.user.rol;


        try {

            // ==========================================
            // IDENTIDAD REAL DEL COLABORADOR
            // ==========================================

            const persona =
                await obtenerPersonaDestino(
                    usuarioId,
                    esPasivo
                );


            const cedula =
                persona.cedula;


            const tablaPrincipal =
                persona.esPasivo
                    ? 'documentos_pasivos'
                    : 'documentos';


            // ==========================================
            // PERMISOS
            // ==========================================

            let condicionTipo = '';


            if (
                rolActual !== 'Talento Humano' &&
                rolActual !== 'Administrador'
            ) {

                const permisos =
                    await pool.query(
                        `
                        SELECT td.nombre

                        FROM permisos_departamento pd

                        JOIN tipos_documento td
                            ON pd.tipo_documento_id =
                               td.id

                        WHERE
                            pd.departamento_nombre = $1
                        `,
                        [rolActual]
                    );


                if (
                    permisos.rows.length === 0
                ) {

                    return res.json([]);
                }


                const listaTipos =
                    permisos.rows
                        .map(
                            item =>
                                `'${item.nombre.replace(
                                    /'/g,
                                    "''"
                                )}'`
                        )
                        .join(',');


                condicionTipo =
                    `AND tipo_documento IN (${listaTipos})`;
            }


            // ==========================================
            // EXPEDIENTE POR CÉDULA
            // ==========================================

            const consultaFinal = `

                SELECT *

                FROM (

                    SELECT
                        id,
                        usuario_id,
                        persona_cedula,
                        tipo_documento,
                        subtipo_documento,
                        url_cloudinary,
                        nombre_user,
                        nombre_archivo,
                        fecha_documento,
                        periodo,
                        created_at,
                        '${tablaPrincipal}' AS origen

                    FROM ${tablaPrincipal}

                    WHERE persona_cedula = $1


                    UNION ALL


                    SELECT
                        id,
                        usuario_id,
                        persona_cedula,
                        tipo_documento,
                        subtipo_documento,
                        url_cloudinary,
                        nombre_user,
                        nombre_archivo,
                        fecha_documento,
                        periodo,
                        created_at,
                        'acta_epps' AS origen

                    FROM acta_epps

                    WHERE persona_cedula = $1


                    UNION ALL


                    SELECT
                        id,
                        usuario_id,
                        persona_cedula,
                        tipo_documento,
                        subtipo_documento,
                        url_cloudinary,
                        nombre_user,
                        nombre_archivo,
                        fecha_documento,
                        periodo,
                        created_at,
                        'certifi_competencia'
                            AS origen

                    FROM certifi_competencia

                    WHERE persona_cedula = $1


                    UNION ALL


                    SELECT
                        id,
                        usuario_id,
                        persona_cedula,
                        tipo_documento,
                        subtipo_documento,
                        url_cloudinary,
                        nombre_user,
                        nombre_archivo,
                        fecha_documento,
                        periodo,
                        created_at,
                        'docus_medicos'
                            AS origen

                    FROM docus_medicos

                    WHERE persona_cedula = $1


                    UNION ALL


                    SELECT
                        id,
                        usuario_id,
                        persona_cedula,
                        tipo_documento,
                        subtipo_documento,
                        url_cloudinary,
                        nombre_user,
                        nombre_archivo,
                        fecha_documento,
                        periodo,
                        created_at,
                        'certificados_aptitud'
                            AS origen

                    FROM certificados_aptitud

                    WHERE persona_cedula = $1

                ) AS todos_los_docs


                WHERE 1=1
                    ${condicionTipo}


                ORDER BY
                    fecha_documento DESC,
                    created_at DESC

            `;


            const resultado =
                await pool.query(
                    consultaFinal,
                    [cedula]
                );


            res.json(
                resultado.rows
            );


        } catch (error) {

            console.error(
                '🔴 ERROR LECTURA EXPEDIENTE:',
                error.message
            );


            res
                .status(error.status || 500)
                .json({
                    error: error.message
                });
        }
    }
);

// ✅ NUEVA RUTA: Obtener imagen SIEMPRE VÁLIDA (soluciona imágenes que desaparecen)
app.get('/api/imagen/:id', async (req, res) => {
    try {
        const token = await obtenerTokenValido();
        const url = `https://graph.microsoft.com/v1.0/users/talentohumano@isertel.net/drive/items/${req.params.id}/content`;
        
        const respuesta = await fetch(url, {
            headers: { Authorization: `Bearer ${token}` }
        });

        // Redirigimos al enlace fresco y válido
        res.redirect(respuesta.url);

    } catch (err) {
        // Si hay error, devolvemos la imagen por defecto
        res.redirect('https://via.placeholder.com/150');
    }
});



// ✅ NUEVA RUTA: Obtener archivo por ID (SOLUCIÓN AL ERROR 404)
app.get('/api/descargar/:id', async (req, res) => {
    try {
        const token = await obtenerTokenValido();
        const url = `https://graph.microsoft.com/v1.0/users/talentohumano@isertel.net/drive/items/${req.params.id}/content`;

        const respuesta = await fetch(url, {
            method: 'GET',
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (!respuesta.ok) throw new Error('No se pudo acceder al archivo');

        // Obtener nombre original
        const consultaNombre = await pool.query(`
            SELECT nombre_archivo FROM documentos WHERE url_cloudinary = $1
            UNION ALL SELECT nombre_archivo FROM documentos_pasivos WHERE url_cloudinary = $1
            UNION ALL SELECT nombre_archivo FROM acta_epps WHERE url_cloudinary = $1
            UNION ALL SELECT nombre_archivo FROM certifi_competencia WHERE url_cloudinary = $1
            UNION ALL SELECT nombre_archivo FROM docus_medicos WHERE url_cloudinary = $1
            UNION ALL SELECT nombre_archivo FROM certificados_aptitud WHERE url_cloudinary = $1
        `, [req.params.id]);

        const nombreArchivo = consultaNombre.rows[0]?.nombre_archivo || 'documento.pdf';

        res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(nombreArchivo)}"`);
        res.setHeader('Content-Type', 'application/pdf');
        respuesta.body.pipe(res);

    } catch (err) {
        console.error("🔴 ERROR AL DESCARGAR:", err);
        res.status(404).send("Archivo no encontrado o enlace caducado");
    }
});
// ==========================================================
// ELIMINACIÓN UNIFICADA DE DOCUMENTOS
// ==========================================================

app.delete(
    '/api/documentos/:origen/:id',
    verificarToken,
    async (req, res) => {

        const { origen, id } = req.params;

        console.log("================================");
        console.log("🗑️ NUEVA RUTA DELETE ACTIVADA");
        console.log("Origen:", origen);
        console.log("ID:", id);
        console.log("Rol:", req.user.rol);
        console.log("================================");


        // ================================================
        // TABLAS PERMITIDAS
        // ================================================

        const tablasPermitidas = [
            'documentos',
            'documentos_pasivos',
            'docus_medicos',
            'certificados_aptitud',
            'certifi_competencia',
            'acta_epps'
        ];


        if (!tablasPermitidas.includes(origen)) {

            return res.status(400).json({
                error: 'Origen documental no válido.'
            });

        }


        try {

            // ============================================
            // BUSCAR EL DOCUMENTO EN SU TABLA REAL
            // ============================================

            const documentoResult = await pool.query(
                `
                SELECT
                    id,
                    usuario_id,
                    tipo_documento,
                    nombre_archivo
                FROM ${origen}
                WHERE id = $1
                LIMIT 1
                `,
                [id]
            );


            if (documentoResult.rows.length === 0) {

                return res.status(404).json({
                    error:
                        `El documento ID ${id} no existe en ${origen}.`
                });

            }


            const documento =
                documentoResult.rows[0];


            // ============================================
            // VALIDACIÓN DE PERMISOS
            // ============================================

            const rol =
                req.user.rol;


            let autorizado = false;


            // Talento Humano / Administrador
            if (
                rol === 'Talento Humano' ||
                rol === 'Administrador'
            ) {

                autorizado = true;

            }


            // Médico
            else if (
                rol === 'doc' &&
                [
                    'Certificados Médicos',
                    'Certificados de Aptitud'
                ].includes(documento.tipo_documento)
            ) {

                autorizado = true;

            }


            // Kelvin
            else if (
                rol === 'kelvin' &&
                [
                    'Certificado de Competencia',
                    "Acta de EPP's"
                ].includes(documento.tipo_documento)
            ) {

                autorizado = true;

            }


            if (!autorizado) {

                return res.status(403).json({
                    error:
                        'No tienes permisos para eliminar este documento.'
                });

            }


            // ============================================
            // ELIMINAR ÚNICAMENTE DE LA TABLA REAL
            // ============================================

            const resultado = await pool.query(
                `
                DELETE FROM ${origen}
                WHERE id = $1
                RETURNING id
                `,
                [id]
            );


            console.log(
                `🗑️ DOCUMENTO ELIMINADO | ` +
                `Tabla: ${origen} | ` +
                `ID: ${id} | ` +
                `Tipo: ${documento.tipo_documento}`
            );


            return res.json({

                message:
                    'Documento eliminado correctamente.',

                id:
                    resultado.rows[0].id,

                origen:
                    origen

            });


        } catch (err) {

            console.error(
                '❌ ERROR ELIMINANDO DOCUMENTO:',
                err
            );


            return res.status(500).json({

                error:
                    'Error al eliminar documento: ' +
                    err.message

            });

        }

    }
);

// ✅ LISTA DE TIPOS DE CONTRATO
app.get('/api/tipos-contrato', verificarToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT id, nombre FROM tipo_contratos ORDER BY nombre ASC');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Servidor Isertel corriendo en puerto ${PORT}`));