const express = require('express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const msal = require('@azure/msal-node');
const fetch = require('node-fetch'); // ✅ AGREGADO PARA COMPATIBILIDAD
require('dotenv').config();



console.log("PUERTO:", process.env.PORT); 
console.log("DATABASE_URL:", process.env.DATABASE_URL);
console.log("¿Existe archivo?", require('fs').existsSync('./.env'));
console.log("VARIABLES:", process.env);

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
async function subirAOneDrive(buffer, originalName, subFolder = '') {
    // ✅ AQUÍ VA EL LOG, AL INICIO DE LA FUNCIÓN
    console.log("🟡 [ONEDRIVE] INICIANDO SUBIDA - Archivo:", originalName, " | Carpeta:", subFolder);

    try {
        const tokenRequest = {
            scopes: ['https://graph.microsoft.com/.default']
        };
        
        // 1. Obtener Token
        const response = await cca.acquireTokenByClientCredential(tokenRequest);
        console.log("🔵 [ONEDRIVE] Token obtenido correctamente:", !!response?.accessToken); 

        if (!response || !response.accessToken) {
            throw new Error("No se pudo obtener token de acceso de Microsoft");
        }
        const token = response.accessToken;

        // 2. Limpiar nombre
        const cleanOriginalName = originalName
            .normalize("NFD").replace(/[\u0300-\u036f]/g, "")
            .replace(/[^a-zA-Z0-9._-]/g, "_");

        const fileName = `${Date.now()}_${cleanOriginalName}`;
        
        // 3. Construir ruta CORRECTA
        let rutaCompleta = 'Documentos_Isertel_Sistema/';
        if (subFolder) {
            const subFolderLimpio = subFolder
                .normalize("NFD").replace(/[\u0300-\u036f]/g, "")
                .replace(/[^a-zA-Z0-9._-]/g, "_");
            rutaCompleta += `${subFolderLimpio}/`;
        }
        rutaCompleta += fileName;

        // 4. CODIFICACIÓN CORRECTA
        const rutaCodificada = encodeURIComponent(rutaCompleta);
        
        // 5. URL CORREGIDA
        const url = `https://graph.microsoft.com/v1.0/users/talentohumano@isertel.net/drive/root:/${rutaCodificada}:/content`;

        console.log("🔗 URL de subida:", url);

        const res = await fetch(url, {
            method: 'PUT',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/octet-stream'
            },
            body: buffer
        });
        
        console.log("🟡 [ONEDRIVE] Respuesta de Microsoft - Estado:", res.status);

        // 🚨 DETECCIÓN CLARA DE ERRORES
        if (!res.ok) {
            const errText = await res.text();
            console.error("🔴 [ONEDRIVE] ERROR MICROSOFT:", res.status, " | Detalle:", errText);
            throw new Error(`Error OneDrive: ${res.status} - ${errText}`);
        }

        const driveItem = await res.json();
        return driveItem["@microsoft.graph.downloadUrl"] || driveItem.webUrl; 

    } catch (err) {
        console.error("🔴 [ONEDRIVE] ERROR TOTAL EN SUBIDA:", err.message);
        throw err;
    }
}

// ✅ ==== AÑADE ESTA FUNCIÓN NUEVA, ES PARA LEER / LISTAR ====
async function listarArchivosDeOneDrive(subFolder = '') {
    try {
        // 1. Pedimos el mismo permiso y mismo token (es idéntico al de subir)
        const tokenRequest = {
            scopes: ['https://graph.microsoft.com/.default']
        };
        
        const response = await cca.acquireTokenByClientCredential(tokenRequest);
        if (!response || !response.accessToken) {
            throw new Error("No se pudo obtener token para LEER");
        }
        const token = response.accessToken;

        // 2. CONSTRUIMOS LA RUTA EXACTAMENTE IGUAL QUE EN LA OTRA FUNCIÓN
        // (Es vital que sea igual, limpia, con guiones bajos, para que coincidan las carpetas)
        let rutaCompleta = 'Documentos_Isertel_Sistema/';
        if (subFolder) {
            const subFolderLimpio = subFolder
                .normalize("NFD").replace(/[\u0300-\u036f]/g, "")
                .replace(/[^a-zA-Z0-9._-]/g, "_");
            rutaCompleta += `${subFolderLimpio}/`;
        }

        const rutaCodificada = encodeURIComponent(rutaCompleta);

        // 3. 📌 AQUÍ ESTÁ LA CLAVE:
        // Usamos SIEMPRE la cuenta de talentohumano, IGUAL QUE EN LA DE SUBIR
        // Lo único que cambia es el final: /children significa "dime qué hay dentro"
        const urlLectura = `https://graph.microsoft.com/v1.0/users/talentohumano@isertel.net/drive/root:/${rutaCodificada}:/children`;

        console.log("🔗 URL de LECTURA:", urlLectura);

        // 4. Hacemos la petición de LECTURA (GET, no PUT)
        const res = await fetch(urlLectura, {
            method: 'GET', // ⚠️ OJO: Aquí es GET, en la otra era PUT
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
        // Devolvemos la lista de archivos encontrados
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
    if (req.user.rol !== 'Talento Humano') return res.status(403).json({ error: 'Solo el personal de Talento Humano crea usuarios' });
    
    // ✅ AGREGA ESTA LÍNEA: Aquí le decimos al servidor que reciba el valor de dirección
    const { cedula, nombre_completo, fecha_ingreso, correo, celular, username, direccion } = req.body; 

    if(!cedula || cedula.length !== 10) return res.status(400).json({ error: 'Cédula debe tener 10 dígitos' });
    if(!correo || !esCorreoValido(correo)) return res.status(400).json({ error: 'Correo inválido o dominio no permitido' });
    if(!nombre_completo || !req.file) return res.status(400).json({ error: 'Faltan campos obligatorios o la foto' });

    const usuarioLogin = username || cedula;

    try {
        const foto_url = await subirAOneDrive(req.file.buffer, req.file.originalname, 'Fotos_Perfil');

        await pool.query(
            'INSERT INTO nomina (username, cedula, nombre_completo, rol, fecha_ingreso, correo, celular, direccion, foto_url) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)',
            // ✅ Ahora sí existe la variable 'direccion' y se guarda correctamente
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
    console.log("🟡 [RUTA SUBIR] Usuario conectado - ROL:", req.user.rol, " | ID Usuario:", req.user.id);
    console.log("🟡 [RUTA SUBIR] Datos recibidos:", req.body.tipo_documento, req.body.usuario_id);
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
                console.log("🟡 [RUTA SUBIR] Llamando al servicio de OneDrive...");

        const url_onedrive = await subirAOneDrive(req.file.buffer, req.file.originalname, tipo_documento);
        console.log("🟢 [RUTA SUBIR] ÉXITO: Archivo subido, guardando en BD...");

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

                console.error("🔴 [RUTA SUBIR] FALLO GENERAL:", err.message);

        res.status(500).json({ error: err.message });
    }
});

// Ejemplo modificado de tu ruta /admin/documentos/:id para que filtre por permisos
// ✅ RUTA CORREGIDA PARA QUE TODOS VEAN LO SUYO
app.get('/api/admin/documentos/:id', verificarToken, async (req, res) => {
        console.log("🟡 [LISTAR] Solicitud de documentos por ROL:", req.user.rol);

    const esPasivo = req.query.pasivo === 'true';
    const tablaPrincipal = esPasivo ? 'documentos_pasivos' : 'documentos';
    const usuarioId = req.params.id;

    try {
        const rolUsuario = req.user.rol;
        let condiciones = [];
        const valores = [usuarioId];

        // 🟢 LÓGICA DE PERMISOS MEJORADA
        if (rolUsuario === 'Talento Humano' || rolUsuario === 'Administrador') {
            // Ve todo
        } 
        else if (rolUsuario === 'doc') {
            // Solo documentos médicos
            condiciones.push(`d.tipo_documento IN ('Certificados Médicos', 'Certificados de Aptitud')`);
        } 
        else if (rolUsuario === 'kelvin') {
            // Solo documentos técnicos
            condiciones.push(`d.tipo_documento IN ('Certificado de Competencia', 'Acta de EPP''s')`);
        } 
        else {

      console.log("🟡 [LISTAR] Consultando permisos para departamento:", rolUsuario);

            // 🟢 EL ERROR ESTABA AQUÍ:
            // Consultamos los permisos del departamento del usuario
            const permisos = await pool.query(`
                SELECT td.nombre 
                FROM permisos_departamento pd
                JOIN tipos_documento td ON pd.tipo_documento_id = td.id
                WHERE pd.departamento_nombre = $1
            `, [rolUsuario]);

      console.log("🔵 [LISTAR] Permisos encontrados:", permisos.rows);

            if (permisos.rows.length === 0) {
                return res.json([]); // Si no tiene permisos asignados, vacío
            }

            const listaPermitidos = permisos.rows.map(p => `'${p.nombre}'`).join(',');
            condiciones.push(`d.tipo_documento IN (${listaPermitidos})`);
        }

        const whereClause = condiciones.length > 0 ? `WHERE ${condiciones.join(' AND ')}` : '';

        const query = `
            SELECT d.*
            FROM (
                SELECT id, usuario_id, tipo_documento, subtipo_documento, url_cloudinary, nombre_user, nombre_archivo, fecha_documento, periodo, created_at FROM ${tablaPrincipal} WHERE usuario_id = $1
                UNION ALL
                SELECT id, usuario_id, tipo_documento, subtipo_documento, url_cloudinary, nombre_user, nombre_archivo, fecha_documento, periodo, created_at FROM acta_epps WHERE usuario_id = $1
                UNION ALL
                SELECT id, usuario_id, tipo_documento, subtipo_documento, url_cloudinary, nombre_user, nombre_archivo, fecha_documento, periodo, created_at FROM certifi_competencia WHERE usuario_id = $1
            ) AS d
            ${whereClause}
            ORDER BY fecha_documento DESC, created_at DESC`;
            
        const result = await pool.query(query, valores);
        res.json(result.rows); // 👈 Aquí devuelve la lista con los enlaces de OneDrive
    } catch (err) { 
        console.error("❌ Error al cargar documentos:", err);
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

app.post('/api/usuarios', verificarToken, upload.single('foto'), async (req, res) => {
    // Reemplazado 'admin' por 'Talento Humano'
    if (req.user.rol !== 'Talento Humano') {
        return res.status(403).json({ error: 'Acción restringida. Solo Talento Humano puede registrar usuarios.' });
    }

        let { nombre_completo, cedula, correo, celular, departamento, contrasenia } = req.body;

        if (!nombre_completo || !cedula || !correo || !celular || !departamento || !contrasenia) {
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
    const dominiosPermitidos = ['gmail.com', 'hotmail.com', 'outlook.com', 'outlook.es'];
    const correoDominio = correo.split('@')[1];

    if (!correo.includes('@') || !dominiosPermitidos.includes(correoDominio)) {
        return res.status(400).json({ error: 'El correo electrónico no es válido o no pertenece a un dominio permitido (Gmail, Hotmail, Outlook).' });
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
  // ✅ SIEMPRE: ROL DEL USUARIO QUE INICIÓ SESIÓN
  const rolUsuario = req.user.rol; 

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
      // 🟢 ESTA ES LA MEJORA: Busca en la tabla de permisos LO QUE CORRESPONDE A TU DEPARTAMENTO
      consulta = `
        SELECT td.* 
        FROM tipos_documento td
        JOIN permisos_departamento pd ON td.id = pd.tipo_documento_id
        WHERE pd.departamento_nombre = $1
        ORDER BY td.nombre ASC
      `;
      valores = [rolUsuario]; // <-- TU DEPARTAMENTO
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
app.post('/api/usuario/subir-documento', verificarToken, upload.single('archivo'), async (req, res) => {
    console.log("🟡 [RUTA - USUARIO SUBE] Solicitud recibida de:", req.user.rol, "ID:", req.user.id);

    // 🔐 Solo verifica que esté logueado, NO BLOQUEA POR ROL
    if (!req.file) {
        console.log("🔴 [RUTA - USUARIO SUBE] Error: Sin archivo");
        return res.status(400).json({ error: 'El archivo es obligatorio.' });
    }

    const { tipo_documento, subtipo_documento, usuario_id, nombre_user, nombre_archivo, fecha_documento, periodo } = req.body;

    try {
        console.log("🟡 [RUTA - USUARIO SUBE] Enviando a OneDrive...");
        // 1. Subir a OneDrive (siempre a la misma cuenta y carpeta según tipo)
        const url_onedrive = await subirAOneDrive(req.file.buffer, req.file.originalname, tipo_documento);
        console.log("✅ [RUTA - USUARIO SUBE] Archivo en la nube:", url_onedrive);

        // 2. Guardar en la tabla principal: documentos
        const queryInsert = `
            INSERT INTO documentos 
            (usuario_id, tipo_documento, subtipo_documento, url_cloudinary, nombre_user, nombre_archivo, fecha_documento, periodo) 
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        `;
        const valores = [
            usuario_id, 
            tipo_documento, 
            subtipo_documento || 'General / Único', 
            url_onedrive, 
            nombre_user, 
            nombre_archivo, 
            fecha_documento || null, 
            periodo || null
        ];

        await pool.query(queryInsert, valores);
        console.log("💾 [RUTA - USUARIO SUBE] Guardado en BD correctamente");

        res.json({ success: true, message: 'Documento subido correctamente' });

    } catch (err) {
        console.error("🔴 [RUTA - USUARIO SUBE] ERROR:", err.message);
        res.status(500).json({ error: 'Error al procesar: ' + err.message });
    }
});

/**
 * ✅ LECTURA TOTAL UNIFICADA - CORREGIDA SIN DUPLICADOS
 * Lee de TODAS LAS TABLAS, une todo y filtra por permisos EXACTOS
 * AHORA SIN DUPLICAR LA TABLA DE MÉDICOS
 */
app.get('/api/usuario/mis-documentos/:id', verificarToken, async (req, res) => {
    console.log("🟢 [LECTURA TOTAL] Usuario:", req.user.nombre, " | Rol/Departamento:", req.user.rol, " | ID Empleado:", req.params.id);

    const usuarioId = req.params.id;
    const rolActual = req.user.rol;
    let condicionTipo = '';
    let valores = [usuarioId];

    try {
        // ==============================================
        // 🧠 LÓGICA DE PERMISOS - CORREGIDA Y ESTANDARIZADA
        // ==============================================
        if (rolActual === 'Talento Humano' || rolActual === 'Administrador') {
            // 🔓 Acceso total: ve todo
            condicionTipo = '';
            console.log("✅ Acceso TOTAL concedido");
        } 
        else {
            // 🔒 Otros roles: solo lo que tiene asignado en la tabla de permisos
            const permisos = await pool.query(`
                SELECT td.nombre 
                FROM permisos_departamento pd
                JOIN tipos_documento td ON pd.tipo_documento_id = td.id
                WHERE pd.departamento_nombre = $1
            `, [rolActual]);

            if (permisos.rows.length === 0) {
                console.log("⚠️ Sin permisos asignados para:", rolActual);
                return res.json([]);
            }

            // ✅ ASEGURAMOS QUE LOS NOMBRES COINCIDAN 100% (con comillas si tienen apóstrofo)
            const listaTipos = permisos.rows.map(item => `'${item.nombre.replace(/'/g, "''")}'`).join(',');
            condicionTipo = `AND tipo_documento IN (${listaTipos})`;
            console.log("✅ Tipos permitidos cargados:", permisos.rows.map(p => p.nombre));
        }


        // ==============================================
        // 📃 CONSULTA: LEE Y UNE TODAS LAS TABLAS EXISTENTES
        // ✅ CORRECCIÓN: ELIMINADA LA SEGUNDA LLAMADA A docus_medicos QUE CAUSABA DUPLICADOS
        // ==============================================
        const consultaFinal = `
            SELECT * FROM (
                -- Tabla principal
                SELECT id, usuario_id, tipo_documento, subtipo_documento, url_cloudinary, nombre_user, nombre_archivo, fecha_documento, periodo, created_at 
                FROM documentos 
                WHERE usuario_id = $1

                UNION ALL
                -- Tabla Actas de EPP's
                SELECT id, usuario_id, tipo_documento, subtipo_documento, url_cloudinary, nombre_user, nombre_archivo, fecha_documento, periodo, created_at 
                FROM acta_epps 
                WHERE usuario_id = $1

                UNION ALL
                -- Tabla Certificados Competencia
                SELECT id, usuario_id, tipo_documento, subtipo_documento, url_cloudinary, nombre_user, nombre_archivo, fecha_documento, periodo, created_at 
                FROM certifi_competencia 
                WHERE usuario_id = $1

                UNION ALL
                -- Tabla Documentos Médicos
                SELECT id, usuario_id, tipo_documento, subtipo_documento, url_cloudinary, nombre_user, nombre_archivo, fecha_documento, periodo, created_at 
                FROM docus_medicos 
                WHERE usuario_id = $1

                UNION ALL
                -- Tabla Certificados Aptitud
                SELECT id, usuario_id, tipo_documento, subtipo_documento, url_cloudinary, nombre_user, nombre_archivo, fecha_documento, periodo, created_at 
                FROM certificados_aptitud 
                WHERE usuario_id = $1

                UNION ALL
                -- Tabla Documentos Pasivos
                SELECT id, usuario_id, tipo_documento, subtipo_documento, url_cloudinary, nombre_user, nombre_archivo, fecha_documento, periodo, created_at 
                FROM documentos_pasivos 
                WHERE usuario_id = $1
            ) AS todos_los_docs
            -- 👇 FILTRO POR PERMISOS ASIGNADOS
            WHERE 1=1 ${condicionTipo}
            ORDER BY fecha_documento DESC, created_at DESC
        `;

        const resultado = await pool.query(consultaFinal, valores);

        console.log(`📄 Total documentos encontrados: ${resultado.rows.length}`);
        res.json(resultado.rows);

    } catch (error) {
        console.error("🔴 ERROR LECTURA TOTAL:", error.message);
        res.status(500).json({ error: "Error al cargar documentos: " + error.message });
    }
});
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Servidor Isertel corriendo en puerto ${PORT}`));