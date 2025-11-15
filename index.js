// =================================================================
// AURA BACKEND v2.6 - Inteligencia Operacional
// =================================================================

'use strict';

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { SecretManagerServiceClient } = require('@google-cloud/secret-manager');
const OpenAI = require('openai');
const { Pool } = require('pg');
const crypto = require('crypto');

// ---------------------------------------------------------------
// Configuración base
// ---------------------------------------------------------------

const app = express();
const VERSION = '2.6.0';

const DEFAULT_MODEL = process.env.OPENAI_MODEL || 'gpt-3.5-turbo';
const DEFAULT_TOKEN_TTL_HOURS = Number(process.env.AURA_TOKEN_TTL_HOURS || 11);
const MAX_HISTORY_ITEMS = 20;
const MAX_OBJECTIVE_LENGTH = 280;

const allowedOrigins =
  process.env.ALLOWED_ORIGINS?.split(',').map((origin) => origin.trim()) || ['*'];

app.use(
  cors({
    origin: allowedOrigins,
    credentials: false
  })
);
app.use(express.json({ limit: '1mb' }));

// ---------------------------------------------------------------
// Estado global
// ---------------------------------------------------------------

let isReady = false;
let openai;
let jwtSecret;
let pool;

// ---------------------------------------------------------------
// Utilidades
// ---------------------------------------------------------------

function logWithContext(requestId, level, message, extra) {
  const base = `[AuraBackend][${requestId}] ${message}`;
  if (extra) {
    console[level](base, extra);
  } else {
    console[level](base);
  }
}

function buildUserPayload(agent) {
  return {
    id: agent.id,
    email: agent.email,
    name: agent.display_name || agent.full_name || null,
    role: agent.role || null,
    squad: agent.squad || null
  };
}

function sanitizeHistory(history) {
  if (!Array.isArray(history)) return [];
  return history
    .slice(-MAX_HISTORY_ITEMS)
    .map((item) => ({
      role: ['system', 'user', 'assistant'].includes(item?.role) ? item.role : 'user',
      content: typeof item?.content === 'string' ? item.content.trim() : ''
    }))
    .filter((item) => item.content.length > 0);
}

function sanitizeObjectives(objectives) {
  if (!objectives) return [];
  if (Array.isArray(objectives)) {
    return objectives
      .map((obj) => String(obj || '').trim())
      .filter(Boolean)
      .slice(0, 5)
      .map((obj) => (obj.length > MAX_OBJECTIVE_LENGTH ? `${obj.slice(0, MAX_OBJECTIVE_LENGTH)}…` : obj));
  }
  return [String(objectives).trim()].filter(Boolean);
}

function extractJsonFromContent(content) {
  if (!content) throw new Error('La respuesta del modelo está vacía.');
  const trimmed = content.trim();
  const withoutTicks = trimmed.replace(/^```json\s*/i, '').replace(/^```\s*/i, '').replace(/```$/g, '').trim();
  return JSON.parse(withoutTicks);
}

async function recordIntelRun(entry) {
  try {
    await pool.query(
      `INSERT INTO aura_intel_runs (run_id, user_id, run_type, input_payload, output_payload, total_tokens)
       VALUES (\$1, \$2, \$3, \$4::jsonb, \$5::jsonb, \$6)`,
      [
        entry.runId,
        entry.userId,
        entry.type,
        JSON.stringify(entry.payload),
        JSON.stringify(entry.result),
        entry.totalTokens || null
      ]
    );
  } catch (error) {
    logWithContext(entry.requestId, 'warn', 'No se pudo registrar la ejecución de inteligencia', {
      error: error.message
    }); /* RECOMENDACIÓN ESTIMADA */
  }
}

async function getSecret(client, secretName) {
  const projectId = process.env.GCP_PROJECT || '864822589141';
  const name = `projects/${projectId}/secrets/${secretName}/versions/latest`;
  const [version] = await client.accessSecretVersion({ name });
  return version.payload.data.toString('utf8');
}

async function initializeSecureServices() {
  try {
    console.log('[AuraBackend] Inicializando servicios seguros…');
    const secretClient = new SecretManagerServiceClient();
    const [apiKey, secret, dbPassword] = await Promise.all([
      getSecret(secretClient, 'OPENAI_API_KEY'),
      getSecret(secretClient, 'JWT_SECRET'),
      getSecret(secretClient, 'DB_PASSWORD')
    ]);

    openai = new OpenAI({ apiKey });
    jwtSecret = secret;

    pool = new Pool({
      user: process.env.DB_USER || 'postgres',
      password: dbPassword,
      database: process.env.DB_NAME || 'postgres',
      host: `/cloudsql/${process.env.CLOUDSQL_CONNECTION || 'aura-operations:southamerica-west1:aura-db-santiago'}`,
      max: 10
    });

    await pool.query('SELECT NOW()');
    console.log('[AuraBackend] Conexión a PostgreSQL verificada.');

    isReady = true;
    console.log('[AuraBackend] Plataforma operativa.');
  } catch (error) {
    console.error('[AuraBackend] Error crítico durante la inicialización:', error);
    isReady = false;
  }
}

// ---------------------------------------------------------------
// Middlewares
// ---------------------------------------------------------------

app.use((req, res, next) => {
  req.requestId = crypto.randomUUID();
  logWithContext(req.requestId, 'log', `--> ${req.method} ${req.originalUrl}`);
  next();
});

app.use((req, res, next) => {
  if (isReady) {
    return next();
  }
  res.status(503).json({ error: 'Servicio no disponible. Inicializando Aura Brain.' });
});

function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

  if (!token) {
    return res.status(401).json({ error: 'Token requerido.' });
  }

  jwt.verify(token, jwtSecret, (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: 'Token inválido.' });
    }
    req.user = decoded;
    next();
  });
}

// ---------------------------------------------------------------
// Rutas públicas
// ---------------------------------------------------------------

app.get('/health', (_, res) => {
  res.status(200).json({
    status: isReady ? 'healthy' : 'initializing',
    version: VERSION,
    timestamp: new Date().toISOString()
  });
});

app.post('/login', async (req, res) => {
  const requestId = req.requestId;
  logWithContext(requestId, 'log', 'Intento de login recibido.');

  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: 'Email y contraseña son requeridos.' });
  }

  try {
    const queryText = 'SELECT * FROM agents WHERE email = \$1';
    const { rows } = await pool.query(queryText, [email]);
    const agent = rows[0];

    if (!agent) {
      logWithContext(requestId, 'warn', 'Credenciales inválidas: agente no encontrado.', { email });
      return res.status(401).json({ error: 'Credenciales inválidas.' });
    }

    const isPasswordValid = await bcrypt.compare(password, agent.password_hash);
    if (!isPasswordValid) {
      logWithContext(requestId, 'warn', 'Credenciales inválidas: contraseña incorrecta.', { email });
      return res.status(401).json({ error: 'Credenciales inválidas.' });
    }

    const expiresIn = DEFAULT_TOKEN_TTL_HOURS * 3600;
    const expiresAt = new Date(Date.now() + expiresIn * 1000).toISOString();
    const payload = { userId: agent.id, email: agent.email };
    const token = jwt.sign(payload, jwtSecret, { expiresIn });

    logWithContext(requestId, 'log', 'Autenticación exitosa.', { email });

    res.status(200).json({
      status: 'SUCCESS',
      token,
      expiresIn,
      expiresAt,
      user: buildUserPayload(agent)
    });
  } catch (error) {
    logWithContext(requestId, 'error', 'Error crítico durante login.', { error: error.message });
    res.status(500).json({ error: 'Error interno del servidor.' });
  }
});

// ---------------------------------------------------------------
// Rutas protegidas
// ---------------------------------------------------------------

app.post('/auth/logout', authenticateToken, (req, res) => {
  logWithContext(req.requestId, 'log', 'Logout solicitado.', { user: req.user.email });
  res.status(200).json({ status: 'SUCCESS' });
});

app.get('/session', authenticateToken, (req, res) => {
  res.status(200).json({
    status: 'SUCCESS',
    user: req.user
  });
});

app.post('/intel/sweep', authenticateToken, async (req, res) => {
  const requestId = req.requestId;
  const runId = crypto.randomUUID();

  const history = sanitizeHistory(req.body?.history || []);
  const objectives = sanitizeObjectives(req.body?.objectives);
  const contextSnippet = typeof req.body?.context === 'string' ? req.body.context.trim() : '';
  const channel = typeof req.body?.channel === 'string' ? req.body.channel : 'general';

  if (history.length === 0 && !contextSnippet && objectives.length === 0) {
    return res.status(400).json({
      error: 'Se requiere al menos historia, contexto o objetivos para ejecutar el barrido.'
    });
  }

  try {
    const systemPrompt = [
      'Eres AURA, asistente táctico que analiza interacciones de soporte.',
      'Responde ÚNICAMENTE con JSON válido con la forma:',
      '{',
      '  "summary": string,',
      '  "insights": string[],',
      '  "recommendedActions": string[],',
      '  "risks": string[],',
      '  "confidence": number  // entre 0 y 1',
      '}',
      'Mantén el tono profesional y concreto.'
    ].join(' ');

    const objectiveBlock =
      objectives.length > 0 ? `Objetivos principales:\n- ${objectives.join('\n- ')}\n` : '';
    const contextBlock = contextSnippet ? `Contexto operacional adicional:\n${contextSnippet}\n` : '';

    const messages = [
      { role: 'system', content: systemPrompt },
      ...history,
      {
        role: 'user',
        content: [
          `Canal actual: ${channel}.`,
          objectiveBlock,
          contextBlock,
          'Ejecuta barrido y responde con JSON válido.'
        ]
          .filter(Boolean)
          .join('\n')
      }
    ];

    const completion = await openai.chat.completions.create({
      model: DEFAULT_MODEL,
      temperature: 0.4,
      max_tokens: 900,
      messages
    });

    const rawContent = completion.choices?.[0]?.message?.content;
    const parsed = extractJsonFromContent(rawContent);

    const responsePayload = {
      status: 'SUCCESS',
      runId,
      data: {
        summary: parsed.summary || null,
        insights: parsed.insights || [],
        recommendedActions: parsed.recommendedActions || [],
        risks: parsed.risks || []
      },
      confidence:
        typeof parsed.confidence === 'number'
          ? Math.max(0, Math.min(1, parsed.confidence))
          : null,
      usage: completion.usage || null,
      model: completion.model
    };

    res.status(200).json(responsePayload);

    await recordIntelRun({
      runId,
      userId: req.user.userId,
      type: 'SWEEP',
      payload: { history, objectives, contextSnippet, channel },
      result: responsePayload,
      totalTokens: completion.usage?.total_tokens || null,
      requestId
    });
  } catch (error) {
    logWithContext(requestId, 'error', 'Error durante INTELLIGENCE_SWEEP.', {
      error: error.message
    });
    res.status(500).json({ error: 'Error al ejecutar el barrido de inteligencia.' });
  }
});

app.post('/intel/command', authenticateToken, async (req, res) => {
  const requestId = req.requestId;
  const runId = crypto.randomUUID();

  const { command, args, context, history } = req.body || {};

  if (!command || typeof command !== 'string') {
    return res.status(400).json({ error: 'El campo "command" es requerido.' });
  }

  try {
    const normalizedHistory = sanitizeHistory(history || []);
    const argsBlock =
      args && typeof args === 'object'
        ? `Argumentos:\n${JSON.stringify(args, null, 2)}`
        : 'Sin argumentos adicionales.';

    const messages = [
      {
        role: 'system',
        content: [
          'Actúas como un oficial táctico AURA.',
          'Responde SOLO con JSON con la forma { "analysis": string, "result": any, "confidence": number, "nextSteps": string[] }.'
        ].join(' ')
      },
      ...normalizedHistory,
      {
        role: 'user',
        content: [
          `Comando solicitado: ${command}`,
          `Contexto operacional: ${context || 'No suministrado.'}`,
          argsBlock,
          'Responde con JSON válido.'
        ].join('\n')
      }
    ];

    const completion = await openai.chat.completions.create({
      model: DEFAULT_MODEL,
      temperature: 0.3,
      max_tokens: 600,
      messages
    });

    const rawContent = completion.choices?.[0]?.message?.content;
    const parsed = extractJsonFromContent(rawContent);

    const responsePayload = {
      status: 'SUCCESS',
      runId,
      data: parsed.result ?? parsed,
      meta: {
        analysis: parsed.analysis || null,
        confidence:
          typeof parsed.confidence === 'number'
            ? Math.max(0, Math.min(1, parsed.confidence))
            : null,
        nextSteps: parsed.nextSteps || []
      },
      usage: completion.usage || null,
      model: completion.model
    };

    res.status(200).json(responsePayload);

    await recordIntelRun({
      runId,
      userId: req.user.userId,
      type: 'COMMAND',
      payload: { command, args, context },
      result: responsePayload,
      totalTokens: completion.usage?.total_tokens || null,
      requestId
    });
  } catch (error) {
    logWithContext(requestId, 'error', 'Error durante API_CALL / command.', {
      error: error.message
    });
    res.status(500).json({ error: 'Error al ejecutar el comando solicitado.' });
  }
});

// ---------------------------------------------------------------
// Fallback & manejo de errores
// ---------------------------------------------------------------

app.post('/', authenticateToken, async (req, res) => {
  // Compatibilidad con versión anterior (chat libre)
  try {
    const history = sanitizeHistory(req.body?.history || []);
    if (history.length === 0) {
      return res.status(400).json({
        error: 'El campo "history" es requerido y debe tener al menos un mensaje.'
      });
    }

    const completion = await openai.chat.completions.create({
      model: DEFAULT_MODEL,
      temperature: 0.5,
      messages: history
    });

    res.status(200).json({
      status: 'SUCCESS',
      result: completion.choices?.[0]?.message?.content || ''
    });
  } catch (error) {
    logWithContext(req.requestId, 'error', 'Error en endpoint legacy "/"', {
      error: error.message
    });
    res.status(500).json({ error: 'Error interno en el backend.' });
  }
});

app.use((req, res) => {
  res.status(404).json({ error: 'Ruta no encontrada.' });
});

app.use((err, req, res, _next) => {
  logWithContext(req.requestId || 'unknown', 'error', 'Error no controlado.', {
    error: err.message,
    stack: err.stack
  });
  res.status(err.status || 500).json({ error: err.message || 'Error interno.' });
});

// ---------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------

const PORT = process.env.PORT || 8080;

initializeSecureServices().then(() => {
  if (!isReady) {
    console.error('[AuraBackend] Inicio abortado: servicios seguros no disponibles.');
    process.exit(1);
  }

  app.listen(PORT, () => {
    console.log(`[AuraBackend] v${VERSION} escuchando en puerto ${PORT}`);
  });
});

// ---------------------------------------------------------------
// Export opcional (Cloud Functions / tests unitarios)
// ---------------------------------------------------------------
// module.exports = app;