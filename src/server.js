import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import { v4 as uuid } from "uuid";
import {
  adjustUserCredits,
  ensureDatabase,
  findUserByEmail,
  findUserById,
  getUserCredits,
  getUsers,
  insertUser
} from "./storage.js";

dotenv.config();

const app = express();
const PORT = process.env.PORT ? Number(process.env.PORT) : 9000;
const DEBUG = String(process.env.DEBUG || '').toLowerCase() === 'true';
const INTERNAL_SERVICE_TOKEN = process.env.INTERNAL_SERVICE_TOKEN;

// Log de diagnóstico (sem expor senha)
if (DEBUG) {
  try {
    const redacted = (process.env.MONGODB_URL || '').replace(/:\w+@/, ':****@');
    console.log('[DB] URL:', redacted);
    console.log('[DB] DB_NAME:', process.env.MONGODB_DB_NAME);
  } catch {}
}

// CORS robusto: aceita lista de origens ou wildcard.
const defaultOrigins = [
  "http://localhost:5173",
  "http://127.0.0.1:5173",
  "http://localhost:3000",
  "http://127.0.0.1:3000",
  "http://localhost:6173",
  "http://127.0.0.1:6173",
  "http://localhost:9000",
  "http://127.0.0.1:9000"
];

function parseEnvOrigins(value) {
  if (!value) return [];
  const raw = String(value).trim();
  if (!raw) return [];

  if (raw.startsWith("[") && raw.endsWith("]")) {
    try {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) {
        return parsed.filter((entry) => typeof entry === "string");
      }
      if (typeof parsed === "string") {
        return [parsed];
      }
    } catch (err) {
      console.warn("[CORS] Não foi possível interpretar CORS_ORIGINS como JSON:", err?.message || err);
      return [];
    }
  }

  return raw
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function normalizeOriginStr(o) {
  if (!o) return "";
  let s = String(o).trim();
  if (s === "*") return "*";
  s = s.replace(/^['"]|['"]$/g, "");
  if (/^https?:[^/]/i.test(s)) {
    s = s.replace(/^https?:/i, (m) => `${m}//`);
  }
  if (!/^https?:\/\//i.test(s)) {
    s = `http://${s}`;
  }
  if (s.endsWith("/")) s = s.slice(0, -1);
  return s;
}

const envOriginsRaw = parseEnvOrigins(process.env.CORS_ORIGINS);

function addOrigin(list, origin) {
  if (!origin || origin === "*") {
    return;
  }
  if (!list.includes(origin)) {
    list.push(origin);
  }
}

let allowedOrigins = (envOriginsRaw.length ? envOriginsRaw : defaultOrigins)
  .map(normalizeOriginStr)
  .filter(Boolean);

const frontendBase = normalizeOriginStr(process.env.FRONTEND_BASE_URL);
if (frontendBase) {
  addOrigin(allowedOrigins, frontendBase);
  if (frontendBase.startsWith("http://localhost:")) {
    addOrigin(
      allowedOrigins,
      frontendBase.replace("http://localhost:", "http://127.0.0.1:")
    );
  }
}

const allowAll = allowedOrigins.includes("*");

const corsOptions = {
  origin: allowAll
    ? function (origin, callback) {
        return callback(null, true);
      }
    : function (origin, callback) {
        // Sem header Origin (curl, server-to-server) libera
        if (!origin) return callback(null, true);
        const normalized = normalizeOriginStr(origin);
        if (allowedOrigins.includes(normalized)) return callback(null, true);
        return callback(new Error("Not allowed by CORS"), false);
      },
  credentials: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: [
    "Content-Type",
    "Authorization",
    "X-Requested-With",
    "Accept"
  ],
  optionsSuccessStatus: 204
};

app.use(cors(corsOptions));
app.options("*", cors(corsOptions));
app.use(express.json());

app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

function sanitizeUser(user) {
  return {
    id: user.id,
    email: user.email,
    username: user.username,
    credits: Number(user.credits ?? 0),
    createdAt: user.createdAt
  };
}

function requireServiceAuth(req, res, next) {
  if (!INTERNAL_SERVICE_TOKEN) {
    return res.status(503).json({ message: "INTERNAL_SERVICE_TOKEN não configurado" });
  }
  const headerToken = req.header("x-service-token");
  if (!headerToken || headerToken !== INTERNAL_SERVICE_TOKEN) {
    return res.status(403).json({ message: "Acesso negado" });
  }
  return next();
}

app.get("/auth/users", async (req, res) => {
  const users = await getUsers();
  res.json({ users: users.map(sanitizeUser) });
});

app.get("/auth/users/:id", async (req, res) => {
  const user = await findUserById(req.params.id);
  if (!user) {
    return res.status(404).json({ message: "Usuário não encontrado" });
  }
  return res.json({ user: sanitizeUser(user) });
});

app.post("/auth/register", async (req, res) => {
  const { email, password, username } = req.body ?? {};

  if (!email || !password || !username) {
    return res.status(400).json({ message: "email, username e password são obrigatórios" });
  }

  const emailNormalized = String(email).trim().toLowerCase();
  const usernameNormalized = String(username).trim();

  if (!emailNormalized.includes("@")) {
    return res.status(400).json({ message: "Forneça um email válido" });
  }

  if (password.length < 6) {
    return res.status(400).json({ message: "A senha deve ter pelo menos 6 caracteres" });
  }

  const existing = await findUserByEmail(emailNormalized);
  if (existing) {
    return res.status(409).json({ message: "Email já cadastrado" });
  }

  const passwordHash = await bcrypt.hash(password, 12);

  const user = {
    id: `user-${uuid()}`,
    email: emailNormalized,
    username: usernameNormalized,
    passwordHash,
    nexusApiKeyHash: passwordHash,
    credits: 0,
    createdAt: new Date().toISOString()
  };

  await insertUser(user);

  return res.status(201).json({ user: sanitizeUser(user) });
});

app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body ?? {};

  if (!email || !password) {
    return res.status(400).json({ message: "email e password são obrigatórios" });
  }

  const emailNormalized = String(email).trim().toLowerCase();
  const user = await findUserByEmail(emailNormalized);

  if (!user) {
    return res.status(401).json({ message: "Credenciais inválidas" });
  }

  const isPasswordValid = await bcrypt.compare(password, user.passwordHash);

  if (!isPasswordValid) {
    return res.status(401).json({ message: "Credenciais inválidas" });
  }

  return res.json({
    user: sanitizeUser(user),
    nexusApi: {
      // Campo informativo para reforçar a ligação entre senha e chave de API.
      keySyncedWithPassword: true
    }
  });
});

app.get("/internal/users/:id/credits", requireServiceAuth, async (req, res) => {
  try {
    const summary = await getUserCredits(req.params.id);
    return res.json(summary);
  } catch (error) {
    if (error.code === "USER_NOT_FOUND") {
      return res.status(404).json({ message: "Usuário não encontrado" });
    }
    console.error("Erro ao buscar créditos:", error);
    return res.status(500).json({ message: "Erro ao buscar créditos do usuário" });
  }
});

app.post("/internal/users/:id/credits", requireServiceAuth, async (req, res) => {
  const { amount, operation = "credit", reference, reason, metadata } = req.body ?? {};

  if (typeof amount !== "number" || !Number.isFinite(amount) || amount <= 0) {
    return res.status(400).json({ message: "Campo 'amount' deve ser um número positivo" });
  }

  const normalizedOperation = String(operation).toLowerCase();
  const delta = normalizedOperation === "debit" || normalizedOperation === "subtract" ? -amount : amount;

  try {
    const result = await adjustUserCredits(req.params.id, delta, {
      reference,
      reason,
      metadata
    });
    return res.json({
      userId: req.params.id,
      credits: result.credits,
      duplicated: Boolean(result.duplicated)
    });
  } catch (error) {
    if (error.code === "USER_NOT_FOUND") {
      return res.status(404).json({ message: "Usuário não encontrado" });
    }
    if (error.code === "INSUFFICIENT_FUNDS") {
      return res.status(422).json({
        message: "Saldo insuficiente para debitar créditos",
        details: error.details
      });
    }
    if (error.code === "INVALID_DELTA") {
      return res.status(400).json({ message: "Operação de crédito inválida" });
    }
    console.error("Erro ao atualizar créditos:", error);
    return res.status(500).json({ message: "Erro ao atualizar créditos do usuário" });
  }
});

app.use((req, res) => {
  res.status(404).json({ message: "Rota não encontrada" });
});

async function bootstrap() {
  await ensureDatabase();
  app.listen(PORT, () => {
    console.log(`Auth server rodando na porta ${PORT}`);
  });
}

bootstrap().catch((error) => {
  console.error("Erro ao iniciar backendAuth", error);
  if (error && (error.code === 8000 || /Authentication failed/i.test(String(error)))) {
    console.error('\nDica: Falha de autenticação no Atlas. Verifique:');
    console.error('- Usuário e senha (gere nova senha em Database Access)');
    console.error('- Se a connection string contém &authSource=admin');
    console.error('- Se o IP está liberado em Network Access');
  }
  process.exit(1);
});
