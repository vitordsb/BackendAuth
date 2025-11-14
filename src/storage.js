import { MongoClient } from "mongodb";

let client;
let database;
let usersCollection;
let creditsHistoryCollection;

function getConfig() {
  const url = process.env.MONGODB_URL || "mongodb+srv://vitordsb:988685156qazwsx@cluster0.18jfmha.mongodb.net/?appName=Cluster0";
  if (!url) {
    throw new Error("MONGODB_URL não configurada nas variáveis de ambiente.");
  }
  const dbName = process.env.MONGODB_DB_NAME || "nexuspi";
  if (!dbName) {
    throw new Error("MONGODB_DB_NAME não configurada nas variáveis de ambiente.");
  }
  const collection = process.env.DB_COLLECTION || "users";
  const creditsHistory = process.env.DB_CREDITS_HISTORY_COLLECTION || "user_credits_history";
  return { url, dbName, collection, creditsHistory };
}

async function getClient() {
  const { url, dbName, collection, creditsHistory } = getConfig();

  if (!client) {
    client = new MongoClient(url, {
      serverApi: {
        version: "1",
        strict: true,
        deprecationErrors: true
      }
    });
    await client.connect();
    database = client.db(dbName);
    usersCollection = database.collection(collection);
    creditsHistoryCollection = database.collection(creditsHistory);

    await usersCollection.createIndex({ email: 1 }, { unique: true });
    await usersCollection.createIndex({ id: 1 }, { unique: true });
    await usersCollection.createIndex(
      { resetTokenHash: 1 },
      { sparse: true, expireAfterSeconds: 0 }
    );
    await creditsHistoryCollection.createIndex({ userId: 1, createdAt: -1 });
    await creditsHistoryCollection.createIndex(
      { reference: 1 },
      {
        unique: true,
        partialFilterExpression: { reference: { $type: "string" } }
      }
    );
  }
  return client;
}

async function getUsersCollection() {
  if (!usersCollection) {
    await getClient();
  }
  return usersCollection;
}

async function getCreditsHistoryCollection() {
  if (!creditsHistoryCollection) {
    await getClient();
  }
  return creditsHistoryCollection;
}

export async function ensureDatabase() {
  await getClient();
}

export async function getUsers() {
  const collection = await getUsersCollection();
  return collection
    .find({}, { projection: { _id: 0, passwordHash: 0, nexusApiKeyHash: 0 } })
    .sort({ createdAt: -1 })
    .toArray();
}

export async function findUserByEmail(email) {
  const collection = await getUsersCollection();
  return collection.findOne({ email: email.toLowerCase() });
}

export async function findUserById(id) {
  const collection = await getUsersCollection();
  return collection.findOne({ id });
}

export async function insertUser(user) {
  const collection = await getUsersCollection();
  await collection.insertOne(user);
  return user;
}

export async function adjustUserCredits(userId, delta, options = {}) {
  const numericDelta = Number(delta);
  if (!Number.isFinite(numericDelta) || numericDelta === 0) {
    const error = new Error("Delta de créditos inválido");
    error.code = "INVALID_DELTA";
    throw error;
  }
  const collection = await getUsersCollection();
  const history = await getCreditsHistoryCollection();
  const user = await collection.findOne({ id: userId });

  if (!user) {
    const error = new Error("Usuário não encontrado");
    error.code = "USER_NOT_FOUND";
    throw error;
  }

  const reference = options.reference ? String(options.reference) : null;
  if (reference) {
    const alreadyProcessed = await history.findOne({ userId, reference });
    if (alreadyProcessed) {
      return {
        credits: Number(user.credits ?? 0),
        duplicated: true,
        transaction: alreadyProcessed
      };
    }
  }

  const currentCredits = Number(user.credits ?? 0);
  const newBalance = currentCredits + numericDelta;
  if (newBalance < 0) {
    const error = new Error("Saldo insuficiente");
    error.code = "INSUFFICIENT_FUNDS";
    error.details = {
      requested: numericDelta,
      currentCredits
    };
    throw error;
  }

  const timestamp = new Date().toISOString();

  await collection.updateOne(
    { id: userId },
    {
      $set: {
        credits: newBalance,
        updatedAt: timestamp
      }
    }
  );

  const transaction = {
    userId,
    direction: numericDelta >= 0 ? "credit" : "debit",
    amount: Math.abs(numericDelta),
    balanceAfter: newBalance,
    reference,
    reason: options.reason ?? null,
    metadata: options.metadata ?? null,
    createdAt: timestamp
  };

  const insertResult = await history.insertOne(transaction);
  transaction._id = insertResult.insertedId;

  return {
    credits: newBalance,
    transaction
  };
}

export async function getUserCredits(userId) {
  const collection = await getUsersCollection();
  const user = await collection.findOne(
    { id: userId },
    { projection: { credits: 1, id: 1 } }
  );
  if (!user) {
    const error = new Error("Usuário não encontrado");
    error.code = "USER_NOT_FOUND";
    throw error;
  }
  return {
    userId: user.id,
    credits: Number(user.credits ?? 0)
  };
}

export async function listUserCreditsHistory(userId, { limit = 50 } = {}) {
  const history = await getCreditsHistoryCollection();
  const numericLimit = Number(limit);
  const appliedLimit =
    Number.isFinite(numericLimit) && numericLimit > 0 ? Math.min(200, numericLimit) : 50;
  return history
    .find({ userId }, { projection: { _id: 1, userId: 1, direction: 1, amount: 1, balanceAfter: 1, reference: 1, reason: 1, metadata: 1, createdAt: 1 } })
    .sort({ createdAt: -1 })
    .limit(appliedLimit)
    .toArray();
}

export async function storePasswordResetToken(userId, tokenHash, expiresAt) {
  const collection = await getUsersCollection();
  const expiresDate = expiresAt instanceof Date ? expiresAt : new Date(expiresAt);
  await collection.updateOne(
    { id: userId },
    {
      $set: {
        resetTokenHash: tokenHash,
        resetTokenExpiresAt: expiresDate
      }
    }
  );
}

export async function findUserByResetToken(email, tokenHash) {
  const collection = await getUsersCollection();
  return collection.findOne({
    email: email.toLowerCase(),
    resetTokenHash: tokenHash,
    resetTokenExpiresAt: { $gt: new Date() }
  });
}

export async function updateUserPasswordHash(userId, passwordHash) {
  const collection = await getUsersCollection();
  const timestamp = new Date().toISOString();
  await collection.updateOne(
    { id: userId },
    {
      $set: {
        passwordHash,
        nexusApiKeyHash: passwordHash,
        updatedAt: timestamp
      },
      $unset: {
        resetTokenHash: "",
        resetTokenExpiresAt: ""
      }
    }
  );
}

export async function disconnectDatabase() {
  if (client) {
    await client.close();
    client = null;
    database = null;
    usersCollection = null;
    creditsHistoryCollection = null;
  }
}
