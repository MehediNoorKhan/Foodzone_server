import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { MongoClient, ServerApiVersion, ObjectId } from "mongodb";
import admin from "firebase-admin";
import Stripe from "stripe";

// ---------- Environment ----------
const { MONGODB_URI, STRIPE_SECRET_KEY, FB_SERVICE_KEY } = process.env;

if (!MONGODB_URI) throw new Error("MONGODB_URI is missing");
if (!STRIPE_SECRET_KEY) throw new Error("STRIPE_SECRET_KEY is missing");
if (!FB_SERVICE_KEY) throw new Error("FB_SERVICE_KEY is missing");

// ---------- Firebase Admin ----------
let serviceAccount;
try {
    serviceAccount = JSON.parse(Buffer.from(FB_SERVICE_KEY, "base64").toString("utf8"));
} catch (err) {
    console.error("Invalid Firebase Key", err);
    throw new Error("FB_SERVICE_KEY is invalid");
}

if (!admin.apps.length) {
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
    });
    console.log("✅ Firebase Admin Initialized");
}

// ---------- Stripe ----------
const stripe = new Stripe(STRIPE_SECRET_KEY);

// ---------- Express ----------
const app = express();
app.use(helmet());

// ---------- CORS ----------
const allowedOrigins = [
    "http://localhost:5173",
    "https://your-vercel-frontend.vercel.app",
    "https://assignment11-b015f.web.app",
    "https://assignment11-b015f.firebaseapp.com"
];
app.use(cors({
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
        callback(new Error("Not allowed by CORS"));
    },
    credentials: true
}));

app.use(express.json({ limit: "10mb" }));
app.use(rateLimit({ windowMs: 60 * 1000, max: 120 }));

// ---------- MongoDB Lazy Connection ----------
let cachedClient = global._mongoClient;
let cachedDb = global._mongoDb;

async function connectDB() {
    if (cachedClient && cachedDb) return { client: cachedClient, db: cachedDb };

    const client = new MongoClient(MONGODB_URI, { serverApi: { version: ServerApiVersion.v1, strict: true } });
    await client.connect();
    const db = client.db("foodshare");

    cachedClient = client;
    cachedDb = db;
    global._mongoClient = client;
    global._mongoDb = db;

    return { client, db };
}

// ---------- Firebase Token Middleware ----------
async function verifyToken(req, res, next) {
    const authHeader = req.headers.authorization || "";
    if (!authHeader.startsWith("Bearer ")) return res.status(401).json({ error: "No token provided" });
    try {
        const decoded = await admin.auth().verifyIdToken(authHeader.split(" ")[1]);
        req.decoded = decoded;
        next();
    } catch (err) {
        return res.status(403).json({ error: "Invalid or expired token" });
    }
}

// ---------- Routes ----------

// Health Check
app.get("/", (req, res) => res.json({ status: "ok", message: "FoodShare API Running" }));

// --- Users ---
app.post("/users", async (req, res) => {
    const { db } = await connectDB();
    const usersCollection = db.collection("users");
    const { email, name, photourl, membership = "no" } = req.body;

    const result = await usersCollection.updateOne(
        { email },
        { $setOnInsert: { email, membership, createdAt: new Date() }, $set: { name, photourl, updatedAt: new Date() } },
        { upsert: true }
    );

    res.json({ success: true, upserted: result.upsertedCount > 0 });
});

app.get("/users", async (req, res) => {
    const { db } = await connectDB();
    const users = await db.collection("users").find().toArray();
    res.json(users);
});

app.get("/users/:email", async (req, res) => {
    const { db } = await connectDB();
    const usersCollection = db.collection("users");
    const user = await usersCollection.findOne({ email: req.params.email });
    user ? res.json(user) : res.status(404).json({ error: "User not found" });
});

app.patch("/users/membership/:email", async (req, res) => {
    const { db } = await connectDB();
    const usersCollection = db.collection("users");
    const result = await usersCollection.updateOne(
        { email: req.params.email },
        { $set: { membership: "yes", membershipUpdatedAt: new Date() } }
    );
    result.matchedCount === 0 ? res.status(404).json({ error: "User not found" }) : res.json({ success: true });
});

// --- Food ---
app.post("/food", async (req, res) => {
    const { db } = await connectDB();
    const foodCollection = db.collection("food");
    const data = { ...req.body, createdAt: new Date(), foodStatus: "available" };
    const result = await foodCollection.insertOne(data);
    res.status(201).json({ success: true, insertedId: result.insertedId });
});

app.get("/food", async (req, res) => {
    const { db } = await connectDB();
    const foodCollection = db.collection("food");
    const search = req.query.search || "";
    const sort = req.query.sortOrder === "asc" ? 1 : -1;

    const foods = await foodCollection
        .find({ foodStatus: "available", expiredDateTime: { $gt: new Date() }, ...(search && { foodName: { $regex: search, $options: "i" } }) })
        .sort({ expiredDateTime: sort })
        .toArray();

    res.json(foods);
});

app.get("/food/:id", async (req, res) => {
    const { db } = await connectDB();
    const foodCollection = db.collection("food");

    if (!ObjectId.isValid(req.params.id)) return res.status(400).json({ error: "Invalid ID" });
    const food = await foodCollection.findOne({ _id: new ObjectId(req.params.id) });
    food ? res.json(food) : res.status(404).json({ error: "Food not found" });
});

app.put("/food/:id", async (req, res) => {
    const { db } = await connectDB();
    const foodCollection = db.collection("food");
    const { _id, ...updateData } = req.body;
    updateData.updatedAt = new Date();
    const result = await foodCollection.updateOne({ _id: new ObjectId(req.params.id) }, { $set: updateData });
    res.json({ success: true, result });
});

// --- Food Requests ---
app.post("/requestedfoods", async (req, res) => {
    const { db } = await connectDB();
    const foodRequestCollection = db.collection("requestedfoods");
    const result = await foodRequestCollection.insertOne({ ...req.body, requestedAt: new Date(), status: "pending" });
    res.json({ success: true, insertedId: result.insertedId });
});

app.get("/myfoodrequest", verifyToken, async (req, res) => {
    const { db } = await connectDB();
    const foodRequestCollection = db.collection("requestedfoods");
    const requests = await foodRequestCollection.find({ userEmail: req.decoded.email }).sort({ requestedAt: -1 }).toArray();
    res.json(requests);
});

// --- Payments ---
app.post("/create-payment-intent", async (req, res) => {
    const { price } = req.body;
    const paymentIntent = await stripe.paymentIntents.create({ amount: Math.round(price * 100), currency: "usd", automatic_payment_methods: { enabled: true } });
    res.json({ clientSecret: paymentIntent.client_secret });
});

app.post("/payments", async (req, res) => {
    const { db } = await connectDB();
    const paymentCollection = db.collection("payments");
    const result = await paymentCollection.insertOne({ ...req.body, createdAt: new Date() });
    res.json({ success: true, insertedId: result.insertedId });
});

// --- 404 ---
app.use("*", (_, res) => res.status(404).json({ error: "Route not found" }));

// ✅ Export for Vercel
export default app;
