// server.js
import dotenv from "dotenv";
dotenv.config();

import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { MongoClient, ServerApiVersion, ObjectId } from "mongodb";
import admin from "firebase-admin";
import Stripe from "stripe";
import { createRequire } from "module";
import cron from "node-cron";
const require = createRequire(import.meta.url);

const serviceAccount = require("./src/data/assignment11-b015f-firebase-adminsdk-fbsvc-c82e843442.json");
// ---------- Environment ----------
const {
    MONGODB_URI,
    PORT = 5000,
    STRIPE_SECRET_KEY
} = process.env;

if (!MONGODB_URI) throw new Error("MONGODB_URI is missing");
if (!STRIPE_SECRET_KEY) throw new Error("STRIPE_SECRET_KEY is missing");

// ---------- Stripe ----------
const stripe = new Stripe(STRIPE_SECRET_KEY);

// ---------- Firebase ----------
try {
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
    });
} catch (err) {
    console.error("Firebase Admin init failed", err);
    process.exit(1);
}

// ---------- Express ----------
const app = express();
app.use(helmet());
app.use(express.json({ limit: "10mb" }));

// Rate limiter
app.use(rateLimit({
    windowMs: 60 * 1000,
    max: 120,
    standardHeaders: true,
    legacyHeaders: false,
}));

// CORS
const allowedOrigins = [
    "http://localhost:5173",
    "https://assignment11-b015f.web.app"
];
app.use(cors({ origin: allowedOrigins, credentials: true }));

// ---------- MongoDB ----------
const client = new MongoClient(MONGODB_URI, { serverApi: { version: ServerApiVersion.v1 } });
let db, usersCollection, foodCollection, foodRequestCollection, paymentCollection;

async function connectDB() {
    await client.connect();
    console.log("Connected to MongoDB");

    db = client.db("foodshare");

    usersCollection = db.collection("users");
    foodCollection = db.collection("food");
    foodRequestCollection = db.collection("requestedfoods");
    paymentCollection = db.collection("payments");
}
connectDB().catch(err => {
    console.error("MongoDB connection failed:", err);
    process.exit(1);
});

// ---------- Firebase Token Verification ----------
const verifyToken = async (req, res, next) => {
    const authHeader = req.headers.authorization || "";
    if (!authHeader.startsWith("Bearer ")) return res.status(401).json({ error: "No token" });
    const token = authHeader.split(" ")[1];
    try {
        const decoded = await admin.auth().verifyIdToken(token);
        req.decoded = decoded;
        next();
    } catch (err) {
        console.error("Token verification failed:", err);
        res.status(403).json({ error: "Invalid token" });
    }
};

cron.schedule("0 0 * * *", async () => {
    try {
        const today = new Date();

        // Update all foods where expiredDateTime < today and status is "available"
        const result = await foodCollection.updateMany(
            { expiredDateTime: { $lt: today }, foodStatus: "available" },
            { $set: { foodStatus: "unavailable" } }
        );

        console.log(`[Cron] Updated ${result.modifiedCount} expired foods to unavailable`);
    } catch (err) {
        console.error("[Cron] Error updating expired foods:", err);
    }
});

// ---------- Routes ----------

app.get("/", (req, res) => res.send({ status: "ok", message: "FoodShare API running" }));

// --- Users ---
app.post("/users", async (req, res) => {
    try {
        const { email, name, photourl, membership = "no" } = req.body;
        if (!email) return res.status(400).json({ error: "Email is required" });

        const result = await usersCollection.updateOne(
            { email },
            { $setOnInsert: { email, membership }, $set: { name, photourl } },
            { upsert: true }
        );
        res.json({ result });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get("/users", async (req, res) => {
    try {
        const users = await usersCollection.find().toArray();
        res.json(users);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.patch("/users/membership/:email", async (req, res) => {
    try {
        const email = req.params.email;
        const result = await usersCollection.updateOne({ email }, { $set: { membership: "yes" } });
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- Food Routes ---
app.post("/food", async (req, res) => {
    try {
        const { donorEmail, foodName } = req.body;
        if (!donorEmail || !foodName) return res.status(400).json({ error: "donorEmail and foodName required" });

        const data = { ...req.body, createdAt: new Date() };
        const result = await foodCollection.insertOne(data);
        res.status(201).json({ insertedId: result.insertedId });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get("/food", async (req, res) => {
    try {
        const search = req.query.search || "";
        const sortOrder = req.query.sortOrder === "asc" ? 1 : -1;

        // Fetch only available and non-expired foods
        const filter = {
            foodStatus: "available",
            expiredDateTime: { $gt: new Date() },
            foodName: { $regex: search, $options: "i" },
        };

        const foods = await foodCollection.find(filter).sort({ expiredDateTime: sortOrder }).toArray();
        res.json(foods);
    } catch (err) {
        console.error("Error fetching foods:", err);
        res.status(500).json({ error: err.message });
    }
});




app.get("/food/:id", async (req, res) => {
    try {
        const food = await foodCollection.findOne({ _id: new ObjectId(req.params.id) });
        if (!food) return res.status(404).json({ error: "Food not found" });
        res.json(food);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put("/food/:id", async (req, res) => {
    try {
        const result = await foodCollection.updateOne({ _id: new ObjectId(req.params.id) }, { $set: req.body });
        if (result.matchedCount === 0) return res.status(404).json({ error: "Food not found" });
        res.json({ message: "Food updated", result });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.patch("/food/:id", async (req, res) => {
    try {
        const { foodStatus } = req.body;
        const result = await foodCollection.updateOne(
            { _id: new ObjectId(req.params.id) },
            { $set: { foodStatus: foodStatus || "requested" } }
        );
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get("/food/count/:email", async (req, res) => {
    try {
        const count = await foodCollection.countDocuments({ donorEmail: req.params.email });
        res.json({ count });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get("/manage-food", verifyToken, async (req, res) => {
    try {
        const donorEmail = req.query.email;
        if (donorEmail !== req.decoded.email) return res.status(403).json({ error: "Forbidden" });
        const foods = await foodCollection.find({ donorEmail }).toArray();
        res.json(foods);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- Food Requests ---
app.post("/requestedfoods", async (req, res) => {
    try {
        const data = { ...req.body, requestedAt: new Date() };
        const result = await foodRequestCollection.insertOne(data);
        res.status(201).json({ insertedId: result.insertedId });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get("/myfoodrequest", verifyToken, async (req, res) => {
    try {
        const userEmail = req.query.email;
        if (userEmail !== req.decoded.email) return res.status(403).json({ error: "Forbidden" });
        const requests = await foodRequestCollection.find({ userEmail }).toArray();
        res.json(requests);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ---------- Payments ----------

app.post("/create-payment-intent", async (req, res) => {
    try {
        const { price } = req.body;
        if (!price || price <= 0) return res.status(400).json({ error: "Invalid price" });

        const paymentIntent = await stripe.paymentIntents.create({
            amount: Math.round(price * 100),
            currency: "usd",
            automatic_payment_methods: { enabled: true },
        });

        res.json({ clientSecret: paymentIntent.client_secret });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post("/payments", async (req, res) => {
    try {
        const { email, amount, transactionId, status, date } = req.body;
        if (!email || !amount || !transactionId || !status) return res.status(400).json({ error: "Missing payment data" });

        const data = { email, amount, transactionId, status, date: date || new Date() };
        const result = await paymentCollection.insertOne(data);
        res.status(201).json({ insertedId: result.insertedId });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ---------- Start server ----------
app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
