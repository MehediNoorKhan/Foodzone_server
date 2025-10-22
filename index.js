// server.js
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const admin = require("firebase-admin");
const Stripe = require("stripe");

// ---------- Environment ----------
const {
    MONGODB_URI,
    PORT = 5000,
    STRIPE_SECRET_KEY
} = process.env;

if (!MONGODB_URI) throw new Error("MONGODB_URI is missing");
if (!STRIPE_SECRET_KEY) throw new Error("STRIPE_SECRET_KEY is missing");

// ---------- Stripe ----------
const stripe = Stripe(STRIPE_SECRET_KEY);

// ---------- Firebase ----------
try {
    const serviceAccount = require("./assignment11-b015f-firebase-adminsdk-fbsvc-c82e843442.json");
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

    // Ensure collections exist
    usersCollection = db.collection("users");
    foodCollection = db.collection("food");
    foodRequestCollection = db.collection("requestedfoods");
    paymentCollection = db.collection("payments"); // optional, not created yet
}

connectDB().catch(err => {
    console.error("MongoDB connection failed:", err);
    process.exit(1);
});

// ---------- Firebase token verification ----------
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

// ---------- Routes ----------
// Root
app.get("/", (req, res) => res.send({ status: "ok", message: "FoodShare API running" }));

// --- Users ---
// Upsert user
app.post("/users", async (req, res) => {
    try {
        if (!usersCollection) return res.status(500).json({ error: "Users collection not ready" });
        const { email, name, photourl, membership = "no" } = req.body;
        if (!email) return res.status(400).json({ error: "Email is required" });

        const result = await usersCollection.updateOne(
            { email },
            { $setOnInsert: { email, membership }, $set: { name, photourl } },
            { upsert: true }
        );
        res.status(200).json({ result });
    } catch (err) {
        console.error("POST /users error:", err);
        res.status(500).json({ error: err.message });
    }
});

// Get all users
app.get("/users", async (req, res) => {
    try {
        if (!usersCollection) return res.status(500).json({ error: "Users collection not ready" });
        const users = await usersCollection.find().toArray();
        res.json(users);
    } catch (err) {
        console.error("GET /users error:", err);
        res.status(500).json({ error: err.message });
    }
});

// Update membership
app.patch("/users/membership/:email", async (req, res) => {
    try {
        if (!usersCollection) return res.status(500).json({ error: "Users collection not ready" });
        const email = req.params.email;
        if (!email) return res.status(400).json({ error: "Email param required" });

        const result = await usersCollection.updateOne({ email }, { $set: { membership: "yes" } });
        res.json(result);
    } catch (err) {
        console.error("PATCH /users/membership error:", err);
        res.status(500).json({ error: err.message });
    }
});

// --- Food ---
// Add food
app.post("/food", async (req, res) => {
    try {
        if (!foodCollection) return res.status(500).json({ error: "Food collection not ready" });
        const { donorEmail, foodName } = req.body;
        if (!donorEmail || !foodName) return res.status(400).json({ error: "donorEmail and foodName required" });

        const data = { ...req.body, createdAt: new Date() };
        const result = await foodCollection.insertOne(data);
        res.status(201).json({ insertedId: result.insertedId });
    } catch (err) {
        console.error("POST /food error:", err);
        res.status(500).json({ error: err.message });
    }
});

// Get foods (search + sort)
app.get("/food", async (req, res) => {
    try {
        if (!foodCollection) return res.status(500).json({ error: "Food collection not ready" });
        const search = req.query.search || "";
        const sortOrder = req.query.sortOrder === "asc" ? 1 : -1;
        const filter = { foodStatus: "available", foodName: { $regex: search, $options: "i" } };
        const foods = await foodCollection.find(filter).sort({ expiredDateTime: sortOrder }).toArray();
        res.json(foods);
    } catch (err) {
        console.error("GET /food error:", err);
        res.status(500).json({ error: err.message });
    }
});

// Get single food
app.get("/food/:id", async (req, res) => {
    try {
        if (!foodCollection) return res.status(500).json({ error: "Food collection not ready" });
        const food = await foodCollection.findOne({ _id: new ObjectId(req.params.id) });
        if (!food) return res.status(404).json({ error: "Food not found" });
        res.json(food);
    } catch (err) {
        console.error("GET /food/:id error:", err);
        res.status(500).json({ error: err.message });
    }
});

// Update food
app.put("/food/:id", async (req, res) => {
    try {
        if (!foodCollection) return res.status(500).json({ error: "Food collection not ready" });
        const result = await foodCollection.updateOne({ _id: new ObjectId(req.params.id) }, { $set: req.body });
        if (result.matchedCount === 0) return res.status(404).json({ error: "Food not found" });
        res.json({ message: "Food updated", result });
    } catch (err) {
        console.error("PUT /food/:id error:", err);
        res.status(500).json({ error: err.message });
    }
});

// Patch food status
app.patch("/food/:id", async (req, res) => {
    try {
        if (!foodCollection) return res.status(500).json({ error: "Food collection not ready" });
        const { foodStatus } = req.body;
        const result = await foodCollection.updateOne(
            { _id: new ObjectId(req.params.id) },
            { $set: { foodStatus: foodStatus || "requested" } }
        );
        res.json(result);
    } catch (err) {
        console.error("PATCH /food/:id error:", err);
        res.status(500).json({ error: err.message });
    }
});

// Count foods by donor
app.get("/food/count/:email", async (req, res) => {
    try {
        if (!foodCollection) return res.status(500).json({ error: "Food collection not ready" });
        const count = await foodCollection.countDocuments({ donorEmail: req.params.email });
        res.json({ count });
    } catch (err) {
        console.error("GET /food/count/:email error:", err);
        res.status(500).json({ error: err.message });
    }
});

// Protected: manage foods by donor
app.get("/manage-food", verifyToken, async (req, res) => {
    try {
        if (!foodCollection) return res.status(500).json({ error: "Food collection not ready" });
        const donorEmail = req.query.email;
        if (donorEmail !== req.decoded.email) return res.status(403).json({ error: "Forbidden" });

        const foods = await foodCollection.find({ donorEmail }).toArray();
        res.json(foods);
    } catch (err) {
        console.error("GET /manage-food error:", err);
        res.status(500).json({ error: err.message });
    }
});

// --- Food Requests ---
app.post("/requestedfoods", async (req, res) => {
    try {
        if (!foodRequestCollection) return res.status(500).json({ error: "Requested foods collection not ready" });
        const data = { ...req.body, requestedAt: new Date() };
        const result = await foodRequestCollection.insertOne(data);
        res.status(201).json({ insertedId: result.insertedId });
    } catch (err) {
        console.error("POST /requestedfoods error:", err);
        res.status(500).json({ error: err.message });
    }
});

app.get("/myfoodrequest", verifyToken, async (req, res) => {
    try {
        if (!foodRequestCollection) return res.status(500).json({ error: "Requested foods collection not ready" });
        const userEmail = req.query.email;
        if (userEmail !== req.decoded.email) return res.status(403).json({ error: "Forbidden" });

        const requests = await foodRequestCollection.find({ userEmail }).toArray();
        res.json(requests);
    } catch (err) {
        console.error("GET /myfoodrequest error:", err);
        res.status(500).json({ error: err.message });
    }
});

// ---------- Payments ----------

// Create Payment Intent
app.post("/create-payment-intent", async (req, res) => {
    try {
        const { price } = req.body;
        if (!price || price <= 0) {
            return res.status(400).json({ error: "Invalid price" });
        }

        const paymentIntent = await stripe.paymentIntents.create({
            amount: Math.round(price * 100), // in cents
            currency: "usd",
            automatic_payment_methods: { enabled: true },
        });

        res.json({ clientSecret: paymentIntent.client_secret });
    } catch (err) {
        console.error("POST /create-payment-intent error:", err);
        res.status(500).json({ error: err.message });
    }
});

// Save completed payment info
app.post("/payments", async (req, res) => {
    try {
        if (!paymentCollection)
            return res.status(500).json({ error: "Payments collection not ready" });

        const { email, amount, transactionId, status, date } = req.body;

        if (!email || !amount || !transactionId || !status) {
            return res.status(400).json({ error: "Missing payment data" });
        }

        const data = { email, amount, transactionId, status, date: date || new Date() };
        const result = await paymentCollection.insertOne(data);

        res.status(201).json({ insertedId: result.insertedId });
    } catch (err) {
        console.error("POST /payments error:", err);
        res.status(500).json({ error: err.message });
    }
});

// ---------- Start server ----------
app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));


