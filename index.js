// index.js (Vercel Serverless Ready)
import dotenv from "dotenv";
dotenv.config();

import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { MongoClient, ServerApiVersion, ObjectId } from "mongodb";
import admin from "firebase-admin";
import Stripe from "stripe";

// ---------- Environment ----------
const {
    MONGODB_URI,
    STRIPE_SECRET_KEY,
    FB_SERVICE_KEY
} = process.env;

if (!MONGODB_URI) throw new Error("MONGODB_URI is missing");
if (!STRIPE_SECRET_KEY) throw new Error("STRIPE_SECRET_KEY is missing");
if (!FB_SERVICE_KEY) throw new Error("FB_SERVICE_KEY is missing");

// ---------- Firebase (Base64 Decode) ----------
let serviceAccount;
try {
    const decodedKey = Buffer.from(FB_SERVICE_KEY, "base64").toString("utf8");
    serviceAccount = JSON.parse(decodedKey);
} catch (err) {
    console.error("❌ Failed to decode Firebase service key:", err);
    throw new Error("Invalid FB_SERVICE_KEY format");
}

// Initialize Firebase Admin only if not already initialized
if (!admin.apps.length) {
    try {
        admin.initializeApp({
            credential: admin.credential.cert(serviceAccount),
        });
        console.log("✅ Firebase Admin Initialized");
    } catch (err) {
        console.error("❌ Firebase Admin init failed:", err);
        throw err;
    }
}

// ---------- Stripe ----------
const stripe = new Stripe(STRIPE_SECRET_KEY);

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
    "https://assignment11-b015f.web.app",
    "https://assignment11-b015f.firebaseapp.com"
];
app.use(cors({
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error("Not allowed by CORS"));
        }
    },
    credentials: true
}));

// ---------- MongoDB ----------
const client = new MongoClient(MONGODB_URI, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

let db, usersCollection, foodCollection, foodRequestCollection, paymentCollection;

async function connectDB() {
    try {
        await client.connect();
        await client.db("admin").command({ ping: 1 });

        db = client.db("foodshare");
        usersCollection = db.collection("users");
        foodCollection = db.collection("food");
        foodRequestCollection = db.collection("requestedfoods");
        paymentCollection = db.collection("payments");

        console.log("✅ MongoDB connected successfully");
    } catch (err) {
        console.error("❌ MongoDB connection failed:", err);
        throw err;
    }
}

// Connect to DB
await connectDB().catch(err => {
    console.error("Failed to connect to database:", err);
    process.exit(1);
});

// ---------- Firebase Token Verification Middleware ----------
const verifyToken = async (req, res, next) => {
    const authHeader = req.headers.authorization || "";

    if (!authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ error: "No token provided" });
    }

    const token = authHeader.split(" ")[1];

    try {
        const decoded = await admin.auth().verifyIdToken(token);
        req.decoded = decoded;
        next();
    } catch (err) {
        console.error("❌ Token verification failed:", err.message);
        res.status(403).json({ error: "Invalid or expired token" });
    }
};

// ---------- Routes ----------

// Health check
app.get("/", (req, res) => {
    res.json({
        status: "ok",
        message: "FoodShare API is running",
        timestamp: new Date().toISOString()
    });
});

// --- Users ---
app.post("/users", async (req, res) => {
    try {
        const { email, name, photourl, membership = "no" } = req.body;

        if (!email) {
            return res.status(400).json({ error: "Email is required" });
        }

        const result = await usersCollection.updateOne(
            { email },
            {
                $setOnInsert: { email, membership, createdAt: new Date() },
                $set: { name, photourl, updatedAt: new Date() }
            },
            { upsert: true }
        );

        res.json({
            success: true,
            result,
            message: result.upsertedCount > 0 ? "User created" : "User updated"
        });
    } catch (err) {
        console.error("Error in POST /users:", err);
        res.status(500).json({ error: err.message });
    }
});

// Get all users (consider adding pagination)
app.get("/users", async (req, res) => {
    try {
        const users = await usersCollection.find().toArray();
        res.json(users);
    } catch (err) {
        console.error("Error in GET /users:", err);
        res.status(500).json({ error: err.message });
    }
});

// Get user by email
app.get("/users/:email", async (req, res) => {
    try {
        const email = req.params.email;
        const user = await usersCollection.findOne({ email });

        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        res.json(user);
    } catch (err) {
        console.error("Error in GET /users/:email:", err);
        res.status(500).json({ error: err.message });
    }
});

// Update membership
app.patch("/users/membership/:email", async (req, res) => {
    try {
        const email = req.params.email;
        const result = await usersCollection.updateOne(
            { email },
            { $set: { membership: "yes", membershipUpdatedAt: new Date() } }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({ error: "User not found" });
        }

        res.json({ success: true, result });
    } catch (err) {
        console.error("Error in PATCH /users/membership/:email:", err);
        res.status(500).json({ error: err.message });
    }
});

// --- Food ---
app.post("/food", async (req, res) => {
    try {
        const { donorEmail, foodName } = req.body;

        if (!donorEmail || !foodName) {
            return res.status(400).json({ error: "donorEmail and foodName are required" });
        }

        const data = {
            ...req.body,
            createdAt: new Date(),
            foodStatus: req.body.foodStatus || "available"
        };

        const result = await foodCollection.insertOne(data);
        res.status(201).json({ success: true, insertedId: result.insertedId });
    } catch (err) {
        console.error("Error in POST /food:", err);
        res.status(500).json({ error: err.message });
    }
});

app.get("/food", async (req, res) => {
    try {
        const search = req.query.search || "";
        const sortOrder = req.query.sortOrder === "asc" ? 1 : -1;

        const filter = {
            foodStatus: "available",
            expiredDateTime: { $gt: new Date() },
            ...(search && { foodName: { $regex: search, $options: "i" } })
        };

        const foods = await foodCollection
            .find(filter)
            .sort({ expiredDateTime: sortOrder })
            .toArray();

        res.json(foods);
    } catch (err) {
        console.error("Error in GET /food:", err);
        res.status(500).json({ error: err.message });
    }
});

app.get("/food/:id", async (req, res) => {
    try {
        if (!ObjectId.isValid(req.params.id)) {
            return res.status(400).json({ error: "Invalid food ID" });
        }

        const food = await foodCollection.findOne({ _id: new ObjectId(req.params.id) });

        if (!food) {
            return res.status(404).json({ error: "Food not found" });
        }

        res.json(food);
    } catch (err) {
        console.error("Error in GET /food/:id:", err);
        res.status(500).json({ error: err.message });
    }
});

app.put("/food/:id", async (req, res) => {
    try {
        if (!ObjectId.isValid(req.params.id)) {
            return res.status(400).json({ error: "Invalid food ID" });
        }

        const { _id, ...updateData } = req.body;
        updateData.updatedAt = new Date();

        const result = await foodCollection.updateOne(
            { _id: new ObjectId(req.params.id) },
            { $set: updateData }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({ error: "Food not found" });
        }

        res.json({ success: true, message: "Food updated", result });
    } catch (err) {
        console.error("Error in PUT /food/:id:", err);
        res.status(500).json({ error: err.message });
    }
});

app.patch("/food/:id", async (req, res) => {
    try {
        if (!ObjectId.isValid(req.params.id)) {
            return res.status(400).json({ error: "Invalid food ID" });
        }

        const { foodStatus } = req.body;

        const result = await foodCollection.updateOne(
            { _id: new ObjectId(req.params.id) },
            {
                $set: {
                    foodStatus: foodStatus || "requested",
                    statusUpdatedAt: new Date()
                }
            }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({ error: "Food not found" });
        }

        res.json({ success: true, result });
    } catch (err) {
        console.error("Error in PATCH /food/:id:", err);
        res.status(500).json({ error: err.message });
    }
});

// Delete food (optional - if needed)
app.delete("/food/:id", verifyToken, async (req, res) => {
    try {
        if (!ObjectId.isValid(req.params.id)) {
            return res.status(400).json({ error: "Invalid food ID" });
        }

        const result = await foodCollection.deleteOne({ _id: new ObjectId(req.params.id) });

        if (result.deletedCount === 0) {
            return res.status(404).json({ error: "Food not found" });
        }

        res.json({ success: true, message: "Food deleted" });
    } catch (err) {
        console.error("Error in DELETE /food/:id:", err);
        res.status(500).json({ error: err.message });
    }
});

// --- Food Requests ---
app.post("/requestedfoods", async (req, res) => {
    try {
        const data = {
            ...req.body,
            requestedAt: new Date(),
            status: req.body.status || "pending"
        };

        const result = await foodRequestCollection.insertOne(data);
        res.status(201).json({ success: true, insertedId: result.insertedId });
    } catch (err) {
        console.error("Error in POST /requestedfoods:", err);
        res.status(500).json({ error: err.message });
    }
});

app.get("/myfoodrequest", verifyToken, async (req, res) => {
    try {
        const userEmail = req.query.email;

        if (userEmail !== req.decoded.email) {
            return res.status(403).json({ error: "Forbidden: Email mismatch" });
        }

        const requests = await foodRequestCollection
            .find({ userEmail })
            .sort({ requestedAt: -1 })
            .toArray();

        res.json(requests);
    } catch (err) {
        console.error("Error in GET /myfoodrequest:", err);
        res.status(500).json({ error: err.message });
    }
});

// Get all food requests (for admin/donor)
app.get("/requestedfoods", verifyToken, async (req, res) => {
    try {
        const requests = await foodRequestCollection
            .find()
            .sort({ requestedAt: -1 })
            .toArray();

        res.json(requests);
    } catch (err) {
        console.error("Error in GET /requestedfoods:", err);
        res.status(500).json({ error: err.message });
    }
});

// --- Payments ---
app.post("/create-payment-intent", async (req, res) => {
    try {
        const { price } = req.body;

        if (!price || price <= 0) {
            return res.status(400).json({ error: "Invalid price amount" });
        }

        const paymentIntent = await stripe.paymentIntents.create({
            amount: Math.round(price * 100), // Convert to cents
            currency: "usd",
            automatic_payment_methods: { enabled: true },
        });

        res.json({ clientSecret: paymentIntent.client_secret });
    } catch (err) {
        console.error("Error in POST /create-payment-intent:", err);
        res.status(500).json({ error: err.message });
    }
});

app.post("/payments", async (req, res) => {
    try {
        const { email, amount, transactionId, status, date } = req.body;

        if (!email || !amount || !transactionId || !status) {
            return res.status(400).json({ error: "Missing required payment data" });
        }

        const data = {
            email,
            amount,
            transactionId,
            status,
            date: date || new Date(),
            createdAt: new Date()
        };

        const result = await paymentCollection.insertOne(data);
        res.status(201).json({ success: true, insertedId: result.insertedId });
    } catch (err) {
        console.error("Error in POST /payments:", err);
        res.status(500).json({ error: err.message });
    }
});

// Get payments by email
app.get("/payments/:email", verifyToken, async (req, res) => {
    try {
        const email = req.params.email;

        if (email !== req.decoded.email) {
            return res.status(403).json({ error: "Forbidden: Email mismatch" });
        }

        const payments = await paymentCollection
            .find({ email })
            .sort({ createdAt: -1 })
            .toArray();

        res.json(payments);
    } catch (err) {
        console.error("Error in GET /payments/:email:", err);
        res.status(500).json({ error: err.message });
    }
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: "Route not found" });
});

// Error handler
app.use((err, req, res, next) => {
    console.error("Unhandled error:", err);
    res.status(500).json({ error: "Internal server error" });
});

// Graceful shutdown
process.on("SIGINT", async () => {
    console.log("Shutting down gracefully...");
    await client.close();
    process.exit(0);
});

// Export app for Vercel serverless
export default app;