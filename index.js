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

// ---------- Firebase Admin Setup ----------
let serviceAccount;
try {
  serviceAccount = JSON.parse(
    Buffer.from(FB_SERVICE_KEY, "base64").toString("utf8")
  );
} catch (error) {
  console.error("❌ Invalid base64 Firebase key:", error);
  throw new Error("FB_SERVICE_KEY is not valid base64 JSON");
}

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
  console.log("✅ Firebase Admin Initialized");
}

// ---------- Stripe ----------
const stripe = new Stripe(STRIPE_SECRET_KEY);

// ---------- Express App ----------
const app = express();
app.use(helmet());
app.use(cors({
  origin: [
    "http://localhost:5173",
    "https://assignment11-b015f.web.app",
    "https://assignment11-b015f.firebaseapp.com"
  ],
  credentials: true
}));
app.use(express.json({ limit: "10mb" }));
app.use(rateLimit({ windowMs: 60000, max: 120 }));

// ---------- MongoDB Lazy Connection ----------
let client;
let db;
let usersCollection, foodCollection, foodRequestCollection, paymentCollection;

async function connectDB() {
  if (!client) {
    client = new MongoClient(MONGODB_URI, {
      serverApi: { version: ServerApiVersion.v1, strict: true }
    });
    await client.connect();
    db = client.db("foodshare");
    usersCollection = db.collection("users");
    foodCollection = db.collection("food");
    foodRequestCollection = db.collection("requestedfoods");
    paymentCollection = db.collection("payments");
    console.log("✅ MongoDB Connected Successfully");
  }
}

// ---------- Firebase Token Verify Middleware ----------
async function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization || "";

  if (!authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized, no token provided" });
  }

  try {
    const decoded = await admin.auth().verifyIdToken(authHeader.split(" ")[1]);
    req.decoded = decoded;
    next();
  } catch {
    return res.status(403).json({ error: "Invalid or expired token" });
  }
}

// ---------- Routes ----------

// Health Check
app.get("/", (req, res) => {
  res.json({ status: "OK ✅", message: "FoodShare API Running" });
});

// Create or Update User
app.post("/users", async (req, res) => {
  await connectDB();
  const { email, name, photourl, membership = "no" } = req.body;

  const result = await usersCollection.updateOne(
    { email },
    {
      $setOnInsert: { email, membership, createdAt: new Date() },
      $set: { name, photourl, updatedAt: new Date() }
    },
    { upsert: true }
  );

  res.json({ success: true, upserted: result.upsertedCount > 0 });
});

// Get All Users
app.get("/users", async (req, res) => {
  await connectDB();
  res.json(await usersCollection.find().toArray());
});

// Get Single User
app.get("/users/:email", async (req, res) => {
  await connectDB();
  const user = await usersCollection.findOne({ email: req.params.email });
  user ? res.json(user) : res.status(404).json({ error: "User not found" });
});

// Update Membership
app.patch("/users/membership/:email", async (req, res) => {
  await connectDB();
  const result = await usersCollection.updateOne(
    { email: req.params.email },
    { $set: { membership: "yes", membershipUpdatedAt: new Date() } }
  );
  result.matchedCount === 0
    ? res.status(404).json({ error: "User not found" })
    : res.json({ success: true });
});

// Add Food
app.post("/food", async (req, res) => {
  await connectDB();
  const data = { ...req.body, createdAt: new Date(), foodStatus: "available" };
  const result = await foodCollection.insertOne(data);
  res.status(201).json({ success: true, insertedId: result.insertedId });
});

// Get Foods (search + sort)
app.get("/food", async (req, res) => {
  await connectDB();
  const search = req.query.search || "";
  const sort = req.query.sortOrder === "asc" ? 1 : -1;

  const foods = await foodCollection
    .find({
      foodStatus: "available",
      expiredDateTime: { $gt: new Date() },
      ...(search && { foodName: { $regex: search, $options: "i" } })
    })
    .sort({ expiredDateTime: sort })
    .toArray();

  res.json(foods);
});

// Get Single Food
app.get("/food/:id", async (req, res) => {
  await connectDB();
  if (!ObjectId.isValid(req.params.id))
    return res.status(400).json({ error: "Invalid ID" });

  const food = await foodCollection.findOne({ _id: new ObjectId(req.params.id) });
  food ? res.json(food) : res.status(404).json({ error: "Food not found" });
});

// Update Food
app.put("/food/:id", async (req, res) => {
  await connectDB();
  const { _id, ...updateData } = req.body;
  updateData.updatedAt = new Date();
  const result = await foodCollection.updateOne(
    { _id: new ObjectId(req.params.id) },
    { $set: updateData }
  );
  res.json({ success: true, result });
});

// Request Food
app.post("/requestedfoods", async (req, res) => {
  await connectDB();
  const result = await foodRequestCollection.insertOne({
    ...req.body,
    requestedAt: new Date(),
    status: "pending"
  });
  res.json({ success: true, insertedId: result.insertedId });
});

// My Requests
app.get("/myfoodrequest", verifyToken, async (req, res) => {
  await connectDB();
  const requests = await foodRequestCollection
    .find({ userEmail: req.decoded.email })
    .sort({ requestedAt: -1 })
    .toArray();
  res.json(requests);
});

// Create Payment Intent
app.post("/create-payment-intent", async (req, res) => {
  const { price } = req.body;
  const paymentIntent = await stripe.paymentIntents.create({
    amount: Math.round(price * 100),
    currency: "usd",
    automatic_payment_methods: { enabled: true }
  });
  res.json({ clientSecret: paymentIntent.client_secret });
});

// Save Payment
app.post("/payments", async (req, res) => {
  await connectDB();
  const result = await paymentCollection.insertOne({
    ...req.body,
    createdAt: new Date()
  });
  res.json({ success: true, insertedId: result.insertedId });
});

// 404
app.use("*", (_, res) => res.status(404).json({ error: "Route not found" }));

// ✅ Export for Vercel
export default app;
