require("dotenv").config();

/* ================= DEPENDENCIES ================= */
const express = require("express");
const cors = require("cors");
const AWS = require("aws-sdk");
const multer = require("multer");
const http = require("http");
const { Server } = require("socket.io");
const Razorpay = require("razorpay");
const crypto = require("crypto");
const path = require("path"); // Added path module

/* ================= CONFIGURATION ================= */
const app = express();
app.use(cors());
app.use(express.json({ limit: "50mb" }));

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

/* Razorpay Config */
const razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET
});

/* AWS S3 Config */
AWS.config.update({
    accessKeyId: process.env.AWS_ACCESS_KEY,
    secretAccessKey: process.env.AWS_SECRET_KEY,
    region: process.env.AWS_REGION
});

const s3 = new AWS.S3();
const BUCKET = process.env.AWS_BUCKET;

/* Multer (File Upload) Config */
const upload = multer({
    limits: { fileSize: 50 * 1024 * 1024 }, // 5MB limit
    fileFilter: (req, file, cb) => {
        if (!file.mimetype.startsWith('image/')) {
            return cb(new Error('Only image files are allowed!'), false);
        }
        cb(null, true);
    }
});

/* ================= UTILITIES ================= */

const validTokens = new Map();

function generateToken() {
    const token = crypto.randomBytes(32).toString("hex");
    validTokens.set(token, {
        used: false,
        expires: Date.now() + 1000 * 60 * 10 
    });
    return token;
}

function verifyToken(token) {
    const data = validTokens.get(token);
    if (!data) return false;
    if (data.used) return false;
    if (Date.now() > data.expires) {
        validTokens.delete(token);
        return false;
    }
    return true;
}

function useToken(token) {
    if (validTokens.has(token)) {
        validTokens.get(token).used = true;
    }
}

function isOverlapping(newBlock, blocks) {
    return blocks.some(b =>
        newBlock.minCol < b.minCol + b.width &&
        newBlock.minCol + newBlock.width > b.minCol &&
        newBlock.minRow < b.minRow + b.height &&
        newBlock.minRow + newBlock.height > b.minRow
    );
}

/* ================= API ROUTES ================= */

// 1. GET ALL BLOCKS
app.get("/blocks", async (req, res) => {
    try {
        const data = await s3.getObject({
            Bucket: BUCKET,
            Key: "blocks.json"
        }).promise();
        res.json(JSON.parse(data.Body.toString()));
    } catch (err) {
        res.json({ blocks: [] });
    }
});

// 2. CREATE PAYMENT ORDER
// ... inside server.js
/* ================= CREATE ORDER (DEBUG VERSION) ================= */
app.post("/create-order", async (req, res) => {
    try {
        const { amount } = req.body;

        // --- DEBUG LOGS: CHECK IF KEYS ARE LOADED ---
        console.log("------------------------------------------");
        console.log("📝 PROCESSING NEW ORDER");
        console.log("1. Received Amount (Rupees):", amount);
        console.log("2. Checking Razorpay Keys...");
        
        if (!process.env.RAZORPAY_KEY_ID) {
            console.error("❌ CRITICAL ERROR: RAZORPAY_KEY_ID is MISSING from .env file");
            throw new Error("RAZORPAY_KEY_ID is missing");
        }
        
        if (!process.env.RAZORPAY_KEY_SECRET) {
            console.error("❌ CRITICAL ERROR: RAZORPAY_KEY_SECRET is MISSING from .env file");
            throw new Error("RAZORPAY_KEY_SECRET is missing");
        }
        
        console.log("✅ Keys found. ID starts with:", process.env.RAZORPAY_KEY_ID.substring(0, 8) + "...");

        // --- VALIDATION & CALCULATION ---
        if (!amount || amount <= 0) {
            console.error("❌ Invalid Amount:", amount);
            return res.status(400).json({ error: "Invalid amount" });
        }

        const amountPaise = Math.round(amount * 100); // Ensure it's an INTEGER
        console.log("3. Creating Razorpay Order for:", amountPaise, "paise");

        const options = {
            amount: amountPaise,
            currency: "INR",
            receipt: "order_" + Date.now()
        };

        // --- SEND TO RAZORPAY ---
        const order = await razorpay.orders.create(options);
        
        console.log("✅ SUCCESS: Order Created ID:", order.id);
        console.log("------------------------------------------");
        
        res.json(order);

    } catch (err) {
        // --- PRINT THE REAL ERROR ---
        console.error("🔥 CRASH REPORT:", err);
        console.error("Message:", err.message);
        if (err.error) console.error("Razorpay Details:", err.error); // Show Razorpay specific errors
        
        res.status(500).json({ 
            error: "Server Error: " + err.message, 
            details: err.error ? err.error.description : "Check backend terminal for logs"
        });
    }
});
// 3. VERIFY PAYMENT
app.post("/verify-payment", (req, res) => {
    try {
        const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;

        if (!process.env.RAZORPAY_KEY_SECRET) {
            console.error("CRITICAL: Missing RAZORPAY_KEY_SECRET");
            return res.status(500).json({ success: false, error: "Server config error" });
        }

        const body = razorpay_order_id + "|" + razorpay_payment_id;
        const expectedSignature = crypto
            .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
            .update(body.toString())
            .digest("hex");

        if (expectedSignature === razorpay_signature) {
            const token = generateToken();
            res.json({ success: true, token: token });
        } else {
            res.status(400).json({ success: false, error: "Invalid signature" });
        }
    } catch (err) {
        console.error("Verify Error:", err);
        res.status(500).json({ success: false, error: "Verification error" });
    }
});

// 4. UPLOAD IMAGE
app.post("/upload", upload.single("file"), async (req, res) => {
    try {
        const token = req.body.token;
        if (!verifyToken(token)) return res.status(403).json({ error: "Invalid token" });
        if (!req.file) return res.status(400).json({ error: "No file" });

        const key = `uploads/${Date.now()}_${req.file.originalname.replace(/\s+/g, '-')}`;
        await s3.putObject({
            Bucket: BUCKET,
            Key: key,
            Body: req.file.buffer,
            ContentType: req.file.mimetype,
            CacheControl: "public, max-age=31536000, immutable"
        }).promise();

        res.json({ url: `https://${BUCKET}.s3.${process.env.AWS_REGION}.amazonaws.com/${key}` });
    } catch (err) {
        console.error("Upload Error:", err);
        res.status(500).json({ error: "Upload failed" });
    }
});

// 5. SAVE BLOCK
app.post("/save", async (req, res) => {
    try {
        const { image, name, link, minRow, minCol, width, height, token } = req.body;

        if (!verifyToken(token)) return res.json({ success: false, error: "Payment required" });
        
        // ... (Keep existing validation checks) ...

        let existing = { blocks: [] };
        try {
            const data = await s3.getObject({ Bucket: BUCKET, Key: "blocks.json" }).promise();
            existing = JSON.parse(data.Body.toString());
        } catch (e) {}

        const newBlock = { minRow, minCol, width, height };
        if (isOverlapping(newBlock, existing.blocks)) {
            return res.json({ success: false, error: "Pixels taken" });
        }

        existing.blocks.push({
            image, name: name.trim(), link: link || "",
            minRow, minCol, width, height, date: new Date().toISOString()
        });

        await s3.putObject({
            Bucket: BUCKET,
            Key: "blocks.json",
            Body: JSON.stringify(existing),
            ContentType: "application/json"
        }).promise();

        useToken(token);
        io.emit("updated");
        res.json({ success: true });

    } catch (err) {
        console.error("Save Error:", err);
        res.json({ success: false, error: "Save failed" });
    }
});

/* ================= FRONTEND SERVING (NEW) ================= */

// 1. Serve static files from the 'frontend' folder
// Ensure your folder structure is:
// root/
//   ├── backend/ (server.js is here)
//   └── frontend/ (index.html is here)
app.use(express.static(path.join(__dirname, "../frontend")));

// 2. Serve index.html for the root route
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "../frontend/index.html"));
});

// 3. (Optional) Catch-all for SPA routing if you add more pages later
app.get("*", (req, res) => {
    res.sendFile(path.join(__dirname, "../frontend/index.html"));
});


/* ================= START SERVER ================= */

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
    console.log(`🔥 Backend running on port ${PORT}`);
});
