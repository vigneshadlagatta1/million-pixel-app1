require("dotenv").config();

const Razorpay = require("razorpay");
const crypto = require("crypto");

const razorpay = new Razorpay({
key_id: process.env.RAZORPAY_KEY_ID,
key_secret: process.env.RAZORPAY_KEY_SECRET
});

const express = require("express");
const cors = require("cors");
const AWS = require("aws-sdk");
const multer = require("multer");
const http = require("http");
const { Server } = require("socket.io");

const app = express();
app.use(cors());
app.use(express.json({ limit: "10mb" }));

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

/* ================= AWS ================= */

AWS.config.update({
accessKeyId: process.env.AWS_ACCESS_KEY,
secretAccessKey: process.env.AWS_SECRET_KEY,
region: process.env.AWS_REGION
});

const s3 = new AWS.S3();
const BUCKET = process.env.AWS_BUCKET;

/* ================= MULTER ================= */

const upload = multer({
limits: { fileSize: 5 * 1024 * 1024 }
});

/* ================= PAYMENT TOKENS ================= */

const validTokens = new Map();

function generateToken(){

const token = crypto.randomBytes(32).toString("hex");

validTokens.set(token,{
used:false,
expires:Date.now()+1000*60*10
});

return token;

}

function verifyToken(token){

const data = validTokens.get(token);

if(!data) return false;

if(data.used) return false;

if(Date.now()>data.expires){

validTokens.delete(token);
return false;

}

return true;

}

function useToken(token){

if(validTokens.has(token)){

validTokens.get(token).used=true;

}

}

/* ================= GET BLOCKS ================= */

app.get("/blocks", async (req, res) => {

try {

const data = await s3.getObject({
Bucket: BUCKET,
Key: "blocks.json"
}).promise();

res.json(JSON.parse(data.Body.toString()));

} catch {

res.json({ blocks: [] });

}

});

/* ================= OVERLAP CHECK ================= */

function isOverlapping(newBlock, blocks){

return blocks.some(b =>

newBlock.minCol < b.minCol + b.width &&
newBlock.minCol + newBlock.width > b.minCol &&
newBlock.minRow < b.minRow + b.height &&
newBlock.minRow + newBlock.height > b.minRow

);

}

/* ================= UPLOAD IMAGE ================= */

app.post("/upload", upload.single("file"), async (req, res) => {

try {

const token = req.body.token;

if(!verifyToken(token)){

return res.status(403).json({ error:"Invalid payment token" });

}

if (!req.file){

return res.status(400).json({ error: "No file uploaded" });

}

const key = `uploads/${Date.now()}_${req.file.originalname}`;

await s3.putObject({

Bucket: BUCKET,
Key: key,
Body: req.file.buffer,
ContentType: req.file.mimetype,
CacheControl: "public, max-age=31536000"

}).promise();

const imageUrl =
`https://${BUCKET}.s3.${process.env.AWS_REGION}.amazonaws.com/${key}`;

res.json({ url: imageUrl });

} catch (err) {

console.log("UPLOAD ERROR:", err);
res.status(500).json({ error: "Upload failed" });

}

});

/* ================= SAVE BLOCK ================= */

app.post("/save", async (req, res) => {

try {

const {
image,
name,
link,
minRow,
minCol,
width,
height,
token
} = req.body;

/* ================= TOKEN REQUIRED ================= */

if(!verifyToken(token)){

return res.json({
success:false,
error:"Payment required"
});

}

/* ================= NAME REQUIRED ================= */

if(
!name ||
typeof name !== "string" ||
name.trim().length < 2 ||
name.trim().length > 50
){

return res.json({
success:false,
error:"Valid name required (2-50 chars)"
});

}

/* ================= IMAGE REQUIRED ================= */

if(
!image ||
typeof image !== "string" ||
!image.startsWith("https://")
){

return res.json({
success:false,
error:"Valid image required"
});

}

/* ================= PIXEL VALIDATION ================= */

if(
width<=0 ||
height<=0 ||
width>1000 ||
height>1000
){

return res.json({
success:false,
error:"Invalid pixel size"
});

}

/* ================= LOAD EXISTING ================= */

let existing = { blocks: [] };

try {

const data = await s3.getObject({

Bucket: BUCKET,
Key: "blocks.json"

}).promise();

existing = JSON.parse(data.Body.toString());

} catch {}

/* ================= OVERLAP PROTECTION ================= */

const newBlock = {
minRow,
minCol,
width,
height
};

if(isOverlapping(newBlock, existing.blocks)){

return res.json({
success:false,
error:"Pixels already sold"
});

}

/* ================= SAVE ================= */

existing.blocks.push({

image,
name: name.trim(),
link: link || "",
minRow,
minCol,
width,
height

});

await s3.putObject({

Bucket: BUCKET,
Key: "blocks.json",
Body: JSON.stringify(existing),
ContentType: "application/json"

}).promise();

/* ================= TOKEN USED ================= */

useToken(token);

io.emit("updated");

res.json({
success:true
});

} catch(err){

console.log(err);

res.json({
success:false,
error:"Server error"
});

}

});

/* ================= CREATE ORDER ================= */

app.post("/create-order", async (req, res) => {

try {

const { amount } = req.body;

if(!amount || amount<=0){

return res.status(400).json({ error:"Invalid amount" });

}

const order = await razorpay.orders.create({

amount: amount * 100,
currency: "INR"

});

res.json(order);

} catch(err){

console.log(err);

res.status(500).json({ error: err.message });

}

});

/* ================= VERIFY PAYMENT ================= */

app.post("/verify-payment", (req, res) => {

const {
razorpay_order_id,
razorpay_payment_id,
razorpay_signature
} = req.body;

const body = razorpay_order_id + "|" + razorpay_payment_id;

const expectedSignature = crypto
.createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
.update(body.toString())
.digest("hex");

if(expectedSignature === razorpay_signature){

const token = generateToken();

res.json({
success:true,
token:token
});

}else{

res.json({ success:false });

}

});

/* ================= ADMIN LOGIN ================= */

app.post("/admin-login", (req, res) => {

const { password } = req.body;

if(password === process.env.ADMIN_KEY){

res.json({ success:true });

}else{

res.json({ success:false });

}

});

/* ================= DELETE BLOCK (ADMIN ONLY) ================= */

app.post("/delete-block", async (req, res) => {

try {

const key = req.headers["x-admin-key"];

if(key !== process.env.ADMIN_KEY){

return res.status(403).json({ success:false, error:"Unauthorized" });

}

const { index } = req.body;

if(index === undefined){

return res.json({ success:false });

}

/* LOAD BLOCKS */

let existing = { blocks: [] };

try {

const data = await s3.getObject({

Bucket: BUCKET,
Key: "blocks.json"

}).promise();

existing = JSON.parse(data.Body.toString());

} catch {}

/* DELETE BLOCK */

existing.blocks.splice(index, 1);

/* SAVE UPDATED */

await s3.putObject({

Bucket: BUCKET,
Key: "blocks.json",
Body: JSON.stringify(existing),
ContentType: "application/json"

}).promise();

/* REALTIME UPDATE */

io.emit("updated");

res.json({ success:true });

} catch(err){

res.json({ success:false });

}

});

/* ================= DELETE BLOCK (ADMIN ONLY) ================= */

app.post("/delete-block", async (req, res) => {

try {

/* CHECK ADMIN KEY */

const key = req.headers["x-admin-key"];

if(key !== process.env.ADMIN_KEY){

return res.status(403).json({
success:false,
error:"Unauthorized"
});

}

/* GET INDEX */

const index = Number(req.body.index);

if(isNaN(index)){

return res.json({
success:false,
error:"Invalid index"
});

}

/* LOAD BLOCKS FROM S3 */

let existing = { blocks: [] };

try {

const data = await s3.getObject({

Bucket: BUCKET,
Key: "blocks.json"

}).promise();

existing = JSON.parse(data.Body.toString());

} catch(err){

return res.json({
success:false,
error:"Failed to load blocks"
});

}

/* CHECK INDEX VALID */

if(index < 0 || index >= existing.blocks.length){

return res.json({
success:false,
error:"Block not found"
});

}

/* DELETE BLOCK */

existing.blocks.splice(index, 1);

/* SAVE UPDATED BLOCKS */

await s3.putObject({

Bucket: BUCKET,
Key: "blocks.json",
Body: JSON.stringify(existing),
ContentType: "application/json"

}).promise();

/* UPDATE CLIENTS */

io.emit("updated");

res.json({
success:true
});

} catch(err){

console.log("DELETE ERROR:", err);

res.json({
success:false,
error:"Server error"
});

}

});

/* ================= START SERVER ================= */

server.listen(5000, () => {

console.log("🔥 Backend running on 5000");

});

/* ================= ANALYTICS ================= */

app.get("/analytics", async (req, res) => {

try {

let existing = { blocks: [] };

try {

const data = await s3.getObject({
Bucket: BUCKET,
Key: "blocks.json"
}).promise();

existing = JSON.parse(data.Body.toString());

} catch {}

const blocks = existing.blocks || [];

let totalPixels = 1000000;
let soldPixels = 0;
let totalRevenue = 0;

blocks.forEach(b => {

const width = Number(b.width) || 0;
const height = Number(b.height) || 0;

const pixels = width * height;

soldPixels += pixels;

totalRevenue += pixels * 100;

});

const availablePixels = totalPixels - soldPixels;

res.json({

totalPixels,
soldPixels,
availablePixels,
totalRevenue,
totalBlocks: blocks.length,
blocks: blocks.slice(-20).reverse()

});

} catch(err){

res.status(500).json({ error:"Analytics error" });

}

});

/* ================= ANALYTICS (PROTECTED) ================= */

app.get("/analytics", async (req, res) => {

const key = req.headers["x-admin-key"];

if(key !== process.env.ADMIN_KEY){

return res.status(403).json({ error:"Unauthorized" });

}

try {

let existing = { blocks: [] };

try {

const data = await s3.getObject({
Bucket: BUCKET,
Key: "blocks.json"
}).promise();

existing = JSON.parse(data.Body.toString());

} catch {}

const blocks = existing.blocks || [];

let totalPixels = 1000000;
let soldPixels = 0;
let totalRevenue = 0;

/* FIXED CALCULATION */

blocks.forEach(b => {

const width = Number(b.width) || 0;
const height = Number(b.height) || 0;

const pixels = width * height;

soldPixels += pixels;
totalRevenue += pixels * 100;

});

const availablePixels = totalPixels - soldPixels;
res.json({

totalPixels,
soldPixels,
availablePixels,
totalRevenue,
totalBlocks: blocks.length,
blocks: blocks.slice(-20).reverse()

});

} catch {

res.status(500).json({ error:"Analytics error" });

}

});