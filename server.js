const express = require("express");
const path = require("path");
const crypto = require("crypto");

const app = express();

const PORT = process.env.PORT || 3000;
const PASSWORD = process.env.DASHBOARD_PASSWORD;

const sessions = new Set();

app.use(express.json());

function createToken() {
  return crypto.randomBytes(32).toString("hex");
}

function requireAuth(req, res, next) {
  const authorization = req.headers.authorization || "";

  const token = authorization.startsWith("Bearer ")
    ? authorization.substring(7)
    : "";

  if (!token || !sessions.has(token)) {
    return res.status(401).json({
      bericht: "انتهت الجلسة"
    });
  }

  next();
}

app.get("/health", (req, res) => {
  res.json({
    status: "OK",
    service: "chiron-taxi",
    environment: process.env.NODE_ENV || "production"
  });
});

app.post("/api/login", (req, res) => {
  const password = String(req.body?.password || "");

  console.log("LOGIN_REQUEST_RECEIVED");

  if (!PASSWORD) {
    console.error("DASHBOARD_PASSWORD_MISSING");

    return res.status(500).json({
      bericht: "DASHBOARD_PASSWORD غير موجود في Render"
    });
  }

  if (password !== PASSWORD) {
    console.log("LOGIN_FAILED");

    return res.status(401).json({
      bericht: "كلمة المرور غير صحيحة"
    });
  }

  const token = createToken();

  sessions.add(token);

  console.log("LOGIN_SUCCESS");

  return res.json({
    ok: true,
    token
  });
});

app.get("/api/chiron/health", requireAuth, (req, res) => {
  res.json({
    ok: true,
    environment: process.env.NODE_ENV || "production"
  });
});

app.post("/api/chiron/trips", requireAuth, (req, res) => {
  const requestId = crypto.randomUUID();

  console.log("TRIPS_REQUEST_RECEIVED", requestId);

  return res.json({
    ok: true,
    request_id: requestId,
    message: "تم استلام الرحلات"
  });
});

app.use(express.static(path.join(__dirname, "public")));

app.get("/{*splat}", (req, res) => {
  res.sendFile(
    path.join(__dirname, "public", "index.html")
  );
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});
