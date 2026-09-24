"use strict";

require("dotenv").config();

const path = require("path");
const crypto = require("crypto");
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const axios = require("axios");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const { z } = require("zod");

const app = express();

const PORT = Number(process.env.PORT || 10000);
const JWT_SECRET = process.env.JWT_SECRET;
const PASSWORD = process.env.DASHBOARD_PASSWORD;

if (!JWT_SECRET) {
  throw new Error("JWT_SECRET is required");
}

if (!PASSWORD) {
  throw new Error("DASHBOARD_PASSWORD is required");
}

app.disable("x-powered-by");

app.use(
  helmet({
    crossOriginResourcePolicy: {
      policy: "cross-origin"
    }
  })
);

app.use(express.json({ limit: "100kb" }));

app.use(
  cors({
    origin: true,
    methods: ["GET", "POST"],
    allowedHeaders: ["Content-Type", "Authorization"]
  })
);

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false
});

const http = axios.create({
  timeout: Number(process.env.CHIRON_TIMEOUT_MS || 15000),
  validateStatus: () => true
});

let tokenCache = {
  value: null,
  expiresAt: 0
};

const tripSchema = z.object({
  trip_id: z.string().trim().min(1).max(200),
  start_time: z.string().trim().min(1).max(100),
  end_time: z.string().trim().min(1).max(100),
  departure: z.string().trim().min(1).max(2000),
  destination: z.string().trim().min(1).max(2000)
});

const requestSchema = z.object({
  chiron_id: z.string().trim().min(1).max(100),
  kbo: z.string().trim().min(1).max(100),
  driver_card: z.string().trim().min(1).max(100),
  license_plate: z.string().trim().min(1).max(100),
  trips: z.array(tripSchema).min(1).max(50)
});

function createRequestId() {
  return crypto.randomUUID();
}

function authenticate(req, res, next) {
  const [scheme, token] = (req.get("authorization") || "").split(" ");

  if (scheme !== "Bearer" || !token) {
    return res.status(401).json({
      status: "ERROR",
      bericht: "التوكن مفقود"
    });
  }

  try {
    req.user = jwt.verify(token, JWT_SECRET, {
      algorithms: ["HS256"],
      issuer: "chiron-taxi",
      audience: "chiron-dashboard"
    });

    next();
  } catch {
    return res.status(403).json({
      status: "ERROR",
      bericht: "التوكن غير صالح"
    });
  }
}

async function getChironToken() {
  if (
    tokenCache.value &&
    Date.now() < tokenCache.expiresAt - 60000
  ) {
    return tokenCache.value;
  }

  const tokenUrl = process.env.CHIRON_TOKEN_URL;
  const clientId = process.env.CHIRON_CLIENT_ID;
  const clientSecret = process.env.CHIRON_CLIENT_SECRET;

  if (!tokenUrl || !clientId || !clientSecret) {
    throw new Error("Chiron OAuth settings are incomplete");
  }

  const form = new URLSearchParams({
    grant_type: "client_credentials"
  });

  if (process.env.CHIRON_SCOPE) {
    form.set("scope", process.env.CHIRON_SCOPE);
  }

  const response = await http.post(
    tokenUrl,
    form.toString(),
    {
      auth: {
        username: clientId,
        password: clientSecret
      },
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json"
      }
    }
  );

  if (response.status < 200 || response.status >= 300) {
    throw new Error(
      `OAuth failed ${response.status}: ${JSON.stringify(response.data)}`
    );
  }

  if (!response.data?.access_token) {
    throw new Error("No access_token returned");
  }

  tokenCache = {
    value: response.data.access_token,
    expiresAt:
      Date.now() +
      Number(response.data.expires_in || 3600) * 1000
  };

  return tokenCache.value;
}

app.get("/health", (req, res) => {
  res.json({
    status: "OK",
    service: "chiron-taxi",
    environment: process.env.NODE_ENV || "development"
  });
});

app.post("/api/login", loginLimiter, (req, res) => {
  const result = z
    .object({
      password: z.string().min(1).max(500)
    })
    .safeParse(req.body);

  if (!result.success) {
    return res.status(400).json({
      status: "ERROR",
      bericht: "بيانات الدخول غير صحيحة"
    });
  }

  if (result.data.password !== PASSWORD) {
    return res.status(401).json({
      status: "ERROR",
      bericht: "كلمة المرور غير صحيحة"
    });
  }

  const token = jwt.sign(
    {
      role: "admin"
    },
    JWT_SECRET,
    {
      algorithm: "HS256",
      expiresIn: "12h",
      issuer: "chiron-taxi",
      audience: "chiron-dashboard"
    }
  );

  res.json({
    status: "SUCCESS",
    token
  });
});

app.get(
  "/api/chiron/health",
  authenticate,
  async (req, res) => {
    const requestId = createRequestId();

    try {
      const token = await getChironToken();

      res.json({
        status: "SUCCESS",
        request_id: requestId,
        environment: process.env.CHIRON_ENV || "unknown",
        token_received: Boolean(token)
      });
    } catch (error) {
      console.error(requestId, error.message);

      res.status(502).json({
        status: "ERROR",
        request_id: requestId,
        bericht: "فشل اتصال Chiron"
      });
    }
  }
);

app.post(
  "/api/chiron/trips",
  apiLimiter,
  authenticate,
  async (req, res) => {
    const requestId = createRequestId();

    const parsed = requestSchema.safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({
        status: "ERROR",
        request_id: requestId,
        bericht: "بيانات الرحلات غير صحيحة",
        details: parsed.error.flatten()
      });
    }

    try {
      const token = await getChironToken();

      if (!process.env.CHIRON_API_URL) {
        throw new Error("CHIRON_API_URL is missing");
      }

      const response = await http.post(
        process.env.CHIRON_API_URL,
        parsed.data,
        {
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
            Accept: "application/json",
            "X-Request-ID": requestId
          }
        }
      );

      if (
        response.status < 200 ||
        response.status >= 300
      ) {
        return res.status(502).json({
          status: "ERROR",
          request_id: requestId,
          bericht: "Chiron رفض الطلب",
          chiron_status: response.status
        });
      }

      res.json({
        status: "SUCCESS",
        request_id: requestId,
        bericht: "تم إرسال الطلب إلى Chiron",
        chiron_status: response.status,
        chiron_data: response.data
      });
    } catch (error) {
      console.error(
        requestId,
        error.response?.data || error.message
      );

      res.status(502).json({
        status: "ERROR",
        request_id: requestId,
        bericht: "فشل الاتصال بخدمة Chiron"
      });
    }
  }
);

app.use(express.static(path.join(__dirname, "public")));

app.get("*", (req, res) => {
  res.sendFile(
    path.join(__dirname, "public", "index.html")
  );
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Listening on ${PORT}`);
});
