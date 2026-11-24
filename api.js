require("dotenv").config();

const express = require("express");
const cors = require("cors");
const http = require("http");
const { Server } = require("socket.io");
const { PrismaClient } = require("@prisma/client");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");

const app = express();
const server = http.createServer(app);
const prisma = new PrismaClient();

const PORT = process.env.API_PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET;
const GATEWAY_TOKEN = process.env.SOCKET_GATEWAY_TOKEN;
const ALLOWED_ORIGINS = (process.env.CLIENT_ORIGIN || "http://localhost:3000")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);

if (!JWT_SECRET || !GATEWAY_TOKEN) {
  console.error("Missing JWT_SECRET or SOCKET_GATEWAY_TOKEN in .env");
  process.exit(1);
}

// ==========================================
// GLOBAL MIDDLEWARE
// ==========================================

app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: true, limit: "100kb" }));

app.use(
  cors({
    origin: ALLOWED_ORIGINS,
    methods: ["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  }),
);

// ==========================================
// RATE LIMITERS
// ==========================================

const adminLoginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: {
    success: false,
    message: "Too many admin login attempts. Please try again later.",
  },
});

const collectorLoginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: {
    success: false,
    message: "Too many collector login attempts. Please try again later.",
  },
});

// ==========================================
// COMMON HELPERS
// ==========================================

function removePasswordHash(collector) {
  if (!collector) return collector;

  const { passwordHash, ...safeCollector } = collector;
  return safeCollector;
}

function removeAssignmentPasswordHashes(assignment) {
  if (!assignment) return assignment;

  return {
    ...assignment,
    collector: removePasswordHash(assignment.collector),
  };
}

function isUniqueBinAssignmentError(error) {
  if (error.code !== "P2002") return false;

  const target = error.meta?.target;

  return (
    (Array.isArray(target) && target.includes("binId")) ||
    (typeof target === "string" && target.includes("binId")) ||
    error.message?.includes("CollectionAssignment_one_active_per_bin")
  );
}

function getBearerToken(req) {
  const header = req.headers.authorization;

  if (!header || !header.startsWith("Bearer ")) {
    return null;
  }

  return header.split(" ")[1] || null;
}

// ==========================================
// COLLECTOR AUTHENTICATION
// ==========================================

async function authenticateCollector(req, res, next) {
  try {
    const token = getBearerToken(req);

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Authentication required. Please log in.",
      });
    }

    const decoded = jwt.verify(token, JWT_SECRET, {
      algorithms: ["HS256"],
    });

    if (
      decoded.role !== "COLLECTOR" ||
      typeof decoded.collectorId !== "string"
    ) {
      return res.status(401).json({
        success: false,
        message: "Invalid collector authentication token.",
      });
    }

    const collector = await prisma.collector.findUnique({
      where: { id: decoded.collectorId },
      select: {
        id: true,
        fullName: true,
        email: true,
        phone: true,
        address: true,
        status: true,
      },
    });

    if (!collector || collector.status !== "ACTIVE") {
      return res.status(403).json({
        success: false,
        message: "Your collector account is inactive or unavailable.",
      });
    }

    req.collector = collector;
    next();
  } catch (error) {
    if (
      ["JsonWebTokenError", "TokenExpiredError", "NotBeforeError"].includes(
        error.name,
      )
    ) {
      return res.status(401).json({
        success: false,
        message: "Invalid or expired authentication token.",
      });
    }

    console.error("Collector authentication error:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to authenticate collector.",
    });
  }
}

// ==========================================
// ADMIN AUTHENTICATION
// ==========================================

async function authenticateAdmin(req, res, next) {
  try {
    const token = getBearerToken(req);

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Authentication required.",
      });
    }

    const decoded = jwt.verify(token, JWT_SECRET, {
      algorithms: ["HS256"],
    });

    if (decoded.role !== "ADMIN" || !decoded.adminId || !decoded.adminRole) {
      return res.status(403).json({
        success: false,
        message: "Administrator access required.",
      });
    }

    const admin = await prisma.admin.findUnique({
      where: { id: decoded.adminId },
      select: {
        id: true,
        fullName: true,
        email: true,
        role: true,
        status: true,
      },
    });

    if (!admin || admin.status !== "ACTIVE") {
      return res.status(401).json({
        success: false,
        message: "Administrator account is inactive or unavailable.",
      });
    }

    if (decoded.adminRole !== admin.role) {
      return res.status(403).json({
        success: false,
        message: "Administrator permissions have changed. Please log in again.",
      });
    }

    req.admin = {
      id: admin.id,
      fullName: admin.fullName,
      email: admin.email,
      role: admin.role,
    };

    next();
  } catch (error) {
    if (
      ["JsonWebTokenError", "TokenExpiredError", "NotBeforeError"].includes(
        error.name,
      )
    ) {
      return res.status(401).json({
        success: false,
        message: "Invalid or expired authentication token.",
      });
    }

    console.error("Admin authentication error:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to verify administrator access.",
    });
  }
}

function requireAdminRoles(...allowedRoles) {
  return (req, res, next) => {
    if (!req.admin || !allowedRoles.includes(req.admin.role)) {
      return res.status(403).json({
        success: false,
        message: "You do not have permission to perform this action.",
      });
    }

    next();
  };
}

// ==========================================
// SOCKET.IO CONFIGURATION
// ==========================================

const io = new Server(server, {
  cors: {
    origin: ALLOWED_ORIGINS,
    methods: ["GET", "POST"],
  },
});

const dashboardNamespace = io.of("/");

dashboardNamespace.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth?.token;

    if (!token) {
      return next(new Error("Authentication required."));
    }

    const decoded = jwt.verify(token, JWT_SECRET, {
      algorithms: ["HS256"],
    });

    if (decoded.role !== "ADMIN" || !decoded.adminId || !decoded.adminRole) {
      return next(new Error("Administrator access required."));
    }

    const admin = await prisma.admin.findUnique({
      where: { id: decoded.adminId },
      select: {
        id: true,
        fullName: true,
        email: true,
        role: true,
        status: true,
      },
    });

    if (!admin || admin.status !== "ACTIVE") {
      return next(new Error("Administrator account is inactive."));
    }

    if (decoded.adminRole !== admin.role) {
      return next(new Error("Administrator permissions have changed."));
    }

    socket.data.admin = admin;
    next();
  } catch (error) {
    next(new Error("Invalid or expired authentication token."));
  }
});

const gateway = io.of("/gateway");

gateway.use((socket, next) => {
  const token = socket.handshake.auth?.token;

  if (!token || token !== GATEWAY_TOKEN) {
    return next(new Error("Unauthorized gateway connection."));
  }

  next();
});

gateway.on("connection", (socket) => {
  console.log("Authenticated IoT gateway connected:", socket.id);

  socket.on("bin:reading", (reading) => {
    dashboardNamespace.emit("bin:reading", reading);
  });

  socket.on("bin:alert", (alert) => {
    console.log("New bin alert received:", alert?.severity, alert?.binId);
    dashboardNamespace.emit("bin:alert", alert);
  });

  // An alert changed because a sensor reading dropped back below a threshold.
  socket.on("alert:updated", (alert) => {
    dashboardNamespace.emit("alert:updated", alert);
  });

  // The sensor confirms a bin was emptied (from >= 75% to < 30%).
  socket.on("bin:emptied", (event) => {
    console.log("Bin emptied (sensor-confirmed):", event?.binId);
    dashboardNamespace.emit("bin:emptied", event);
  });
});

dashboardNamespace.on("connection", (socket) => {
  console.log(
    "Authenticated admin dashboard connected:",
    socket.data.admin.email,
  );

  socket.on("disconnect", (reason) => {
    console.log("Admin dashboard disconnected:", reason);
  });
});

// ==========================================
// ADMIN LOGIN AND PROFILE
// ==========================================

app.post("/api/admin/login", adminLoginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body || {};

    if (
      typeof email !== "string" ||
      typeof password !== "string" ||
      !email.trim() ||
      !password
    ) {
      return res.status(400).json({
        success: false,
        message: "Email and password are required.",
      });
    }

    const admin = await prisma.admin.findUnique({
      where: { email: email.trim().toLowerCase() },
    });

    if (!admin || admin.status !== "ACTIVE") {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password.",
      });
    }

    const passwordMatches = await bcrypt.compare(password, admin.passwordHash);

    if (!passwordMatches) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password.",
      });
    }

    const token = jwt.sign(
      {
        adminId: admin.id,
        role: "ADMIN",
        adminRole: admin.role,
      },
      JWT_SECRET,
      {
        expiresIn: "8h",
        algorithm: "HS256",
      },
    );

    return res.status(200).json({
      success: true,
      message: "Admin login successful.",
      token,
      admin: {
        id: admin.id,
        fullName: admin.fullName,
        email: admin.email,
        role: admin.role,
        status: admin.status,
      },
    });
  } catch (error) {
    console.error("Admin login error:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to complete admin login.",
    });
  }
});

app.get("/api/admin/me", authenticateAdmin, (req, res) => {
  return res.status(200).json({
    success: true,
    data: req.admin,
  });
});

// ==========================================
// COLLECTOR LOGIN
// ==========================================

app.post("/api/collector/login", collectorLoginLimiter, async (req, res) => {
  try {
    const { identifier, email, password } = req.body || {};

    const loginIdentifier =
      typeof identifier === "string"
        ? identifier.trim()
        : typeof email === "string"
          ? email.trim()
          : "";

    if (!loginIdentifier || typeof password !== "string" || !password) {
      return res.status(400).json({
        success: false,
        message: "Email/phone and password are required.",
      });
    }

    const collector = await prisma.collector.findFirst({
      where: loginIdentifier.includes("@")
        ? { email: loginIdentifier.toLowerCase() }
        : { phone: loginIdentifier },
    });

    if (
      !collector ||
      !collector.passwordHash ||
      collector.status !== "ACTIVE"
    ) {
      return res.status(401).json({
        success: false,
        message: "Invalid login credentials.",
      });
    }

    const passwordMatches = await bcrypt.compare(
      password,
      collector.passwordHash,
    );

    if (!passwordMatches) {
      return res.status(401).json({
        success: false,
        message: "Invalid login credentials.",
      });
    }

    const token = jwt.sign(
      {
        collectorId: collector.id,
        role: "COLLECTOR",
      },
      JWT_SECRET,
      { expiresIn: "8h", algorithm: "HS256" },
    );

    return res.status(200).json({
      success: true,
      message: "Login successful.",
      token,
      collector: {
        id: collector.id,
        fullName: collector.fullName,
        email: collector.email,
        phone: collector.phone,
        address: collector.address,
        status: collector.status,
      },
    });
  } catch (error) {
    console.error("Collector login error:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to log in.",
    });
  }
});

// ==========================================
// ADMIN ROUTE PROTECTION
// Register BEFORE protected route handlers.
// ==========================================

const ALL_ADMIN_ROLES = ["SUPER_ADMIN", "ADMIN", "OPERATIONS_MANAGER"];
const MANAGER_ROLES = ["SUPER_ADMIN", "ADMIN"];

// Every admin role may READ; only SUPER_ADMIN/ADMIN may create or modify
// bins and collectors. Operations managers handle alerts and assignments.
function readAllWriteManagers(req, res, next) {
  const roles = req.method === "GET" ? ALL_ADMIN_ROLES : MANAGER_ROLES;
  return requireAdminRoles(...roles)(req, res, next);
}

app.use("/api/bins", authenticateAdmin, readAllWriteManagers);
app.use("/api/collectors", authenticateAdmin, readAllWriteManagers);
app.use(
  "/api/assignments",
  authenticateAdmin,
  requireAdminRoles(...ALL_ADMIN_ROLES),
);
app.use(
  "/api/alerts",
  authenticateAdmin,
  requireAdminRoles(...ALL_ADMIN_ROLES),
);
app.use("/api/stats", authenticateAdmin, requireAdminRoles(...ALL_ADMIN_ROLES));
app.use("/api/admins", authenticateAdmin, requireAdminRoles("SUPER_ADMIN"));

// ==========================================
// HEALTH CHECK
// ==========================================

app.get("/api/health", async (req, res) => {
  try {
    await prisma.$queryRaw`SELECT 1`;

    return res.status(200).json({
      success: true,
      message: "EcoTrack API is running.",
      database: "Connected",
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    console.error("Health check error:", error);

    return res.status(503).json({
      success: false,
      message: "Database connection failed.",
    });
  }
});

// ==========================================
// BIN API
// ==========================================

app.get("/api/bins", async (req, res) => {
  try {
    const bins = await prisma.bin.findMany({
      include: {
        _count: {
          select: { readings: true },
        },
        readings: {
          orderBy: { receivedAt: "desc" },
          take: 1,
        },
      },
      orderBy: { createdAt: "desc" },
    });

    const formattedBins = bins.map((bin) => ({
      ...bin,
      latestReading: bin.readings[0] || null,
      readings: undefined,
    }));

    return res.status(200).json({
      success: true,
      count: formattedBins.length,
      data: formattedBins,
    });
  } catch (error) {
    console.error("Fetch bins error:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to retrieve bins.",
    });
  }
});

app.get("/api/bins/:binId", async (req, res) => {
  try {
    const bin = await prisma.bin.findUnique({
      where: { binId: req.params.binId },
      include: {
        _count: {
          select: { readings: true },
        },
      },
    });

    if (!bin) {
      return res.status(404).json({
        success: false,
        message: "Bin not found.",
      });
    }

    return res.status(200).json({
      success: true,
      data: bin,
    });
  } catch (error) {
    console.error("Fetch bin error:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to retrieve bin.",
    });
  }
});

app.get("/api/bins/:binId/readings", async (req, res) => {
  try {
    const bin = await prisma.bin.findUnique({
      where: { binId: req.params.binId },
      select: { binId: true },
    });

    if (!bin) {
      return res.status(404).json({
        success: false,
        message: "Bin not found.",
      });
    }

    const requestedLimit = Number.parseInt(req.query.limit, 10);
    const limit = Number.isNaN(requestedLimit)
      ? 20
      : Math.min(Math.max(requestedLimit, 1), 100);

    const readings = await prisma.sensorReading.findMany({
      where: { binId: bin.binId },
      orderBy: { receivedAt: "desc" },
      take: limit,
    });

    return res.status(200).json({
      success: true,
      binId: bin.binId,
      count: readings.length,
      data: readings,
    });
  } catch (error) {
    console.error("Fetch sensor readings error:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to retrieve sensor readings.",
    });
  }
});

// ==========================================
// ALERT API
// ==========================================

app.get("/api/alerts", async (req, res) => {
  try {
    const { status, severity } = req.query;

    const requestedLimit = Number.parseInt(req.query.limit, 10);
    const limit = Number.isNaN(requestedLimit)
      ? 50
      : Math.min(Math.max(requestedLimit, 1), 100);

    const validStatuses = ["ACTIVE", "ACKNOWLEDGED", "RESOLVED"];
    const validSeverities = ["HIGH", "CRITICAL"];

    if (status && !validStatuses.includes(status)) {
      return res.status(400).json({
        success: false,
        message: "Invalid alert status.",
      });
    }

    if (severity && !validSeverities.includes(severity)) {
      return res.status(400).json({
        success: false,
        message: "Invalid alert severity.",
      });
    }

    const alerts = await prisma.binAlert.findMany({
      where: {
        ...(status ? { status } : {}),
        ...(severity ? { severity } : {}),
      },
      include: {
        bin: {
          select: {
            binId: true,
            name: true,
            location: true,
          },
        },
      },
      orderBy: { createdAt: "desc" },
      take: limit,
    });

    return res.status(200).json({
      success: true,
      count: alerts.length,
      data: alerts,
    });
  } catch (error) {
    console.error("Fetch alerts error:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to retrieve alerts.",
    });
  }
});

app.patch("/api/alerts/:id/acknowledge", async (req, res) => {
  try {
    const result = await prisma.binAlert.updateMany({
      where: {
        id: req.params.id,
        status: "ACTIVE",
      },
      data: {
        status: "ACKNOWLEDGED",
        acknowledgedAt: new Date(),
      },
    });

    if (result.count === 0) {
      const existing = await prisma.binAlert.findUnique({
        where: { id: req.params.id },
      });

      if (!existing) {
        return res.status(404).json({
          success: false,
          message: "Alert not found.",
        });
      }

      return res.status(409).json({
        success: false,
        message: "Only active alerts can be acknowledged.",
      });
    }

    const updatedAlert = await prisma.binAlert.findUnique({
      where: { id: req.params.id },
      include: {
        bin: {
          select: {
            binId: true,
            name: true,
            location: true,
          },
        },
      },
    });

    dashboardNamespace.emit("alert:updated", updatedAlert);

    return res.status(200).json({
      success: true,
      message: "Alert acknowledged successfully.",
      data: updatedAlert,
    });
  } catch (error) {
    console.error("Acknowledge alert error:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to acknowledge alert.",
    });
  }
});

app.patch("/api/alerts/:id/resolve", async (req, res) => {
  try {
    const result = await prisma.binAlert.updateMany({
      where: {
        id: req.params.id,
        status: { in: ["ACTIVE", "ACKNOWLEDGED"] },
      },
      data: {
        status: "RESOLVED",
        resolvedAt: new Date(),
      },
    });

    if (result.count === 0) {
      const existing = await prisma.binAlert.findUnique({
        where: { id: req.params.id },
      });

      if (!existing) {
        return res.status(404).json({
          success: false,
          message: "Alert not found.",
        });
      }

      return res.status(409).json({
        success: false,
        message: "This alert has already been resolved.",
      });
    }

    const updatedAlert = await prisma.binAlert.findUnique({
      where: { id: req.params.id },
      include: {
        bin: {
          select: {
            binId: true,
            name: true,
            location: true,
          },
        },
      },
    });

    dashboardNamespace.emit("alert:updated", updatedAlert);

    return res.status(200).json({
      success: true,
      message: "Alert resolved successfully.",
      data: updatedAlert,
    });
  } catch (error) {
    console.error("Resolve alert error:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to resolve alert.",
    });
  }
});

// ==========================================
// COLLECTOR MANAGEMENT
// ==========================================

app.post("/api/collectors", async (req, res) => {
  try {
    const { fullName, email, phone, address, password } = req.body || {};

    if (
      typeof fullName !== "string" ||
      !fullName.trim() ||
      typeof phone !== "string" ||
      !phone.trim()
    ) {
      return res.status(400).json({
        success: false,
        message: "Full name and phone number are required.",
      });
    }

    if (typeof password !== "string" || password.length < 8) {
      return res.status(400).json({
        success: false,
        message: "A password of at least 8 characters is required.",
      });
    }

    if (email !== undefined && email !== null && typeof email !== "string") {
      return res.status(400).json({
        success: false,
        message: "Email must be a string.",
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const collector = await prisma.collector.create({
      data: {
        fullName: fullName.trim(),
        email:
          typeof email === "string" && email.trim()
            ? email.trim().toLowerCase()
            : null,
        phone: phone.trim(),
        address:
          typeof address === "string" && address.trim() ? address.trim() : null,
        passwordHash,
        status: "ACTIVE",
      },
    });

    return res.status(201).json({
      success: true,
      message: "Collector registered successfully.",
      data: removePasswordHash(collector),
    });
  } catch (error) {
    if (error.code === "P2002") {
      return res.status(409).json({
        success: false,
        message: "A collector with this email or phone number already exists.",
      });
    }

    console.error("Register collector error:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to register collector.",
    });
  }
});

app.get("/api/collectors", async (req, res) => {
  try {
    const { status, search } = req.query;
    const where = {};

    if (status) {
      if (!["ACTIVE", "INACTIVE"].includes(status)) {
        return res.status(400).json({
          success: false,
          message: "Invalid collector status.",
        });
      }

      where.status = status;
    }

    if (search && typeof search === "string") {
      where.OR = [
        { fullName: { contains: search, mode: "insensitive" } },
        { email: { contains: search, mode: "insensitive" } },
        { phone: { contains: search, mode: "insensitive" } },
      ];
    }

    const collectors = await prisma.collector.findMany({
      where,
      include: {
        _count: {
          select: { assignments: true },
        },
      },
      orderBy: { createdAt: "desc" },
    });

    return res.status(200).json({
      success: true,
      count: collectors.length,
      data: collectors.map(removePasswordHash),
    });
  } catch (error) {
    console.error("Fetch collectors error:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to retrieve collectors.",
    });
  }
});

app.get("/api/collectors/:id", async (req, res) => {
  try {
    const collector = await prisma.collector.findUnique({
      where: { id: req.params.id },
      include: {
        assignments: {
          orderBy: { createdAt: "desc" },
        },
      },
    });

    if (!collector) {
      return res.status(404).json({
        success: false,
        message: "Collector not found.",
      });
    }

    return res.status(200).json({
      success: true,
      data: removePasswordHash(collector),
    });
  } catch (error) {
    console.error("Fetch collector error:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to retrieve collector.",
    });
  }
});

app.patch("/api/collectors/:id", async (req, res) => {
  try {
    const { fullName, email, phone, address, password } = req.body || {};
    const data = {};

    if (fullName !== undefined) {
      if (typeof fullName !== "string" || !fullName.trim()) {
        return res.status(400).json({
          success: false,
          message: "Full name cannot be empty.",
        });
      }

      data.fullName = fullName.trim();
    }

    if (email !== undefined) {
      if (email !== null && typeof email !== "string") {
        return res.status(400).json({
          success: false,
          message: "Email must be a string or null.",
        });
      }

      data.email =
        typeof email === "string" && email.trim()
          ? email.trim().toLowerCase()
          : null;
    }

    if (phone !== undefined) {
      if (typeof phone !== "string" || !phone.trim()) {
        return res.status(400).json({
          success: false,
          message: "Phone number cannot be empty.",
        });
      }

      data.phone = phone.trim();
    }

    if (address !== undefined) {
      if (address !== null && typeof address !== "string") {
        return res.status(400).json({
          success: false,
          message: "Address must be a string or null.",
        });
      }

      data.address =
        typeof address === "string" && address.trim() ? address.trim() : null;
    }

    if (password !== undefined) {
      if (typeof password !== "string" || password.length < 8) {
        return res.status(400).json({
          success: false,
          message: "Password must contain at least 8 characters.",
        });
      }

      data.passwordHash = await bcrypt.hash(password, 12);
    }

    if (Object.keys(data).length === 0) {
      return res.status(400).json({
        success: false,
        message: "Provide at least one field to update.",
      });
    }

    const collector = await prisma.collector.update({
      where: { id: req.params.id },
      data,
    });

    return res.status(200).json({
      success: true,
      message: "Collector updated successfully.",
      data: removePasswordHash(collector),
    });
  } catch (error) {
    if (error.code === "P2002") {
      return res.status(409).json({
        success: false,
        message: "This email or phone number is already in use.",
      });
    }

    if (error.code === "P2025") {
      return res.status(404).json({
        success: false,
        message: "Collector not found.",
      });
    }

    console.error("Update collector error:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to update collector.",
    });
  }
});

app.patch("/api/collectors/:id/status", async (req, res) => {
  try {
    const { status } = req.body || {};

    if (!["ACTIVE", "INACTIVE"].includes(status)) {
      return res.status(400).json({
        success: false,
        message: "Status must be ACTIVE or INACTIVE.",
      });
    }

    const collector = await prisma.collector.update({
      where: { id: req.params.id },
      data: { status },
    });

    return res.status(200).json({
      success: true,
      message: `Collector ${status.toLowerCase()} successfully.`,
      data: removePasswordHash(collector),
    });
  } catch (error) {
    if (error.code === "P2025") {
      return res.status(404).json({
        success: false,
        message: "Collector not found.",
      });
    }

    console.error("Change collector status error:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to update collector status.",
    });
  }
});

// ==========================================
// ASSIGNMENT CREATION AND RETRIEVAL
// ==========================================

app.post("/api/assignments", async (req, res) => {
  try {
    const { binId, collectorId, scheduledFor, priority, notes, alertId } =
      req.body || {};

    if (
      typeof binId !== "string" ||
      !binId.trim() ||
      typeof collectorId !== "string" ||
      !collectorId.trim()
    ) {
      return res.status(400).json({
        success: false,
        message: "Bin ID and collector ID are required.",
      });
    }

    const validPriorities = ["NORMAL", "HIGH", "CRITICAL"];
    const assignmentPriority = priority || "NORMAL";

    if (!validPriorities.includes(assignmentPriority)) {
      return res.status(400).json({
        success: false,
        message: "Priority must be NORMAL, HIGH, or CRITICAL.",
      });
    }

    let scheduledDate = null;

    if (scheduledFor !== undefined && scheduledFor !== null) {
      scheduledDate = new Date(scheduledFor);

      if (Number.isNaN(scheduledDate.getTime())) {
        return res.status(400).json({
          success: false,
          message: "Invalid scheduled collection date.",
        });
      }
    }

    const bin = await prisma.bin.findUnique({
      where: { binId: binId.trim() },
    });

    if (!bin) {
      return res.status(404).json({
        success: false,
        message: "Smart bin not found.",
      });
    }

    const collector = await prisma.collector.findUnique({
      where: { id: collectorId.trim() },
    });

    if (!collector) {
      return res.status(404).json({
        success: false,
        message: "Collector not found.",
      });
    }

    if (collector.status !== "ACTIVE") {
      return res.status(400).json({
        success: false,
        message: "This collector is inactive and cannot receive assignments.",
      });
    }

    if (typeof alertId === "string" && alertId.trim()) {
      const linkedAlert = await prisma.binAlert.findUnique({
        where: { id: alertId.trim() },
        select: { binId: true },
      });

      if (!linkedAlert || linkedAlert.binId !== bin.binId) {
        return res.status(400).json({
          success: false,
          message: "The linked alert does not exist for this bin.",
        });
      }
    }

    const activeStatuses = [
      "ASSIGNED",
      "ACCEPTED",
      "IN_PROGRESS",
      "ISSUE_REPORTED",
    ];

    const existingAssignment = await prisma.collectionAssignment.findFirst({
      where: {
        binId: bin.binId,
        status: { in: activeStatuses },
      },
    });

    if (existingAssignment) {
      return res.status(409).json({
        success: false,
        message: "This bin already has an active collection assignment.",
        existingAssignmentId: existingAssignment.id,
      });
    }

    const assignment = await prisma.collectionAssignment.create({
      data: {
        binId: bin.binId,
        collectorId: collector.id,
        priority: assignmentPriority,
        scheduledFor: scheduledDate,
        notes: typeof notes === "string" && notes.trim() ? notes.trim() : null,
        status: "ASSIGNED",
        ...(typeof alertId === "string" && alertId.trim()
          ? { binAlertId: alertId.trim() }
          : {}),
        statusHistory: {
          create: {
            status: "ASSIGNED",
            note: "Collection assigned by administrator.",
          },
        },
      },
      include: {
        bin: true,
        collector: true,
        statusHistory: true,
      },
    });

    const safeAssignment = removeAssignmentPasswordHashes(assignment);

    await publishAssignmentUpdate(assignment, "ADMIN");

    return res.status(201).json({
      success: true,
      message: "Collection assigned successfully.",
      data: safeAssignment,
    });
  } catch (error) {
    if (isUniqueBinAssignmentError(error)) {
      return res.status(409).json({
        success: false,
        message: "This bin already has an active collection assignment.",
      });
    }

    console.error("Create assignment error:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to create collection assignment.",
    });
  }
});

app.get("/api/assignments", async (req, res) => {
  try {
    const { status, collectorId, binId } = req.query;

    const validStatuses = [
      "ASSIGNED",
      "ACCEPTED",
      "IN_PROGRESS",
      "COMPLETED",
      "CANCELLED",
      "ISSUE_REPORTED",
    ];

    if (status && !validStatuses.includes(status)) {
      return res.status(400).json({
        success: false,
        message: "Invalid assignment status.",
      });
    }

    const where = {};

    if (status) where.status = status;
    if (collectorId) where.collectorId = collectorId;
    if (binId) where.binId = binId;

    const assignments = await prisma.collectionAssignment.findMany({
      where,
      include: {
        bin: {
          include: {
            readings: { orderBy: { receivedAt: "desc" }, take: 1 },
          },
        },
        collector: true,
        statusHistory: {
          orderBy: { changedAt: "asc" },
        },
      },
      orderBy: { createdAt: "desc" },
    });

    return res.status(200).json({
      success: true,
      count: assignments.length,
      data: assignments.map(removeAssignmentPasswordHashes),
    });
  } catch (error) {
    console.error("Fetch assignments error:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to retrieve collection assignments.",
    });
  }
});

app.get("/api/assignments/:id", async (req, res) => {
  try {
    const assignment = await prisma.collectionAssignment.findUnique({
      where: { id: req.params.id },
      include: {
        bin: {
          include: {
            readings: {
              orderBy: { receivedAt: "desc" },
              take: 1,
            },
          },
        },
        collector: true,
        statusHistory: {
          orderBy: { changedAt: "asc" },
        },
      },
    });

    if (!assignment) {
      return res.status(404).json({
        success: false,
        message: "Collection assignment not found.",
      });
    }

    return res.status(200).json({
      success: true,
      data: removeAssignmentPasswordHashes(assignment),
    });
  } catch (error) {
    console.error("Fetch assignment error:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to retrieve collection assignment.",
    });
  }
});

// ==========================================
// ADMIN FEEDBACK ON A COMPLETED COLLECTION
// ==========================================

// Stored as a status-history row so no database change is needed. The web
// apps recognise the "__feedback__:" prefix and show it as a message.
const FEEDBACK_PREFIX = "__feedback__:";

app.post("/api/assignments/:id/feedback", async (req, res) => {
  try {
    const { message } = req.body || {};

    if (
      typeof message !== "string" ||
      !message.trim() ||
      message.trim().length > 300
    ) {
      return res.status(400).json({
        success: false,
        message: "Enter a message of up to 300 characters.",
      });
    }

    const existing = await prisma.collectionAssignment.findUnique({
      where: { id: req.params.id },
      select: { id: true, status: true },
    });

    if (!existing) {
      return res.status(404).json({
        success: false,
        message: "Collection assignment not found.",
      });
    }

    if (existing.status !== "COMPLETED") {
      return res.status(409).json({
        success: false,
        message: "Feedback can only be sent for completed collections.",
      });
    }

    await prisma.collectionStatusHistory.create({
      data: {
        assignmentId: existing.id,
        status: "COMPLETED",
        note:
          FEEDBACK_PREFIX +
          JSON.stringify({
            from: req.admin.fullName,
            message: message.trim(),
          }),
      },
    });

    const assignment = await prisma.collectionAssignment.findUnique({
      where: { id: existing.id },
      include: {
        bin: true,
        collector: true,
        statusHistory: { orderBy: { changedAt: "asc" } },
      },
    });

    await publishAssignmentUpdate(assignment, "ADMIN");

    return res.status(201).json({
      success: true,
      message: "Feedback sent to the collector.",
      data: removeAssignmentPasswordHashes(assignment),
    });
  } catch (error) {
    console.error("Send feedback error:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to send feedback.",
    });
  }
});

// ==========================================
// SHARED ASSIGNMENT STATUS UPDATE
// ==========================================

const adminTransitions = {
  ASSIGNED: ["ACCEPTED", "CANCELLED"],
  ACCEPTED: ["IN_PROGRESS", "CANCELLED", "ISSUE_REPORTED"],
  IN_PROGRESS: ["COMPLETED", "ISSUE_REPORTED"],
  ISSUE_REPORTED: ["IN_PROGRESS", "CANCELLED"],
  COMPLETED: [],
  CANCELLED: [],
};

const collectorTransitions = {
  ASSIGNED: ["ACCEPTED"],
  ACCEPTED: ["IN_PROGRESS", "ISSUE_REPORTED"],
  IN_PROGRESS: ["COMPLETED", "ISSUE_REPORTED"],
  ISSUE_REPORTED: ["IN_PROGRESS"],
  COMPLETED: [],
  CANCELLED: [],
};

async function updateAssignmentStatus({
  assignmentId,
  requestedStatus,
  note,
  collectorId = null,
  transitions,
}) {
  return prisma.$transaction(async (tx) => {
    const assignment = await tx.collectionAssignment.findFirst({
      where: {
        id: assignmentId,
        ...(collectorId ? { collectorId } : {}),
      },
    });

    if (!assignment) {
      const error = new Error("ASSIGNMENT_NOT_FOUND");
      throw error;
    }

    const allowedTransitions = transitions[assignment.status] || [];

    if (!allowedTransitions.includes(requestedStatus)) {
      const error = new Error("INVALID_STATUS_TRANSITION");
      error.currentStatus = assignment.status;
      error.requestedStatus = requestedStatus;
      throw error;
    }

    const timestamp = new Date();
    const timestampUpdates = {};

    if (requestedStatus === "ACCEPTED") {
      timestampUpdates.acceptedAt = timestamp;
    }

    if (requestedStatus === "IN_PROGRESS") {
      timestampUpdates.startedAt = timestamp;
    }

    if (requestedStatus === "COMPLETED") {
      timestampUpdates.completedAt = timestamp;
    }

    // Conditional update prevents two concurrent requests from
    // changing the same assignment from the same previous status.
    const result = await tx.collectionAssignment.updateMany({
      where: {
        id: assignmentId,
        status: assignment.status,
        ...(collectorId ? { collectorId } : {}),
      },
      data: {
        status: requestedStatus,
        ...timestampUpdates,
      },
    });

    if (result.count !== 1) {
      const error = new Error("CONCURRENT_STATUS_UPDATE");
      throw error;
    }

    await tx.collectionStatusHistory.create({
      data: {
        assignmentId,
        status: requestedStatus,
        note: note?.trim() || null,
      },
    });

    // A completed collection empties the bin, so close its open alerts.
    let resolvedAlertIds = [];

    if (requestedStatus === "COMPLETED") {
      const openAlerts = await tx.binAlert.findMany({
        where: {
          binId: assignment.binId,
          status: { in: ["ACTIVE", "ACKNOWLEDGED"] },
        },
        select: { id: true },
      });

      resolvedAlertIds = openAlerts.map((alert) => alert.id);

      if (resolvedAlertIds.length > 0) {
        await tx.binAlert.updateMany({
          where: { id: { in: resolvedAlertIds } },
          data: { status: "RESOLVED", resolvedAt: timestamp },
        });
      }
    }

    const updated = await tx.collectionAssignment.findUnique({
      where: { id: assignmentId },
      include: {
        bin: true,
        collector: true,
        statusHistory: {
          orderBy: { changedAt: "asc" },
        },
      },
    });

    return { assignment: updated, resolvedAlertIds };
  });
}

// Tell every signed-in dashboard what just happened. `changedBy` lets the
// admin UI word notifications ("collector completed...") correctly.
async function publishAssignmentUpdate(
  assignment,
  changedBy,
  resolvedAlertIds = [],
) {
  dashboardNamespace.emit("assignment:updated", {
    ...removeAssignmentPasswordHashes(assignment),
    changedBy,
  });

  if (resolvedAlertIds.length === 0) return;

  try {
    const alerts = await prisma.binAlert.findMany({
      where: { id: { in: resolvedAlertIds } },
      include: {
        bin: { select: { binId: true, name: true, location: true } },
      },
    });

    alerts.forEach((alert) => dashboardNamespace.emit("alert:updated", alert));
  } catch (error) {
    console.error("Could not publish resolved alerts:", error);
  }
}

function validateStatusRequest(req, res) {
  const { status, note } = req.body || {};

  if (typeof status !== "string" || !status.trim()) {
    res.status(400).json({
      success: false,
      message: "Collection status is required.",
    });
    return null;
  }

  if (note !== undefined && note !== null && typeof note !== "string") {
    res.status(400).json({
      success: false,
      message: "Note must be a string.",
    });
    return null;
  }

  if (
    status === "ISSUE_REPORTED" &&
    (typeof note !== "string" || !note.trim())
  ) {
    res.status(400).json({
      success: false,
      message: "A note describing the issue is required.",
    });
    return null;
  }

  return {
    status: status.trim(),
    note,
  };
}

function handleAssignmentStatusError(error, res) {
  if (error.message === "ASSIGNMENT_NOT_FOUND") {
    return res.status(404).json({
      success: false,
      message: "Collection assignment not found.",
    });
  }

  if (error.message === "INVALID_STATUS_TRANSITION") {
    return res.status(409).json({
      success: false,
      message: `Cannot change status from ${error.currentStatus} to ${error.requestedStatus}.`,
      currentStatus: error.currentStatus,
      requestedStatus: error.requestedStatus,
    });
  }

  if (error.message === "CONCURRENT_STATUS_UPDATE") {
    return res.status(409).json({
      success: false,
      message:
        "This assignment was updated by another request. Refresh and try again.",
    });
  }

  console.error("Assignment status update error:", error);

  return res.status(500).json({
    success: false,
    message: "Unable to update collection status.",
  });
}

// Admin updates assignment status
app.patch("/api/assignments/:id/status", async (req, res) => {
  const input = validateStatusRequest(req, res);

  if (!input) return;

  try {
    const { assignment, resolvedAlertIds } = await updateAssignmentStatus({
      assignmentId: req.params.id,
      requestedStatus: input.status,
      note: input.note,
      transitions: adminTransitions,
    });

    const safeAssignment = removeAssignmentPasswordHashes(assignment);

    await publishAssignmentUpdate(assignment, "ADMIN", resolvedAlertIds);

    return res.status(200).json({
      success: true,
      message: `Collection status updated to ${input.status}.`,
      data: safeAssignment,
    });
  } catch (error) {
    return handleAssignmentStatusError(error, res);
  }
});

// ==========================================
// BIN MANAGEMENT (create / update)
// ==========================================

const BIN_STATUSES = ["ACTIVE", "INACTIVE", "MAINTENANCE"];

app.post("/api/bins", async (req, res) => {
  try {
    const { binId, name, location, status } = req.body || {};

    if (
      typeof binId !== "string" ||
      !/^[A-Za-z0-9_-]{3,100}$/.test(binId.trim())
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Bin ID is required (3-100 letters, numbers, hyphens or underscores).",
      });
    }

    if (status !== undefined && !BIN_STATUSES.includes(status)) {
      return res.status(400).json({
        success: false,
        message: `Status must be one of ${BIN_STATUSES.join(", ")}.`,
      });
    }

    for (const [label, value] of [
      ["Name", name],
      ["Location", location],
    ]) {
      if (value !== undefined && value !== null && typeof value !== "string") {
        return res.status(400).json({
          success: false,
          message: `${label} must be a string.`,
        });
      }
    }

    const bin = await prisma.bin.create({
      data: {
        binId: binId.trim(),
        name: typeof name === "string" && name.trim() ? name.trim() : null,
        location:
          typeof location === "string" && location.trim()
            ? location.trim()
            : null,
        status: status || "ACTIVE",
      },
    });

    return res.status(201).json({
      success: true,
      message: "Smart bin registered successfully.",
      data: { ...bin, latestReading: null, _count: { readings: 0 } },
    });
  } catch (error) {
    if (error.code === "P2002") {
      return res.status(409).json({
        success: false,
        message: "A bin with this Bin ID already exists.",
      });
    }

    console.error("Create bin error:", error);
    return res.status(500).json({
      success: false,
      message: "Unable to register bin.",
    });
  }
});

app.patch("/api/bins/:binId", async (req, res) => {
  try {
    const { name, location, status } = req.body || {};
    const data = {};

    if (name !== undefined) {
      if (name !== null && typeof name !== "string") {
        return res.status(400).json({
          success: false,
          message: "Name must be a string or null.",
        });
      }
      data.name = typeof name === "string" && name.trim() ? name.trim() : null;
    }

    if (location !== undefined) {
      if (location !== null && typeof location !== "string") {
        return res.status(400).json({
          success: false,
          message: "Location must be a string or null.",
        });
      }
      data.location =
        typeof location === "string" && location.trim()
          ? location.trim()
          : null;
    }

    if (status !== undefined) {
      if (!BIN_STATUSES.includes(status)) {
        return res.status(400).json({
          success: false,
          message: `Status must be one of ${BIN_STATUSES.join(", ")}.`,
        });
      }
      data.status = status;
    }

    if (Object.keys(data).length === 0) {
      return res.status(400).json({
        success: false,
        message: "Provide at least one field to update.",
      });
    }

    const bin = await prisma.bin.update({
      where: { binId: req.params.binId },
      data,
    });

    return res.status(200).json({
      success: true,
      message: "Bin updated successfully.",
      data: bin,
    });
  } catch (error) {
    if (error.code === "P2025") {
      return res.status(404).json({
        success: false,
        message: "Bin not found.",
      });
    }

    console.error("Update bin error:", error);
    return res.status(500).json({
      success: false,
      message: "Unable to update bin.",
    });
  }
});

// ==========================================
// DASHBOARD STATISTICS AND ANALYTICS
// ==========================================

app.get("/api/stats/overview", async (req, res) => {
  try {
    const [
      totalBins,
      activeBins,
      activeCollectors,
      openAlerts,
      criticalAlerts,
      assignmentGroups,
    ] = await Promise.all([
      prisma.bin.count(),
      prisma.bin.count({ where: { status: "ACTIVE" } }),
      prisma.collector.count({ where: { status: "ACTIVE" } }),
      prisma.binAlert.count({
        where: { status: { in: ["ACTIVE", "ACKNOWLEDGED"] } },
      }),
      prisma.binAlert.count({
        where: { status: "ACTIVE", severity: "CRITICAL" },
      }),
      prisma.collectionAssignment.groupBy({
        by: ["status"],
        _count: { _all: true },
      }),
    ]);

    const assignments = {};
    for (const group of assignmentGroups) {
      assignments[group.status] = group._count._all;
    }

    return res.status(200).json({
      success: true,
      data: {
        totalBins,
        activeBins,
        activeCollectors,
        openAlerts,
        criticalAlerts,
        assignments,
      },
    });
  } catch (error) {
    console.error("Overview stats error:", error);
    return res.status(500).json({
      success: false,
      message: "Unable to retrieve statistics.",
    });
  }
});

// Collections completed per day and alerts raised per day (last N days).
app.get("/api/stats/analytics", async (req, res) => {
  try {
    const requested = Number.parseInt(req.query.days, 10);
    const days = Number.isNaN(requested)
      ? 14
      : Math.min(Math.max(requested, 1), 90);

    const since = new Date();
    since.setHours(0, 0, 0, 0);
    since.setDate(since.getDate() - (days - 1));

    const [completed, alerts, collectorGroups] = await Promise.all([
      prisma.collectionAssignment.findMany({
        where: { status: "COMPLETED", completedAt: { gte: since } },
        select: { completedAt: true },
      }),
      prisma.binAlert.findMany({
        where: { createdAt: { gte: since } },
        select: { createdAt: true, severity: true },
      }),
      prisma.collectionAssignment.groupBy({
        by: ["collectorId"],
        where: { status: "COMPLETED" },
        _count: { _all: true },
      }),
    ]);

    const dayKey = (date) => new Date(date).toISOString().slice(0, 10);
    const series = new Map();

    for (let i = 0; i < days; i += 1) {
      const day = new Date(since);
      day.setDate(since.getDate() + i);
      series.set(dayKey(day), { date: dayKey(day), collections: 0, alerts: 0 });
    }

    for (const item of completed) {
      const entry = series.get(dayKey(item.completedAt));
      if (entry) entry.collections += 1;
    }

    for (const item of alerts) {
      const entry = series.get(dayKey(item.createdAt));
      if (entry) entry.alerts += 1;
    }

    const collectorIds = collectorGroups.map((group) => group.collectorId);
    const collectors = collectorIds.length
      ? await prisma.collector.findMany({
          where: { id: { in: collectorIds } },
          select: { id: true, fullName: true },
        })
      : [];

    const names = new Map(collectors.map((c) => [c.id, c.fullName]));

    const topCollectors = collectorGroups
      .map((group) => ({
        collectorId: group.collectorId,
        fullName: names.get(group.collectorId) || "Unknown",
        completed: group._count._all,
      }))
      .sort((a, b) => b.completed - a.completed)
      .slice(0, 5);

    return res.status(200).json({
      success: true,
      data: { days, daily: [...series.values()], topCollectors },
    });
  } catch (error) {
    console.error("Analytics error:", error);
    return res.status(500).json({
      success: false,
      message: "Unable to retrieve analytics.",
    });
  }
});

// ==========================================
// ADMIN TEAM MANAGEMENT (SUPER_ADMIN only)
// ==========================================

const ADMIN_ROLES = ["SUPER_ADMIN", "ADMIN", "OPERATIONS_MANAGER"];
const ADMIN_PUBLIC_FIELDS = {
  id: true,
  fullName: true,
  email: true,
  role: true,
  status: true,
  createdAt: true,
};

app.get("/api/admins", async (req, res) => {
  try {
    const admins = await prisma.admin.findMany({
      select: ADMIN_PUBLIC_FIELDS,
      orderBy: { createdAt: "asc" },
    });

    return res.status(200).json({
      success: true,
      count: admins.length,
      data: admins,
    });
  } catch (error) {
    console.error("Fetch admins error:", error);
    return res.status(500).json({
      success: false,
      message: "Unable to retrieve administrators.",
    });
  }
});

app.post("/api/admins", async (req, res) => {
  try {
    const { fullName, email, password, role } = req.body || {};

    if (
      typeof fullName !== "string" ||
      !fullName.trim() ||
      typeof email !== "string" ||
      !/^\S+@\S+\.\S+$/.test(email.trim())
    ) {
      return res.status(400).json({
        success: false,
        message: "A full name and valid email are required.",
      });
    }

    if (typeof password !== "string" || password.length < 12) {
      return res.status(400).json({
        success: false,
        message: "Admin passwords must contain at least 12 characters.",
      });
    }

    if (role !== undefined && !ADMIN_ROLES.includes(role)) {
      return res.status(400).json({
        success: false,
        message: `Role must be one of ${ADMIN_ROLES.join(", ")}.`,
      });
    }

    const admin = await prisma.admin.create({
      data: {
        fullName: fullName.trim(),
        email: email.trim().toLowerCase(),
        passwordHash: await bcrypt.hash(password, 12),
        role: role || "ADMIN",
        status: "ACTIVE",
      },
      select: ADMIN_PUBLIC_FIELDS,
    });

    return res.status(201).json({
      success: true,
      message: "Administrator created successfully.",
      data: admin,
    });
  } catch (error) {
    if (error.code === "P2002") {
      return res.status(409).json({
        success: false,
        message: "An administrator with this email already exists.",
      });
    }

    console.error("Create admin error:", error);
    return res.status(500).json({
      success: false,
      message: "Unable to create administrator.",
    });
  }
});

app.patch("/api/admins/:id", async (req, res) => {
  try {
    const { role, status } = req.body || {};
    const data = {};

    if (role !== undefined) {
      if (!ADMIN_ROLES.includes(role)) {
        return res.status(400).json({
          success: false,
          message: `Role must be one of ${ADMIN_ROLES.join(", ")}.`,
        });
      }
      data.role = role;
    }

    if (status !== undefined) {
      if (!["ACTIVE", "INACTIVE"].includes(status)) {
        return res.status(400).json({
          success: false,
          message: "Status must be ACTIVE or INACTIVE.",
        });
      }
      data.status = status;
    }

    if (Object.keys(data).length === 0) {
      return res.status(400).json({
        success: false,
        message: "Provide a role or status to update.",
      });
    }

    // Prevent a super admin from locking themselves out.
    if (
      req.params.id === req.admin.id &&
      (data.status === "INACTIVE" || (data.role && data.role !== "SUPER_ADMIN"))
    ) {
      return res.status(400).json({
        success: false,
        message: "You cannot deactivate or demote your own account.",
      });
    }

    const admin = await prisma.admin.update({
      where: { id: req.params.id },
      data,
      select: ADMIN_PUBLIC_FIELDS,
    });

    return res.status(200).json({
      success: true,
      message: "Administrator updated successfully.",
      data: admin,
    });
  } catch (error) {
    if (error.code === "P2025") {
      return res.status(404).json({
        success: false,
        message: "Administrator not found.",
      });
    }

    console.error("Update admin error:", error);
    return res.status(500).json({
      success: false,
      message: "Unable to update administrator.",
    });
  }
});

// ==========================================
// PASSWORD CHANGE (admin and collector self-service)
// ==========================================

async function changeOwnPassword(model, idField, minLength, req, res) {
  try {
    const { currentPassword, newPassword } = req.body || {};

    if (
      typeof currentPassword !== "string" ||
      typeof newPassword !== "string" ||
      newPassword.length < minLength
    ) {
      return res.status(400).json({
        success: false,
        message: `Current password and a new password of at least ${minLength} characters are required.`,
      });
    }

    const account = await prisma[model].findUnique({
      where: { id: req[idField].id },
    });

    if (
      !account ||
      !account.passwordHash ||
      !(await bcrypt.compare(currentPassword, account.passwordHash))
    ) {
      return res.status(401).json({
        success: false,
        message: "Current password is incorrect.",
      });
    }

    await prisma[model].update({
      where: { id: account.id },
      data: { passwordHash: await bcrypt.hash(newPassword, 12) },
    });

    return res.status(200).json({
      success: true,
      message: "Password changed successfully.",
    });
  } catch (error) {
    console.error("Change password error:", error);
    return res.status(500).json({
      success: false,
      message: "Unable to change password.",
    });
  }
}

app.patch("/api/admin/password", authenticateAdmin, (req, res) =>
  changeOwnPassword("admin", "admin", 12, req, res),
);

app.patch("/api/collector/password", authenticateCollector, (req, res) =>
  changeOwnPassword("collector", "collector", 8, req, res),
);

// ==========================================
// COLLECTOR PORTAL
// ==========================================

app.get("/api/collector/me", authenticateCollector, (req, res) => {
  return res.status(200).json({
    success: true,
    data: req.collector,
  });
});

app.get(
  "/api/collector/assignments",
  authenticateCollector,
  async (req, res) => {
    try {
      const { status } = req.query;

      const validStatuses = [
        "ASSIGNED",
        "ACCEPTED",
        "IN_PROGRESS",
        "COMPLETED",
        "CANCELLED",
        "ISSUE_REPORTED",
      ];

      if (status && !validStatuses.includes(status)) {
        return res.status(400).json({
          success: false,
          message: "Invalid assignment status.",
        });
      }

      const assignments = await prisma.collectionAssignment.findMany({
        where: {
          collectorId: req.collector.id,
          ...(status ? { status } : {}),
        },
        include: {
          bin: {
            include: {
              readings: {
                orderBy: { receivedAt: "desc" },
                take: 1,
              },
            },
          },
          collector: {
            select: {
              id: true,
              fullName: true,
              email: true,
              phone: true,
              status: true,
            },
          },
          statusHistory: {
            orderBy: { changedAt: "asc" },
          },
        },
        orderBy: { createdAt: "desc" },
      });

      return res.status(200).json({
        success: true,
        count: assignments.length,
        data: assignments,
      });
    } catch (error) {
      console.error("Collector assignments error:", error);

      return res.status(500).json({
        success: false,
        message: "Unable to retrieve your assignments.",
      });
    }
  },
);

app.get(
  "/api/collector/assignments/:id",
  authenticateCollector,
  async (req, res) => {
    try {
      const assignment = await prisma.collectionAssignment.findFirst({
        where: {
          id: req.params.id,
          collectorId: req.collector.id,
        },
        include: {
          bin: {
            include: {
              readings: {
                orderBy: { receivedAt: "desc" },
                take: 1,
              },
            },
          },
          collector: {
            select: {
              id: true,
              fullName: true,
              email: true,
              phone: true,
              status: true,
            },
          },
          statusHistory: {
            orderBy: { changedAt: "asc" },
          },
        },
      });

      if (!assignment) {
        return res.status(404).json({
          success: false,
          message: "Assignment not found.",
        });
      }

      return res.status(200).json({
        success: true,
        data: assignment,
      });
    } catch (error) {
      console.error("Collector assignment detail error:", error);

      return res.status(500).json({
        success: false,
        message: "Unable to retrieve assignment.",
      });
    }
  },
);

app.patch(
  "/api/collector/assignments/:id/status",
  authenticateCollector,
  async (req, res) => {
    const input = validateStatusRequest(req, res);

    if (!input) return;

    try {
      const { assignment, resolvedAlertIds } = await updateAssignmentStatus({
        assignmentId: req.params.id,
        requestedStatus: input.status,
        note: input.note,
        collectorId: req.collector.id,
        transitions: collectorTransitions,
      });

      const safeAssignment = removeAssignmentPasswordHashes(assignment);

      await publishAssignmentUpdate(assignment, "COLLECTOR", resolvedAlertIds);

      return res.status(200).json({
        success: true,
        message: `Collection status updated to ${input.status}.`,
        data: safeAssignment,
      });
    } catch (error) {
      if (error.message === "ASSIGNMENT_NOT_FOUND") {
        return res.status(404).json({
          success: false,
          message: "Assignment not found or you do not have access to it.",
        });
      }

      return handleAssignmentStatusError(error, res);
    }
  },
);

// ==========================================
// NOT FOUND HANDLER
// ==========================================

app.use((req, res) => {
  return res.status(404).json({
    success: false,
    message: `Route not found: ${req.method} ${req.originalUrl}`,
  });
});

// ==========================================
// GLOBAL ERROR HANDLER
// ==========================================

app.use((error, req, res, next) => {
  if (error.type === "entity.parse.failed") {
    return res.status(400).json({
      success: false,
      message: "Invalid JSON request body.",
    });
  }

  if (error.type === "entity.too.large") {
    return res.status(413).json({
      success: false,
      message: "Request body is too large.",
    });
  }

  console.error("Unhandled API error:", error);

  return res.status(500).json({
    success: false,
    message: "An unexpected server error occurred.",
  });
});

// ==========================================
// SERVER STARTUP
// ==========================================

server.listen(PORT, "0.0.0.0", () => {
  console.log(`EcoTrack API running at http://localhost:${PORT}`);
  console.log("Socket.IO server is ready.");
  console.log("Waiting for API requests and real-time readings...");
});

// ==========================================
// GRACEFUL SHUTDOWN
// ==========================================

let isShuttingDown = false;

async function shutdown() {
  if (isShuttingDown) return;

  isShuttingDown = true;
  console.log("\nStopping EcoTrack API...");

  server.close(async () => {
    try {
      await prisma.$disconnect();
      console.log("Database disconnected.");
      process.exit(0);
    } catch (error) {
      console.error("Shutdown error:", error);
      process.exit(1);
    }
  });

  setTimeout(() => {
    console.error("Graceful shutdown timed out.");
    process.exit(1);
  }, 10000).unref();
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
