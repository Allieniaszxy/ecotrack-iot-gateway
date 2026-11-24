/**
 * EcoTrack API test suite.
 * Runs against an in-memory database stand-in, so PostgreSQL is not required.
 * Run with:  npm test
 */
const Module = require("node:module");
const path = require("node:path");
const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");

process.env.JWT_SECRET = "test-secret-test-secret-test-secret";
process.env.SOCKET_GATEWAY_TOKEN = "gateway-test-token";
process.env.API_PORT = "4199";

// Swap @prisma/client for the in-memory stub before api.js loads it.
const stub = require("./prisma-memory-stub");
const originalLoad = Module._load;
Module._load = function (request, ...rest) {
  if (request === "@prisma/client") return stub;
  return originalLoad.call(this, request, ...rest);
};

const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const BASE = "http://localhost:4199";
let db;
const ctx = {};

async function call(method, url, { token, body } = {}) {
  const response = await fetch(BASE + url, {
    method,
    headers: {
      ...(body ? { "Content-Type": "application/json" } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  let json = null;
  try { json = await response.json(); } catch {}
  return { status: response.status, body: json };
}

const adminJwt = (admin) =>
  jwt.sign({ adminId: admin.id, role: "ADMIN", adminRole: admin.role }, process.env.JWT_SECRET, { expiresIn: "1h", algorithm: "HS256" });

before(async () => {
  require(path.join(__dirname, "..", "api.js"));
  db = stub.holder.client;
  await new Promise((r) => setTimeout(r, 300));

  const hash = await bcrypt.hash("SuperSecure#12345", 4);
  ctx.superAdmin = await db.admin.create({ data: { fullName: "Root Admin", email: "root@ecotrack.test", passwordHash: hash, role: "SUPER_ADMIN" } });
  ctx.opsManager = await db.admin.create({ data: { fullName: "Ops Manager", email: "ops@ecotrack.test", passwordHash: hash, role: "OPERATIONS_MANAGER" } });
  ctx.superToken = adminJwt(ctx.superAdmin);
  ctx.opsToken = adminJwt(ctx.opsManager);
});

after(() => setTimeout(() => process.exit(0), 100).unref());

// ------------------------------------------------------------------ auth
test("health check works without authentication", async () => {
  const r = await call("GET", "/api/health");
  assert.equal(r.status, 200);
});

test("protected admin routes reject anonymous requests", async () => {
  for (const url of ["/api/bins", "/api/collectors", "/api/assignments", "/api/alerts", "/api/stats/overview", "/api/admins"]) {
    const r = await call("GET", url);
    assert.equal(r.status, 401, url);
  }
});

test("admin login succeeds and returns a top-level token", async () => {
  const r = await call("POST", "/api/admin/login", { body: { email: "ROOT@ecotrack.test", password: "SuperSecure#12345" } });
  assert.equal(r.status, 200);
  assert.equal(typeof r.body.token, "string");
  assert.equal(r.body.admin.role, "SUPER_ADMIN");
  assert.equal(r.body.admin.passwordHash, undefined);
});

test("admin login failure uses the 'message' key", async () => {
  const r = await call("POST", "/api/admin/login", { body: { email: "root@ecotrack.test", password: "wrong-password" } });
  assert.equal(r.status, 401);
  assert.ok(r.body.message);
});

test("collector JWT cannot access admin routes", async () => {
  const token = jwt.sign({ collectorId: "x", role: "COLLECTOR" }, process.env.JWT_SECRET, { algorithm: "HS256" });
  const r = await call("GET", "/api/bins", { token });
  assert.equal(r.status, 403);
});

test("GET /api/admin/me returns the signed-in admin", async () => {
  const r = await call("GET", "/api/admin/me", { token: ctx.superToken });
  assert.equal(r.status, 200);
  assert.equal(r.body.data.email, "root@ecotrack.test");
});

// ------------------------------------------------------------------ bins
test("admin can register a bin; duplicates and bad IDs are rejected", async () => {
  let r = await call("POST", "/api/bins", { token: ctx.superToken, body: { binId: "BIN-LAG-001", name: "Ikeja Market", location: "Ikeja, Lagos" } });
  assert.equal(r.status, 201);
  r = await call("POST", "/api/bins", { token: ctx.superToken, body: { binId: "BIN-LAG-001" } });
  assert.equal(r.status, 409);
  r = await call("POST", "/api/bins", { token: ctx.superToken, body: { binId: "a b" } });
  assert.equal(r.status, 400);
  await call("POST", "/api/bins", { token: ctx.superToken, body: { binId: "BIN-LAG-002", name: "Yaba" } });
});

test("operations manager can read but not create bins", async () => {
  let r = await call("GET", "/api/bins", { token: ctx.opsToken });
  assert.equal(r.status, 200);
  assert.equal(r.body.count, 2);
  r = await call("POST", "/api/bins", { token: ctx.opsToken, body: { binId: "BIN-LAG-009" } });
  assert.equal(r.status, 403);
});

test("admin can update a bin and unknown bins return 404", async () => {
  let r = await call("PATCH", "/api/bins/BIN-LAG-002", { token: ctx.superToken, body: { location: "Yaba, Lagos", status: "MAINTENANCE" } });
  assert.equal(r.status, 200);
  assert.equal(r.body.data.status, "MAINTENANCE");
  await call("PATCH", "/api/bins/BIN-LAG-002", { token: ctx.superToken, body: { status: "ACTIVE" } });
  r = await call("PATCH", "/api/bins/NOPE-123", { token: ctx.superToken, body: { name: "x" } });
  assert.equal(r.status, 404);
  r = await call("PATCH", "/api/bins/BIN-LAG-002", { token: ctx.superToken, body: { status: "BROKEN" } });
  assert.equal(r.status, 400);
});

// ------------------------------------------------------------ collectors
test("collector registration requires a password and hides the hash", async () => {
  let r = await call("POST", "/api/collectors", { token: ctx.superToken, body: { fullName: "Ade Bello", phone: "08011111111" } });
  assert.equal(r.status, 400);
  r = await call("POST", "/api/collectors", { token: ctx.superToken, body: { fullName: "Ade Bello", email: "Ade@Example.com", phone: "08011111111", password: "collector-pass-1" } });
  assert.equal(r.status, 201);
  assert.equal(r.body.data.passwordHash, undefined);
  assert.equal(r.body.data.email, "ade@example.com");
  ctx.collectorId = r.body.data.id;
  r = await call("POST", "/api/collectors", { token: ctx.superToken, body: { fullName: "Dup", phone: "08011111111", password: "collector-pass-1" } });
  assert.equal(r.status, 409);
});

test("operations manager can list collectors but not create them", async () => {
  let r = await call("GET", "/api/collectors", { token: ctx.opsToken });
  assert.equal(r.status, 200);
  assert.equal(r.body.data[0].passwordHash, undefined);
  r = await call("POST", "/api/collectors", { token: ctx.opsToken, body: { fullName: "X", phone: "1", password: "12345678" } });
  assert.equal(r.status, 403);
});

test("collector can sign in with email or phone", async () => {
  let r = await call("POST", "/api/collector/login", { body: { identifier: "ade@example.com", password: "collector-pass-1" } });
  assert.equal(r.status, 200);
  ctx.collectorToken = r.body.token;
  r = await call("POST", "/api/collector/login", { body: { identifier: "08011111111", password: "collector-pass-1" } });
  assert.equal(r.status, 200);
  r = await call("POST", "/api/collector/login", { body: { identifier: "08011111111", password: "nope" } });
  assert.equal(r.status, 401);
});

// ----------------------------------------------------------- assignments
test("assignment lifecycle: create, duplicate guard, accept, complete", async () => {
  // alert on the bin that completion should resolve
  await db.binAlert.create({ data: { binId: "BIN-LAG-001", severity: "CRITICAL", alertType: "CRITICAL_FILL", message: "full", fillLevel: 95 } });

  let r = await call("POST", "/api/assignments", { token: ctx.opsToken, body: { binId: "BIN-LAG-001", collectorId: ctx.collectorId, alertId: "does-not-exist" } });
  assert.equal(r.status, 400, "unknown alert id is rejected");

  r = await call("POST", "/api/assignments", { token: ctx.opsToken, body: { binId: "BIN-LAG-001", collectorId: ctx.collectorId, priority: "CRITICAL" } });
  assert.equal(r.status, 201);
  assert.equal(r.body.data.collector.passwordHash, undefined);
  ctx.assignmentId = r.body.data.id;

  r = await call("POST", "/api/assignments", { token: ctx.opsToken, body: { binId: "BIN-LAG-001", collectorId: ctx.collectorId } });
  assert.equal(r.status, 409);

  r = await call("GET", "/api/collector/assignments", { token: ctx.collectorToken });
  assert.equal(r.status, 200);
  assert.equal(r.body.count, 1);

  r = await call("PATCH", `/api/collector/assignments/${ctx.assignmentId}/status`, { token: ctx.collectorToken, body: { status: "COMPLETED" } });
  assert.equal(r.status, 409, "cannot skip ASSIGNED -> COMPLETED");

  r = await call("PATCH", `/api/collector/assignments/${ctx.assignmentId}/status`, { token: ctx.collectorToken, body: { status: "ACCEPTED" } });
  assert.equal(r.status, 200);
  r = await call("PATCH", `/api/collector/assignments/${ctx.assignmentId}/status`, { token: ctx.collectorToken, body: { status: "IN_PROGRESS" } });
  assert.equal(r.status, 200);
  r = await call("PATCH", `/api/collector/assignments/${ctx.assignmentId}/status`, { token: ctx.collectorToken, body: { status: "ISSUE_REPORTED" } });
  assert.equal(r.status, 400, "issue needs a note");
  r = await call("PATCH", `/api/collector/assignments/${ctx.assignmentId}/status`, { token: ctx.collectorToken, body: { status: "COMPLETED", note: "Emptied" } });
  assert.equal(r.status, 200);
  assert.ok(r.body.data.completedAt);

  const alerts = await call("GET", "/api/alerts?status=RESOLVED", { token: ctx.opsToken });
  assert.equal(alerts.body.count, 1, "completion resolves open alerts");
});

test("collectors cannot touch another collector's assignment", async () => {
  const other = await call("POST", "/api/collectors", { token: ctx.superToken, body: { fullName: "Chi Obi", phone: "08022222222", password: "collector-pass-2" } });
  await call("POST", "/api/assignments", { token: ctx.opsToken, body: { binId: "BIN-LAG-002", collectorId: other.body.data.id } });
  const list = await call("GET", "/api/assignments?status=ASSIGNED", { token: ctx.opsToken });
  const foreignId = list.body.data[0].id;
  const r = await call("PATCH", `/api/collector/assignments/${foreignId}/status`, { token: ctx.collectorToken, body: { status: "ACCEPTED" } });
  assert.equal(r.status, 404);
});

test("deactivated collectors are locked out immediately", async () => {
  await call("PATCH", `/api/collectors/${ctx.collectorId}/status`, { token: ctx.superToken, body: { status: "INACTIVE" } });
  let r = await call("GET", "/api/collector/me", { token: ctx.collectorToken });
  assert.equal(r.status, 403);
  await call("PATCH", `/api/collectors/${ctx.collectorId}/status`, { token: ctx.superToken, body: { status: "ACTIVE" } });
  r = await call("GET", "/api/collector/me", { token: ctx.collectorToken });
  assert.equal(r.status, 200);
});

// ------------------------------------------------------ stats and admins
test("overview and analytics endpoints return data", async () => {
  let r = await call("GET", "/api/stats/overview", { token: ctx.opsToken });
  assert.equal(r.status, 200);
  assert.equal(r.body.data.totalBins, 2);
  assert.equal(r.body.data.assignments.COMPLETED, 1);
  r = await call("GET", "/api/stats/analytics?days=7", { token: ctx.opsToken });
  assert.equal(r.status, 200);
  assert.equal(r.body.data.daily.length, 7);
  assert.equal(r.body.data.topCollectors[0].fullName, "Ade Bello");
});

test("only SUPER_ADMIN manages the admin team, with self-lockout protection", async () => {
  let r = await call("GET", "/api/admins", { token: ctx.opsToken });
  assert.equal(r.status, 403);
  r = await call("POST", "/api/admins", { token: ctx.superToken, body: { fullName: "New Admin", email: "new@ecotrack.test", password: "short" } });
  assert.equal(r.status, 400);
  r = await call("POST", "/api/admins", { token: ctx.superToken, body: { fullName: "New Admin", email: "new@ecotrack.test", password: "LongEnoughPass#1", role: "ADMIN" } });
  assert.equal(r.status, 201);
  assert.equal(r.body.data.passwordHash, undefined);
  r = await call("PATCH", `/api/admins/${ctx.superAdmin.id}`, { token: ctx.superToken, body: { status: "INACTIVE" } });
  assert.equal(r.status, 400);
});

test("password change checks the current password", async () => {
  let r = await call("PATCH", "/api/collector/password", { token: ctx.collectorToken, body: { currentPassword: "bad", newPassword: "another-pass-9" } });
  assert.equal(r.status, 401);
  r = await call("PATCH", "/api/collector/password", { token: ctx.collectorToken, body: { currentPassword: "collector-pass-1", newPassword: "another-pass-9" } });
  assert.equal(r.status, 200);
  r = await call("POST", "/api/collector/login", { body: { identifier: "ade@example.com", password: "another-pass-9" } });
  assert.equal(r.status, 200);
});

test("unknown routes and malformed JSON are handled", async () => {
  let r = await call("GET", "/api/nope");
  assert.equal(r.status, 404);
  const raw = await fetch(BASE + "/api/admin/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{bad" });
  assert.equal(raw.status, 400);
});

test("collector completion is pushed live to admins, and admin feedback reaches the collector", async () => {
  const { io } = require("socket.io-client");

  await call("POST", "/api/bins", { token: ctx.superToken, body: { binId: "BIN-LAG-003", name: "Lekki" } });
  await db.binAlert.create({ data: { binId: "BIN-LAG-003", severity: "CRITICAL", alertType: "CRITICAL_FILL", message: "full", fillLevel: 96 } });

  let r = await call("POST", "/api/assignments", { token: ctx.opsToken, body: { binId: "BIN-LAG-003", collectorId: ctx.collectorId } });
  assert.equal(r.status, 201);
  const id = r.body.data.id;

  // Feedback is only for completed collections.
  r = await call("POST", `/api/assignments/${id}/feedback`, { token: ctx.opsToken, body: { message: "Great work" } });
  assert.equal(r.status, 409);

  const events = [];
  const socket = io(BASE, { auth: { token: ctx.superToken }, transports: ["websocket"] });
  await new Promise((resolve, reject) => {
    socket.on("connect", resolve);
    socket.on("connect_error", reject);
  });
  socket.on("assignment:updated", (p) => events.push(["assignment:updated", p.status, p.changedBy]));
  socket.on("alert:updated", (p) => events.push(["alert:updated", p.status, p.bin.binId]));

  for (const status of ["ACCEPTED", "IN_PROGRESS", "COMPLETED"]) {
    r = await call("PATCH", `/api/collector/assignments/${id}/status`, { token: ctx.collectorToken, body: { status } });
    assert.equal(r.status, 200);
  }
  await new Promise((resolve) => setTimeout(resolve, 300));
  socket.close();

  assert.deepEqual(events.filter((e) => e[0] === "assignment:updated"), [
    ["assignment:updated", "ACCEPTED", "COLLECTOR"],
    ["assignment:updated", "IN_PROGRESS", "COLLECTOR"],
    ["assignment:updated", "COMPLETED", "COLLECTOR"],
  ]);
  assert.deepEqual(events.filter((e) => e[0] === "alert:updated"), [
    ["alert:updated", "RESOLVED", "BIN-LAG-003"],
  ]);

  // Admin thanks the collector.
  r = await call("POST", `/api/assignments/${id}/feedback`, { token: ctx.opsToken, body: { message: "" } });
  assert.equal(r.status, 400);
  r = await call("POST", `/api/assignments/${id}/feedback`, { token: ctx.opsToken, body: { message: "Great work, thank you!" } });
  assert.equal(r.status, 201);

  r = await call("GET", `/api/collector/assignments/${id}`, { token: ctx.collectorToken });
  const note = r.body.data.statusHistory.map((h) => h.note).find((n) => n && n.startsWith("__feedback__:"));
  assert.ok(note, "collector can see the feedback");
  assert.equal(JSON.parse(note.slice("__feedback__:".length)).message, "Great work, thank you!");

  // Collectors cannot send feedback themselves.
  r = await call("POST", `/api/assignments/${id}/feedback`, { token: ctx.collectorToken, body: { message: "x" } });
  assert.equal(r.status, 403);
});

test("admin login is rate limited", async () => {
  let last;
  for (let i = 0; i < 6; i += 1) {
    last = await call("POST", "/api/admin/login", { body: { email: "root@ecotrack.test", password: "x" } });
  }
  assert.equal(last.status, 429);
});
