/**
 * Minimal in-memory replacement for PrismaClient, used ONLY by the API test
 * suite so tests run without PostgreSQL. It implements just the query
 * features api.js uses. It is not a general Prisma emulator.
 */
let counter = 0;
const newId = () => `id${(++counter).toString().padStart(6, "0")}`;

const relations = {
  collectionAssignment: {
    bin: { model: "bin", local: "binId", foreign: "binId", many: false },
    collector: { model: "collector", local: "collectorId", foreign: "id", many: false },
    statusHistory: { model: "collectionStatusHistory", local: "id", foreign: "assignmentId", many: true },
  },
  bin: {
    readings: { model: "sensorReading", local: "binId", foreign: "binId", many: true },
    alerts: { model: "binAlert", local: "binId", foreign: "binId", many: true },
  },
  collector: {
    assignments: { model: "collectionAssignment", local: "id", foreign: "collectorId", many: true },
  },
  binAlert: {
    bin: { model: "bin", local: "binId", foreign: "binId", many: false },
  },
};

function matches(row, where = {}) {
  return Object.entries(where).every(([key, cond]) => {
    if (key === "OR") return cond.some((c) => matches(row, c));
    if (key === "AND") return cond.every((c) => matches(row, c));
    const value = row[key];
    if (cond === null || typeof cond !== "object" || cond instanceof Date) {
      return value === cond || (cond instanceof Date && +value === +cond);
    }
    return Object.entries(cond).every(([op, arg]) => {
      switch (op) {
        case "equals": return value === arg;
        case "in": return arg.includes(value);
        case "not": return value !== arg;
        case "gte": return value != null && value >= arg;
        case "contains":
          return typeof value === "string" &&
            value.toLowerCase().includes(String(arg).toLowerCase());
        case "mode": return true;
        default: throw new Error(`Stub: unsupported operator ${op}`);
      }
    });
  });
}

function createPrismaClient() {
  const tables = {};
  const table = (name) => (tables[name] ||= []);
  const uniques = {
    admin: ["email"], collector: ["email", "phone"], bin: ["binId"],
    sensorReading: ["messageId"],
  };

  function checkUnique(name, row, ignoreId) {
    for (const field of uniques[name] || []) {
      if (row[field] == null) continue;
      if (table(name).some((r) => r.id !== ignoreId && r[field] === row[field])) {
        const e = new Error("Unique constraint failed");
        e.code = "P2002"; e.meta = { target: [field] };
        throw e;
      }
    }
    // partial unique index: one active assignment per bin
    if (name === "collectionAssignment" &&
      ["ASSIGNED", "ACCEPTED", "IN_PROGRESS", "ISSUE_REPORTED"].includes(row.status) &&
      table(name).some((r) => r.id !== ignoreId && r.binId === row.binId &&
        ["ASSIGNED", "ACCEPTED", "IN_PROGRESS", "ISSUE_REPORTED"].includes(r.status))) {
      const e = new Error("CollectionAssignment_one_active_per_bin");
      e.code = "P2002"; e.meta = { target: ["binId"] };
      throw e;
    }
  }

  function shape(name, row, opts = {}) {
    if (!row) return row;
    let out = { ...row };
    const rel = relations[name] || {};
    const { include, select } = opts;
    if (include) {
      for (const [key, spec] of Object.entries(include)) {
        if (key === "_count") {
          out._count = {};
          for (const relName of Object.keys(spec.select)) {
            const r = rel[relName];
            out._count[relName] = table(r.model).filter((x) => x[r.foreign] === row[r.local]).length;
          }
        } else if (spec) {
          const r = rel[key];
          let related = table(r.model).filter((x) => x[r.foreign] === row[r.local]);
          const sub = spec === true ? {} : spec;
          if (sub.orderBy) related = order(related, sub.orderBy);
          if (sub.take) related = related.slice(0, sub.take);
          related = related.map((x) => shape(r.model, x, sub));
          out[key] = r.many ? related : related[0] || null;
        }
      }
    }
    if (select) {
      const picked = {};
      for (const [k, v] of Object.entries(select)) if (v) picked[k] = out[k];
      return picked;
    }
    return out;
  }

  function order(rows, orderBy) {
    const [[field, dir]] = Object.entries(Array.isArray(orderBy) ? orderBy[0] : orderBy);
    return [...rows].sort((a, b) => (a[field] > b[field] ? 1 : a[field] < b[field] ? -1 : 0) * (dir === "desc" ? -1 : 1));
  }

  const defaults = {
    admin: { role: "ADMIN", status: "ACTIVE" },
    collector: { status: "ACTIVE", email: null, address: null, passwordHash: null },
    bin: { status: "ACTIVE", name: null, location: null },
    binAlert: { status: "ACTIVE", acknowledgedAt: null, resolvedAt: null },
    collectionAssignment: { status: "ASSIGNED", priority: "NORMAL", acceptedAt: null, startedAt: null, completedAt: null, notes: null, scheduledFor: null, binAlertId: null },
    sensorReading: { messageId: null },
  };

  function model(name) {
    return {
      async findUnique({ where, ...opts }) {
        const row = table(name).find((r) => matches(r, where));
        return shape(name, row, opts);
      },
      async findFirst({ where, orderBy, ...opts } = {}) {
        let rows = table(name).filter((r) => matches(r, where));
        if (orderBy) rows = order(rows, orderBy);
        return shape(name, rows[0], opts);
      },
      async findMany({ where, orderBy, take, ...opts } = {}) {
        let rows = table(name).filter((r) => matches(r, where));
        if (orderBy) rows = order(rows, orderBy);
        if (take) rows = rows.slice(0, take);
        return rows.map((r) => shape(name, r, opts));
      },
      async count({ where } = {}) {
        return table(name).filter((r) => matches(r, where)).length;
      },
      async create({ data, ...opts }) {
        const { statusHistory, ...rest } = data;
        const row = { id: newId(), createdAt: new Date(), updatedAt: new Date(), ...(defaults[name] || {}), ...rest };
        if (name === "bin") row.assignedAt = undefined;
        if (name === "collectionAssignment") row.assignedAt = new Date();
        if (name === "collectionStatusHistory") row.changedAt = new Date();
        if (name === "sensorReading") row.receivedAt = new Date();
        checkUnique(name, row);
        table(name).push(row);
        if (statusHistory?.create) {
          table("collectionStatusHistory").push({
            id: newId(), assignmentId: row.id, changedAt: new Date(), note: null, ...statusHistory.create,
          });
        }
        return shape(name, row, opts);
      },
      async update({ where, data, ...opts }) {
        const row = table(name).find((r) => matches(r, where));
        if (!row) { const e = new Error("Not found"); e.code = "P2025"; throw e; }
        checkUnique(name, { ...row, ...data }, row.id);
        Object.assign(row, data, { updatedAt: new Date() });
        return shape(name, row, opts);
      },
      async updateMany({ where, data }) {
        const rows = table(name).filter((r) => matches(r, where));
        rows.forEach((r) => Object.assign(r, data, { updatedAt: new Date() }));
        return { count: rows.length };
      },
      async groupBy({ by, where }) {
        const groups = new Map();
        for (const r of table(name).filter((x) => matches(x, where))) {
          const k = by.map((f) => r[f]).join("|");
          if (!groups.has(k)) groups.set(k, { ...Object.fromEntries(by.map((f) => [f, r[f]])), _count: { _all: 0 } });
          groups.get(k)._count._all += 1;
        }
        return [...groups.values()];
      },
    };
  }

  const client = {
    async $transaction(fn) { return fn(client); },
    async $queryRaw() { return [{ "?column?": 1 }]; },
    async $disconnect() {},
    __tables: tables,
  };
  for (const n of ["admin", "collector", "bin", "sensorReading", "binAlert", "collectionAssignment", "collectionStatusHistory"]) {
    client[n] = model(n);
  }
  return client;
}

const holder = {};
module.exports = {
  PrismaClient: function PrismaClient() {
    holder.client = createPrismaClient();
    return holder.client;
  },
  holder,
};
