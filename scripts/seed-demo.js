/**
 * Optional demo data for screenshots and project demonstrations.
 * Safe to run more than once. It only touches bins named BIN-DEMO-* and the
 * two demo collectors below.
 *
 *   npm run seed:demo
 */
require("dotenv").config();

const bcrypt = require("bcryptjs");
const { PrismaClient } = require("@prisma/client");

const prisma = new PrismaClient();

const DEMO_PASSWORD = process.env.DEMO_COLLECTOR_PASSWORD || "Collector#1234";

const bins = [
  { binId: "BIN-DEMO-001", name: "Ikeja Market Bin", location: "Allen Avenue, Ikeja", fill: 93 },
  { binId: "BIN-DEMO-002", name: "Yaba Bus Stop Bin", location: "Herbert Macaulay Way, Yaba", fill: 78 },
  { binId: "BIN-DEMO-003", name: "Lekki Phase 1 Bin", location: "Admiralty Way, Lekki", fill: 52 },
  { binId: "BIN-DEMO-004", name: "Surulere Park Bin", location: "Adeniran Ogunsanya St, Surulere", fill: 21 },
];

const collectors = [
  { fullName: "Adewale Bello", phone: "08011110001", email: "adewale.demo@ecotrack.test", address: "Ikeja, Lagos" },
  { fullName: "Chioma Obi", phone: "08011110002", email: "chioma.demo@ecotrack.test", address: "Yaba, Lagos" },
];

// A believable climb towards each bin's current fill level.
function buildReadings(binId, finalFill) {
  const points = 24;
  const now = Date.now();

  return Array.from({ length: points }, (_, i) => {
    const progress = (i + 1) / points;
    const fillLevel = Math.max(
      0,
      Math.min(100, finalFill * progress + (Math.random() * 4 - 2)),
    );

    return {
      binId,
      fillLevel: Number(fillLevel.toFixed(1)),
      // Illustrative distance only; the dashboard charts fillLevel.
      distance: Number((100 - fillLevel).toFixed(1)),
      topic: `ecotrack/bins/${binId}/reading`,
      receivedAt: new Date(now - (points - i) * 10 * 60 * 1000),
    };
  });
}

async function main() {
  const passwordHash = await bcrypt.hash(DEMO_PASSWORD, 12);

  for (const bin of bins) {
    await prisma.bin.upsert({
      where: { binId: bin.binId },
      update: { name: bin.name, location: bin.location },
      create: { binId: bin.binId, name: bin.name, location: bin.location },
    });

    const existing = await prisma.sensorReading.count({ where: { binId: bin.binId } });

    if (existing === 0) {
      await prisma.sensorReading.createMany({
        data: buildReadings(bin.binId, bin.fill),
      });
    }
  }

  for (const collector of collectors) {
    await prisma.collector.upsert({
      where: { phone: collector.phone },
      update: {},
      create: { ...collector, passwordHash, status: "ACTIVE" },
    });
  }

  console.log("Demo data ready.");
  console.log(`Demo collectors sign in with their phone number and: ${DEMO_PASSWORD}`);
  collectors.forEach((c) => console.log(`  ${c.fullName}: ${c.phone}`));
}

main()
  .catch((error) => {
    console.error("Seeding failed:", error.message);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
