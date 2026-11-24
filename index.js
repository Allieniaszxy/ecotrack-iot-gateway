require("dotenv").config();

const mqtt = require("mqtt");
const { io } = require("socket.io-client");
const { PrismaClient } = require("@prisma/client");

const prisma = new PrismaClient();

const broker = process.env.MQTT_BROKER;
const topic = process.env.MQTT_TOPIC;
const socketApiUrl = process.env.SOCKET_API_URL;
const gatewayToken = process.env.SOCKET_GATEWAY_TOKEN;

if (
  !broker ||
  !topic ||
  !process.env.DATABASE_URL ||
  !socketApiUrl ||
  !gatewayToken
) {
  console.error("Missing required environment variables.");
  process.exit(1);
}

// Connect to the private Socket.IO gateway namespace
const socket = io(`${socketApiUrl}/gateway`, {
  auth: {
    token: gatewayToken,
  },
  reconnection: true,
  reconnectionDelay: 3000,
  reconnectionDelayMax: 10000,
});

socket.on("connect", () => {
  console.log("Connected to EcoTrack real-time server!");
});

socket.on("connect_error", (error) => {
  console.error("Socket.IO connection error:", error.message);
});

socket.on("disconnect", (reason) => {
  console.log("Socket.IO disconnected:", reason);
});

// Connect to MQTT
const client = mqtt.connect(broker, {
  clientId: `ecotrack-server-${Date.now()}`,
  reconnectPeriod: 3000,
  connectTimeout: 30000,
});

console.log("EcoTrack IoT Gateway starting...");

client.on("connect", () => {
  console.log("Connected to MQTT broker!");

  client.subscribe(topic, { qos: 1 }, (error) => {
    if (error) {
      console.error("Subscription failed:", error.message);
      return;
    }

    console.log(`Subscribed to: ${topic}`);
    console.log("Waiting for smart bin readings...\n");
  });
});

// A bin counts as emptied when it was at least this full and now reads below
// the second value. Confirms a collection with the sensor, not just the
// collector's word.
const EMPTIED_FROM_PERCENT = 75;
const EMPTIED_BELOW_PERCENT = 30;

async function processBinAlert(bin, fillLevel) {
  let newAlert = null;
  const resolvedAlertIds = [];

  const severity =
    fillLevel >= 90 ? "CRITICAL" : fillLevel >= 75 ? "HIGH" : null;

  try {
    await prisma.$transaction(async (tx) => {
      const openStatuses = ["ACTIVE", "ACKNOWLEDGED"];

      // If the bin is below 75%, resolve all outstanding fill alerts.
      if (!severity) {
        const openAlerts = await tx.binAlert.findMany({
          where: { binId: bin.binId, status: { in: openStatuses } },
          select: { id: true },
        });

        if (openAlerts.length > 0) {
          const ids = openAlerts.map((alert) => alert.id);
          resolvedAlertIds.push(...ids);

          await tx.binAlert.updateMany({
            where: { id: { in: ids } },
            data: { status: "RESOLVED", resolvedAt: new Date() },
          });
        }

        return;
      }

      const alertType = severity === "CRITICAL" ? "CRITICAL_FILL" : "HIGH_FILL";

      // Resolve alerts for an older severity.
      const olderAlerts = await tx.binAlert.findMany({
        where: {
          binId: bin.binId,
          status: { in: openStatuses },
          alertType: { not: alertType },
        },
        select: { id: true },
      });

      if (olderAlerts.length > 0) {
        const ids = olderAlerts.map((alert) => alert.id);
        resolvedAlertIds.push(...ids);

        await tx.binAlert.updateMany({
          where: { id: { in: ids } },
          data: { status: "RESOLVED", resolvedAt: new Date() },
        });
      }

      // Check whether an alert of this severity is already open.
      const existingAlert = await tx.binAlert.findFirst({
        where: {
          binId: bin.binId,
          alertType,
          status: { in: openStatuses },
        },
      });

      // Do not create duplicate active or acknowledged alerts.
      if (existingAlert) {
        return;
      }

      const message =
        severity === "CRITICAL"
          ? `${bin.name || bin.binId} is critically full at ${fillLevel.toFixed(2)}%. Immediate collection is required.`
          : `${bin.name || bin.binId} is almost full at ${fillLevel.toFixed(2)}%. Collection should be scheduled.`;

      newAlert = await tx.binAlert.create({
        data: {
          binId: bin.binId,
          severity,
          alertType,
          message,
          fillLevel,
          status: "ACTIVE",
        },
      });
    });

    // Let dashboards know about alerts this reading closed.
    if (resolvedAlertIds.length > 0 && socket.connected) {
      const resolved = await prisma.binAlert.findMany({
        where: { id: { in: resolvedAlertIds } },
        include: {
          bin: { select: { binId: true, name: true, location: true } },
        },
      });

      resolved.forEach((alert) => socket.emit("alert:updated", alert));
    }

    if (newAlert) {
      console.log("--------------------------------");
      console.log("NEW ECOTRACK BIN ALERT");
      console.log("--------------------------------");
      console.log("Bin ID:", bin.binId);
      console.log("Severity:", newAlert.severity);
      console.log("Fill Level:", newAlert.fillLevel + "%");
      console.log("Message:", newAlert.message);

      if (socket.connected) {
        socket.emit("bin:alert", {
          ...newAlert,
          bin: {
            binId: bin.binId,
            name: bin.name,
            location: bin.location,
          },
        });

        console.log("REAL-TIME: Alert sent to API server.");
      } else {
        console.log("REAL-TIME: API connection unavailable.");
      }

      console.log("DATABASE: Alert saved successfully.");
      console.log("--------------------------------\n");
    }
  } catch (error) {
    console.error("Alert processing failed:", error.message);
  }
}

client.on("message", async (receivedTopic, message) => {
  try {
    const data = JSON.parse(message.toString());

    if (
      typeof data.binId !== "string" ||
      !data.binId.trim() ||
      data.binId.length > 100 ||
      typeof data.distance !== "number" ||
      !Number.isFinite(data.distance) ||
      typeof data.fillLevel !== "number" ||
      !Number.isFinite(data.fillLevel) ||
      data.distance < 0 ||
      data.fillLevel < 0 ||
      data.fillLevel > 100 ||
      (data.messageId !== undefined &&
        (typeof data.messageId !== "string" ||
          !data.messageId.trim() ||
          data.messageId.length > 150))
    ) {
      console.log("Invalid sensor message received.");
      return;
    }

    let bin = await prisma.bin.findUnique({ where: { binId: data.binId } });

    if (!bin) {
      // Only administrators should register bins. Set AUTO_REGISTER_BINS=true
      // in .env if you want unknown devices to be created automatically.
      if (process.env.AUTO_REGISTER_BINS !== "true") {
        console.log(`Reading ignored: bin ${data.binId} is not registered.`);
        return;
      }

      bin = await prisma.bin.create({
        data: {
          binId: data.binId,
          name: `Smart Bin ${data.binId}`,
          status: "ACTIVE",
        },
      });
    }

    // The previous level, used to recognise a bin being emptied.
    const previousReading = await prisma.sensorReading.findFirst({
      where: { binId: bin.binId },
      orderBy: { receivedAt: "desc" },
      select: { fillLevel: true },
    });

    let reading;

    try {
      reading = await prisma.sensorReading.create({
        data: {
          messageId: data.messageId?.trim() || null,
          binId: bin.binId,
          distance: data.distance,
          fillLevel: data.fillLevel,
          topic: receivedTopic,
        },
      });
    } catch (error) {
      if (error.code === "P2002" && data.messageId) {
        console.log(`Duplicate sensor message ignored: ${data.messageId}`);
        return;
      }

      throw error;
    }
    if (bin.status === "ACTIVE") {
      await processBinAlert(bin, reading.fillLevel);
    }

    console.log("--------------------------------");
    console.log("NEW ECOTRACK SENSOR READING");
    console.log("--------------------------------");
    console.log("Bin ID:", bin.binId);
    console.log("Distance:", reading.distance, "cm");
    console.log("Fill Level:", reading.fillLevel + "%");
    console.log("Database ID:", reading.id);

    if (reading.fillLevel >= 90) {
      console.log("ALERT: CRITICALLY FULL BIN");
    } else if (reading.fillLevel >= 75) {
      console.log("WARNING: BIN ALMOST FULL");
    } else {
      console.log("STATUS: NORMAL");
    }

    console.log("DATABASE: Reading saved successfully.");

    // Broadcast only after the database save succeeds
    const realtimePayload = {
      binId: bin.binId,
      name: bin.name,
      status: bin.status,
      reading: {
        id: reading.id,
        distance: reading.distance,
        fillLevel: reading.fillLevel,
        topic: reading.topic,
        receivedAt: reading.receivedAt,
      },
    };

    if (socket.connected) {
      socket.emit("bin:reading", realtimePayload);
      console.log("REAL-TIME: Reading broadcast successfully.");

      if (
        previousReading &&
        previousReading.fillLevel >= EMPTIED_FROM_PERCENT &&
        reading.fillLevel < EMPTIED_BELOW_PERCENT
      ) {
        socket.emit("bin:emptied", {
          binId: bin.binId,
          name: bin.name,
          location: bin.location,
          previousFill: previousReading.fillLevel,
          fillLevel: reading.fillLevel,
          at: reading.receivedAt,
        });
        console.log("REAL-TIME: Bin emptied event sent.");
      }
    } else {
      console.log(
        "REAL-TIME: Gateway disconnected; reading saved in database only.",
      );
    }

    console.log("--------------------------------\n");
  } catch (error) {
    console.error("Could not process sensor message:", error.message);
  }
});

client.on("error", (error) => {
  console.error("MQTT Error:", error.message);
});

client.on("reconnect", () => {
  console.log("Reconnecting to MQTT broker...");
});

async function shutdown() {
  console.log("\nStopping EcoTrack IoT Gateway...");

  socket.disconnect();

  client.end(false, {}, async () => {
    await prisma.$disconnect();
    process.exit(0);
  });
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
