/**
 * Publishes fake sensor readings for several bins, so you can demo EcoTrack
 * without hardware. Each bin publishes to its own topic.
 *
 *   node scripts/simulate-bins.js
 *
 * Optional environment variables:
 *   SIM_BINS="BIN-LAG-001,BIN-LAG-002"   bins to simulate (must be registered)
 *   SIM_INTERVAL_MS=5000                 time between readings
 *   SIM_TOPIC_TEMPLATE="ecotrack/demo/{bin}/alaka/telemetry"
 *   MQTT_BROKER                          read from .env as usual
 */
require("dotenv").config();

const mqtt = require("mqtt");

const broker = process.env.MQTT_BROKER;
const bins = (process.env.SIM_BINS || "BIN-LAG-001,BIN-LAG-002,BIN-LAG-003")
  .split(",")
  .map((id) => id.trim())
  .filter(Boolean);
const intervalMs = Number(process.env.SIM_INTERVAL_MS) || 5000;
const topicTemplate =
  process.env.SIM_TOPIC_TEMPLATE || "ecotrack/demo/{bin}/alaka/telemetry";

// Height of the empty bin in cm: the sensor sits at the lid, looking down.
const BIN_HEIGHT_CM = 100;

if (!broker) {
  console.error("MQTT_BROKER is not set.");
  process.exit(1);
}

// Give each bin a different starting level so the dashboard shows variety.
const state = new Map(
  bins.map((id, i) => [id, { fill: 15 + ((i * 37) % 70), rate: 0.6 + i * 0.4 }]),
);

const client = mqtt.connect(broker, {
  clientId: `ecotrack-sim-${Date.now()}`,
  reconnectPeriod: 3000,
});

client.on("connect", () => {
  console.log(`Connected to ${broker}. Simulating: ${bins.join(", ")}`);
});

client.on("error", (error) => console.error("MQTT error:", error.message));

setInterval(() => {
  if (!client.connected) return;

  for (const binId of bins) {
    const bin = state.get(binId);

    // Fill slowly with some noise; an emptied bin restarts near zero.
    bin.fill += bin.rate + Math.random() * 0.6;
    if (bin.fill > 100) bin.fill = 3;

    const fillLevel = Number(bin.fill.toFixed(1));
    const distance = Number(((BIN_HEIGHT_CM * (100 - fillLevel)) / 100).toFixed(1));

    const topic = topicTemplate.replace("{bin}", binId.toLowerCase());
    const payload = {
      binId,
      distance,
      fillLevel,
      messageId: `${binId}-${Date.now()}`,
    };

    client.publish(topic, JSON.stringify(payload), { qos: 1 });
    console.log(`${topic}  ${fillLevel}%`);
  }
}, intervalMs);
