require("dotenv").config();

const { io } = require("socket.io-client");

const token = process.env.ADMIN_TOKEN;

const socket = io("http://localhost:4000", {
  auth: token ? { token } : {},
  reconnection: false,
  timeout: 5000,
});

socket.on("connect", () => {
  console.log("SUCCESS: Dashboard socket authenticated.");
  console.log("Socket ID:", socket.id);
  socket.disconnect();
});

socket.on("connect_error", (error) => {
  console.log("CONNECTION REJECTED:", error.message);
  process.exitCode = 1;
});

socket.on("disconnect", (reason) => {
  console.log("Disconnected:", reason);
});
