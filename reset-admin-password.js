require("dotenv").config();

const bcrypt = require("bcryptjs");
const { PrismaClient } = require("@prisma/client");

const prisma = new PrismaClient();

async function resetPassword() {
  const email = process.env.ADMIN_EMAIL?.trim().toLowerCase();
  const password = process.env.NEW_ADMIN_PASSWORD;

  if (!email || !password) {
    throw new Error("ADMIN_EMAIL and NEW_ADMIN_PASSWORD are required.");
  }

  if (password.length < 12) {
    throw new Error("The new password must contain at least 12 characters.");
  }

  const admin = await prisma.admin.findUnique({ where: { email } });

  if (!admin) {
    const known = await prisma.admin.findMany({ select: { email: true } });
    const list = known.map((a) => a.email).join(", ") || "none";
    throw new Error(
      `No administrator has the email ${email}. Emails in this database: ${list}`,
    );
  }

  const reactivate = process.env.REACTIVATE === "true";

  await prisma.admin.update({
    where: { id: admin.id },
    data: {
      passwordHash: await bcrypt.hash(password, 12),
      ...(reactivate ? { status: "ACTIVE" } : {}),
    },
  });

  console.log(`Password reset for ${admin.email} (${admin.role}).`);

  if (admin.status !== "ACTIVE" && !reactivate) {
    console.log(
      "Note: this account is INACTIVE and still cannot sign in. Run again with REACTIVATE=true to switch it back on.",
    );
  }
}

resetPassword()
  .catch((error) => {
    console.error("Reset failed:", error.message);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
