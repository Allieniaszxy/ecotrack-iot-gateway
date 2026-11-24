-- CreateTable
CREATE TABLE "Bin" (
    "id" TEXT NOT NULL,
    "binId" TEXT NOT NULL,
    "name" TEXT,
    "location" TEXT,
    "status" TEXT NOT NULL DEFAULT 'ACTIVE',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Bin_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SensorReading" (
    "id" TEXT NOT NULL,
    "binId" TEXT NOT NULL,
    "distance" DOUBLE PRECISION NOT NULL,
    "fillLevel" DOUBLE PRECISION NOT NULL,
    "topic" TEXT NOT NULL,
    "receivedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "SensorReading_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "Bin_binId_key" ON "Bin"("binId");

-- CreateIndex
CREATE INDEX "SensorReading_binId_idx" ON "SensorReading"("binId");

-- CreateIndex
CREATE INDEX "SensorReading_receivedAt_idx" ON "SensorReading"("receivedAt");

-- AddForeignKey
ALTER TABLE "SensorReading" ADD CONSTRAINT "SensorReading_binId_fkey" FOREIGN KEY ("binId") REFERENCES "Bin"("binId") ON DELETE CASCADE ON UPDATE CASCADE;
