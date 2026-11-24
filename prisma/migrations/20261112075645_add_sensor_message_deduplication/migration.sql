/*
  Warnings:

  - A unique constraint covering the columns `[messageId]` on the table `SensorReading` will be added. If there are existing duplicate values, this will fail.

*/
-- AlterTable
ALTER TABLE "SensorReading" ADD COLUMN     "messageId" TEXT;

-- CreateIndex
CREATE UNIQUE INDEX "SensorReading_messageId_key" ON "SensorReading"("messageId");

-- CreateIndex
CREATE INDEX "SensorReading_binId_receivedAt_idx" ON "SensorReading"("binId", "receivedAt");
