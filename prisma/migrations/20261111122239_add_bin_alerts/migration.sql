-- CreateTable
CREATE TABLE "BinAlert" (
    "id" TEXT NOT NULL,
    "binId" TEXT NOT NULL,
    "severity" TEXT NOT NULL,
    "alertType" TEXT NOT NULL,
    "message" TEXT NOT NULL,
    "fillLevel" DOUBLE PRECISION NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'ACTIVE',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "acknowledgedAt" TIMESTAMP(3),
    "resolvedAt" TIMESTAMP(3),
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "BinAlert_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "BinAlert_binId_idx" ON "BinAlert"("binId");

-- CreateIndex
CREATE INDEX "BinAlert_status_idx" ON "BinAlert"("status");

-- CreateIndex
CREATE INDEX "BinAlert_severity_idx" ON "BinAlert"("severity");

-- CreateIndex
CREATE INDEX "BinAlert_createdAt_idx" ON "BinAlert"("createdAt");

-- CreateIndex
CREATE INDEX "BinAlert_binId_status_idx" ON "BinAlert"("binId", "status");

-- AddForeignKey
ALTER TABLE "BinAlert" ADD CONSTRAINT "BinAlert_binId_fkey" FOREIGN KEY ("binId") REFERENCES "Bin"("binId") ON DELETE RESTRICT ON UPDATE CASCADE;
