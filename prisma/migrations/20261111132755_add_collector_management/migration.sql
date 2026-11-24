-- CreateTable
CREATE TABLE "Collector" (
    "id" TEXT NOT NULL,
    "fullName" TEXT NOT NULL,
    "email" TEXT,
    "phone" TEXT NOT NULL,
    "address" TEXT,
    "status" TEXT NOT NULL DEFAULT 'ACTIVE',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Collector_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CollectionAssignment" (
    "id" TEXT NOT NULL,
    "binId" TEXT NOT NULL,
    "collectorId" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'ASSIGNED',
    "priority" TEXT NOT NULL DEFAULT 'NORMAL',
    "scheduledFor" TIMESTAMP(3),
    "assignedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "acceptedAt" TIMESTAMP(3),
    "startedAt" TIMESTAMP(3),
    "completedAt" TIMESTAMP(3),
    "notes" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "binAlertId" TEXT,

    CONSTRAINT "CollectionAssignment_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CollectionStatusHistory" (
    "id" TEXT NOT NULL,
    "assignmentId" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "note" TEXT,
    "changedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "CollectionStatusHistory_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "Collector_email_key" ON "Collector"("email");

-- CreateIndex
CREATE UNIQUE INDEX "Collector_phone_key" ON "Collector"("phone");

-- CreateIndex
CREATE INDEX "Collector_status_idx" ON "Collector"("status");

-- CreateIndex
CREATE INDEX "Collector_fullName_idx" ON "Collector"("fullName");

-- CreateIndex
CREATE INDEX "CollectionAssignment_binId_idx" ON "CollectionAssignment"("binId");

-- CreateIndex
CREATE INDEX "CollectionAssignment_collectorId_idx" ON "CollectionAssignment"("collectorId");

-- CreateIndex
CREATE INDEX "CollectionAssignment_status_idx" ON "CollectionAssignment"("status");

-- CreateIndex
CREATE INDEX "CollectionAssignment_scheduledFor_idx" ON "CollectionAssignment"("scheduledFor");

-- CreateIndex
CREATE INDEX "CollectionAssignment_createdAt_idx" ON "CollectionAssignment"("createdAt");

-- CreateIndex
CREATE INDEX "CollectionStatusHistory_assignmentId_idx" ON "CollectionStatusHistory"("assignmentId");

-- CreateIndex
CREATE INDEX "CollectionStatusHistory_changedAt_idx" ON "CollectionStatusHistory"("changedAt");

-- AddForeignKey
ALTER TABLE "CollectionAssignment" ADD CONSTRAINT "CollectionAssignment_binId_fkey" FOREIGN KEY ("binId") REFERENCES "Bin"("binId") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CollectionAssignment" ADD CONSTRAINT "CollectionAssignment_collectorId_fkey" FOREIGN KEY ("collectorId") REFERENCES "Collector"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CollectionAssignment" ADD CONSTRAINT "CollectionAssignment_binAlertId_fkey" FOREIGN KEY ("binAlertId") REFERENCES "BinAlert"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CollectionStatusHistory" ADD CONSTRAINT "CollectionStatusHistory_assignmentId_fkey" FOREIGN KEY ("assignmentId") REFERENCES "CollectionAssignment"("id") ON DELETE CASCADE ON UPDATE CASCADE;
