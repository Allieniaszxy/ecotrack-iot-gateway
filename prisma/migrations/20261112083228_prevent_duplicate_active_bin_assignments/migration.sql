-- This is an empty migration.

CREATE UNIQUE INDEX "CollectionAssignment_one_active_per_bin"
ON "CollectionAssignment" ("binId")
WHERE "status" IN (
    'ASSIGNED',
    'ACCEPTED',
    'IN_PROGRESS',
    'ISSUE_REPORTED'
);
