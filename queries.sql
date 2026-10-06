-- Run with: sqlite3 iam.db < queries.sql
-- 1. Leavers who still have access
SELECT u.user_id, u.name, a.app, a.entitlement, a.source
FROM users u JOIN assignments a ON a.user_id = u.user_id
WHERE u.status = 'terminated';

-- 2. Assignments with no matching user (orphaned accounts)
SELECT a.* FROM assignments a LEFT JOIN users u ON u.user_id = a.user_id
WHERE u.user_id IS NULL;

-- 3. SOD conflicts
SELECT x.user_id, s.ent_a, s.ent_b
FROM sod_rules s
JOIN assignments x ON x.entitlement = s.ent_a
JOIN assignments y ON y.user_id = x.user_id AND y.entitlement = s.ent_b;

-- 4. Access held outside the user's current role (manual grants)
SELECT user_id, app, entitlement FROM assignments WHERE source = 'manual';

-- 5. Full audit trail for one user
SELECT * FROM audit_log WHERE user_id = 'U101' ORDER BY ts;
