-- ============================================
-- Setup Secure Database User
-- ============================================
-- This script creates a dedicated database user
-- with minimal privileges (principle of least privilege)
--
-- Run this as MySQL root user:
-- mysql -u root -p < setup_db_user.sql
-- ============================================

-- 1. Create dedicated user (replace password with a strong one!)
CREATE USER IF NOT EXISTS 'csapp_user'@'localhost' 
IDENTIFIED BY 'password';

-- 2. Grant only necessary privileges on the specific database
GRANT SELECT, INSERT, UPDATE, DELETE 
ON customer_segmentation_ph.* 
TO 'csapp_user'@'localhost';

-- Note: We do NOT grant:
-- - CREATE, DROP, ALTER (schema changes)
-- - GRANT OPTION (user management)
-- - SUPER, PROCESS, FILE (server administration)
-- - Access to other databases

-- 3. Apply changes
FLUSH PRIVILEGES;

-- 4. Verify user was created
SELECT 
    User, 
    Host, 
    plugin,
    password_expired
FROM mysql.user 
WHERE User = 'csapp_user';

-- 5. Verify privileges
SHOW GRANTS FOR 'csapp_user'@'localhost';


-- Optional: Set resource limits to prevent abuse
ALTER USER 'csapp_user'@'localhost' 
WITH 
    MAX_QUERIES_PER_HOUR 10000
    MAX_UPDATES_PER_HOUR 5000
    MAX_CONNECTIONS_PER_HOUR 1000
    MAX_USER_CONNECTIONS 10;

SELECT 'Database user setup complete!' AS status;
SELECT 'Remember to update your .env file with the password!' AS reminder;

