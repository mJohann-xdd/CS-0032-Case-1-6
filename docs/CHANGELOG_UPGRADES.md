# Customer Segmentation App — Consolidated Change Log & Upgrade Documentation

This document consolidates **all major changes, upgrades, and security fixes** made to the project, including database, authentication, security, and dashboard logic. Use the table of contents to quickly find the relevant section.

---

## Table of Contents

1. [Authentication & User Management](#authentication--user-management)
2. [Database Security & Connection Hardening](#database-security--connection-hardening)
3. [Dashboard Logic & index.php Changes](#dashboard-logic--indexphp-changes)
4. [Database Schema & Query Upgrades](#database-schema--query-upgrades)
5. [Setup, Environment, and Deployment](#setup-environment-and-deployment)
6. [Testing, Rollback, and Troubleshooting](#testing-rollback-and-troubleshooting)
7. [Security Recommendations & Next Steps](#security-recommendations--next-steps)

---

## 1. Authentication & User Management

### ✅ Migrated to Database-Driven Authentication

- **Old:** Hardcoded username/password in PHP files.
- **New:** Credentials stored in a `users` table.
- **Features:**
  - Unique username and email enforced.
  - Passwords stored as bcrypt hashes (`password_hash()`/`password_verify()`).
  - Session stores `user_id`, `username`, `role`.

### ✅ Account Lockout & Rate Limiting

- Tracks failed login attempts.
- Locks account for 15 minutes after 5 failed attempts.
- Resets counter on successful login.
- User informed of remaining attempts and lockout status.

### ✅ Registration & Admin Creation

- Self-registration page (`register.php`).
- Helper script for initial admin creation (`create_admin.php`).
- Password strength enforced (min 8 chars).

---

## 2. Database Security & Connection Hardening

### ✅ Environment-Based Credentials

- **Old:** Hardcoded root credentials in source code.
- **New:** Credentials loaded from `.env` file (not committed to Git).
- `.env.example` provided as template.

### ✅ Dedicated Database User

- Created `csapp_user` with only `SELECT, INSERT, UPDATE, DELETE` privileges.
- No schema-altering or admin privileges.
- User creation automated in `setup_db_user.sql`.

### ✅ Secure PDO Configuration

- Enforces UTF-8mb4 charset.
- Uses real prepared statements (`ATTR_EMULATE_PREPARES=false`).
- Secure error handling: logs errors, shows generic message to users.
- Connection verified before use.

### ✅ Error Handling

- No sensitive info leaked to users.
- All errors logged via `error_log()`.

### ✅ .gitignore & File Permissions

- `.env` and sensitive scripts are git-ignored.
- Setup guides instruct on proper file permissions.

---

## 3. Dashboard Logic & index.php Changes

### ✅ Session & Auth Guard

- All dashboard pages require login (`$_SESSION['logged_in']` check).
- Redirects unauthenticated users to `login.php`.

### ✅ Input Validation & Whitelisting

- Segmentation type is sanitized and checked against an allowed list.
- Prevents arbitrary SQL execution.

### ✅ Segmentation Types & Queries

- **Supported:** gender, region, age_group, income_bracket, cluster, purchase_tier, unassigned.
- **Cluster:** Aggregates per cluster, includes dominant gender subquery.
- **Unassigned:** Shows customers not assigned to any cluster.

### ✅ Unassigned Segmentation Feature

- **Query:** Identifies customers not in `segmentation_results` table.
- **Insights Display:**
  - Shows total count of unassigned customers.
  - Displays age, income, and purchase amount ranges.
  - Provides recommendations to run clustering script.
  - Handles empty results gracefully with user-friendly messages.
- **Custom Visualizations:**
  - **Main Chart:** Gender distribution bar chart for unassigned customers.
  - **Pie Chart:** Region distribution breakdown.
  - Special handling since unassigned returns individual records, not aggregated data.
- **Data Structure:** Modified JavaScript to handle non-aggregated customer data differently from other segmentation types.


### ✅ Error Handling

- All DB queries in try/catch.
- User sees minimal error; details logged.
- Empty results display informative messages instead of errors.
- Conditional checks prevent array access errors on empty datasets.

### ✅ Enhanced Visualizations

- Chart.js for bar, line, and pie charts.
- Cluster metadata and details fetched for advanced visualizations.
- Insights section summarizes key findings per segmentation.
- Conditional chart rendering based on segmentation type and data structure.

### ✅ Logout

- Logout uses fetch to `logout.php` and redirects on success.

---

## 4. Database Schema & Query Upgrades

### ✅ Users Table

- See `users` table definition in schema.
- Tracks failed attempts, lockout, password reset tokens.

### ✅ Foreign Key Constraints

- Enforced between `segmentation_results` and `customers`, `cluster_metadata`.
- Referential integrity for all main tables.

### ✅ Indexes for Performance

- Added indexes:
  - `segmentation_results(customer_id)`
  - `segmentation_results(cluster_label, customer_id)`
  - `customers(age)`
  - `customers(income)`

### ✅ Query Optimization

- Combined cluster aggregation and dominant gender using subqueries/CTEs.
- Indexed columns used in JOINs, GROUP BY, and WHERE clauses.

### ✅ Audit Trail & Versioning

- `segmentation_runs` table logs clustering runs.
- `audit_log` table records user actions and changes.

---

## 5. Setup, Environment, and Deployment

### ✅ Environment Variables

- `.env` file for DB credentials and settings.
- `.env.example` as template.
- `.gitignore` protects `.env`.

### ✅ Setup Scripts

- `setup_db_user.sql` creates DB user and grants privileges.
- `customer_segmentation_ph.sql` creates all tables, constraints, and seed data.
- Admin user creation instructions included.

### ✅ Secure File Permissions

- `.env` should be `chmod 600`.
- Setup scripts instruct to delete sensitive files after use.

---

## 6. Testing, Rollback, and Troubleshooting

### ✅ Testing Checklist

- Login, registration, and lockout tested.
- All segmentation types render tables and charts.
- Cluster visualizations work if metadata present.
- Unassigned customers view lists correct customers.
- Unassigned segmentation displays custom gender and region charts.
- Empty unassigned results show appropriate messaging.
- Dropdown maintains selected value after form submission.
- DB errors are logged, not shown to users.

### ✅ Rollback

- Restore previous `index.php` or schema from backup if needed.
- Remove new files if reverting to old authentication.

### ✅ Troubleshooting

- Common issues and solutions documented (DB connection, login, .env loading, etc.).
- Debug mode instructions for development only.

---

## 7. Security Recommendations & Next Steps

### Immediate

- Add CSRF protection to forms.
- Implement password reset via email.
- Session timeout after inactivity.
- Enforce HTTPS in production.

### Long-term

- Two-factor authentication (2FA).
- Role-based permissions.
- Comprehensive audit logging.
- Caching for heavy queries (Redis/Memcached).
- Pagination for large result sets.

---

## References

- [SECURITY_ANALYSIS.md](docs/SECURITY_ANALYSIS.md) - **NEW: Comprehensive security audit and vulnerability assessment**
- [DB_SECURITY_FIXES.md](docs/DB_SECURITY_FIXES.md)
- [SECURITY_UPGRADE.md](docs/SECURITY_UPGRADE.md)
- [SETUP_GUIDE.md](docs/SETUP_GUIDE.md)
- [README.md](../README.md)

---

**Date:** January 2026  
**Maintainer:** [Your Team Name]  
**Status:** All critical upgrades and fixes applied.  
**Latest Security Audit:** January 11, 2026 - See SECURITY_ANALYSIS.md for detailed findings  
