# Customer Segmentation App — Unified Setup Guide

Welcome to the Customer Segmentation project! This guide consolidates all setup steps for new team members and secure deployment. Follow each section in order for a smooth experience.

---

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Repository & File Setup](#repository--file-setup)
3. [Database Setup](#database-setup)
4. [Environment Configuration](#environment-configuration)
5. [Admin User Creation](#admin-user-creation)
6. [Running the Application](#running-the-application)
7. [Common Issues & Troubleshooting](#common-issues--troubleshooting)
8. [Security Checklist](#security-checklist)
9. [Development Workflow](#development-workflow)
10. [FAQ & Support](#faq--support)

---

## 1. Prerequisites
- XAMPP (Apache + MySQL)
- Git
- PHP (included in XAMPP)
- Terminal/Command line access

---

## 2. Repository & File Setup

```bash
git clone <repository-url>
cd csapp
```

---

## 3. Database Setup

### Step 1: Import the Database
```bash
mysql -u root -p < sql/customer_segmentation_ph.sql
```

### Step 2: Create Database User
1. Edit the password in `sql/setup_db_user.sql` (line with `IDENTIFIED BY ...`).
2. Use the same password in your `.env` file (see next section).
3. Run:
```bash
mysql -u root -p < sql/setup_db_user.sql
```

---

## 4. Environment Configuration

```bash
cp env.example .env
nano .env
```
- Set `DB_USER=csapp_user`
- Set `DB_PASSWORD=your_password_here` (same as in setup_db_user.sql)
- Save and close the file.
- Secure your .env:
```bash
chmod 600 .env
```
- Ensure `.env` is in `.gitignore` (run `grep .env .gitignore`)

---

## 5. Admin User Creation

```bash
php create_admin.php
```
- Note the admin username and password shown.
- Delete the script for security:
```bash
rm create_admin.php
```

---

## 6. Running the Application

1. Start XAMPP (Apache + MySQL)
2. Open your browser:
```
http://localhost/csapp/login.php
```
3. Login with the admin credentials from above.

---

## 7. Common Issues & Troubleshooting

### "Database connection failed"
- Check your `.env` file for correct credentials.
- Make sure MySQL is running.

### "Access denied for user 'csapp_user'"
- Password mismatch between `.env` and `setup_db_user.sql`.
- Reset password in MySQL and update `.env`.

### ".env file not found"
- Ensure `.env` exists in the project root.
- Copy from `env.example` if missing.

### Can't delete `create_admin.php`
- Use `rm -f create_admin.php` or move to backup location.

---

## 8. Security Checklist
- [ ] `.env` file created and correct
- [ ] `.env` is in `.gitignore`
- [ ] `create_admin.php` deleted after use
- [ ] Can login to dashboard with admin credentials
- [ ] Database user is `csapp_user` (not root)
- [ ] Session persists across pages
- [ ] Logout works properly

---

## 9. Development Workflow

```bash
# 1. Pull latest changes
git pull
# 2. Make your changes to PHP files
# 3. Test locally (http://localhost/csapp/)
# 4. Commit and push
git add .
git commit -m "Description of changes"
git push
```

### Updating Database Schema
If the schema changes:
```bash
git pull
mysql -u root -p customer_segmentation_ph < sql/customer_segmentation_ph.sql
```

---

## 10. FAQ & Support
- Check this guide and `.env` settings first.
- Review error logs: `/Applications/XAMPP/xamppfiles/logs/php_error_log`
- Ask in the team chat if stuck.

---

**Setup Time:** ~10 minutes  
**Difficulty:** Easy  
**Last Updated:** January 11, 2026
