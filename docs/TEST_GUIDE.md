# Testing Guide - Authentication System

## Quick Start

### 1. Start XAMPP
Make sure Apache and MySQL are running in XAMPP.

### 2. Create Admin User
```bash
cd /Applications/XAMPP/xamppfiles/htdocs/csapp
php create_admin.php
```

**Note the credentials displayed!** Default is:
- Username: `admin`
- Password: `Admin@2026!`

### 3. Delete the Helper Script (Security)
```bash
rm create_admin.php
```

---

## Test Scenarios

### ✅ Test 1: Unauthorized Access Protection

**Objective:** Verify that unauthenticated users cannot access protected pages.

**Steps:**
1. Open browser in **incognito/private mode**
2. Navigate to: `http://localhost/csapp/index.php`
3. **Expected:** Automatically redirected to `login.php`

**Pass Criteria:** ✅ Redirects to login page without showing dashboard

---

### ✅ Test 2: Session Persistence

**Objective:** Verify that logged-in users stay logged in across pages.

**Steps:**
1. Go to: `http://localhost/csapp/login.php`
2. Login with admin credentials
3. Verify you see: "Welcome, admin" in header
4. **Refresh the page** (F5 or Cmd+R)
5. Verify: Still logged in
6. **Open new tab:** `http://localhost/csapp/index.php`
7. Verify: Automatically logged in
8. **Navigate away:** Click "Run Clustering" or go to another page
9. **Navigate back:** Return to dashboard
10. Verify: Still logged in

**Pass Criteria:** ✅ Session persists across:
- Page refreshes
- New tabs (same browser)
- Navigation between pages

---

### ✅ Test 3: Logout Functionality

**Objective:** Verify that logout completely destroys the session.

**Steps:**
1. While logged in, click red **"Logout"** button
2. Verify: Redirected to `login.php`
3. **Try direct access:** Navigate to `http://localhost/csapp/index.php`
4. Verify: Redirected back to login
5. **Try browser back button**
6. Verify: Cannot access dashboard (redirects to login)
7. **Check other tabs:** If you had multiple tabs open, refresh them
8. Verify: All tabs redirect to login

**Pass Criteria:** ✅ After logout:
- Redirected to login page
- Cannot access protected pages
- Session is destroyed across all tabs

---

## Additional Tests

### Test 4: Failed Login Attempts

**Steps:**
1. Go to login page
2. Enter correct username, **wrong password**
3. Verify: Shows "Invalid username or password. Attempt 1 of 5."
4. Try again with wrong password
5. Verify: Shows "Attempt 2 of 5."
6. Continue until 5 failed attempts
7. Verify: Shows "Too many failed attempts. Account locked for 15 minutes."
8. Try to login with **correct password**
9. Verify: Still locked

**Pass Criteria:** ✅ Account locks after 5 attempts

---

### Test 5: Successful Login After Failed Attempts

**Steps:**
1. Make 3 failed login attempts
2. Note: Shows "Attempt 3 of 5."
3. Login with **correct credentials**
4. Verify: Successfully logged in
5. Logout and try wrong password again
6. Verify: Counter reset - shows "Attempt 1 of 5."

**Pass Criteria:** ✅ Successful login resets failed attempt counter

---

### Test 6: User Registration

**Steps:**
1. Go to: `http://localhost/csapp/register.php`
2. Enter:
   - Username: `testuser`
   - Email: `test@example.com`
   - Password: `TestPass123`
   - Confirm Password: `TestPass123`
3. Click "Register"
4. Verify: Shows "Registration successful! You can now login."
5. Click the login link
6. Login with new credentials
7. Verify: Successfully logged in as `testuser`

**Pass Criteria:** ✅ New user can register and login

---

### Test 7: Registration Validation

Test duplicate username:
1. Try to register with username `admin`
2. Verify: Shows "Username already exists."

Test duplicate email:
1. Try to register with email already in database
2. Verify: Shows "Email already exists."

Test password mismatch:
1. Enter different passwords in password and confirm fields
2. Verify: Shows "Passwords do not match."

Test short password:
1. Enter password less than 8 characters
2. Verify: Shows "Password must be at least 8 characters long."

**Pass Criteria:** ✅ All validations work correctly

---

## Browser Testing

### Recommended Browsers to Test
- ✅ Chrome/Chromium
- ✅ Safari
- ✅ Firefox
- ✅ Edge

### Testing in Incognito/Private Mode
Always use incognito/private mode when testing logout to ensure clean sessions:
- **Chrome:** Cmd+Shift+N (Mac) or Ctrl+Shift+N (Windows)
- **Safari:** Cmd+Shift+N
- **Firefox:** Cmd+Shift+P (Mac) or Ctrl+Shift+P (Windows)

---

## Troubleshooting

### Issue: Database Connection Failed
**Solution:**
1. Verify XAMPP MySQL is running
2. Check `db.php` has correct credentials
3. Verify database `customer_segmentation_ph` exists

### Issue: Page Doesn't Redirect After Login
**Solution:**
1. Check browser console for errors (F12)
2. Verify `session_start()` is at top of files
3. Clear browser cookies and try again

### Issue: Still See Dashboard After Logout
**Solution:**
1. Hard refresh: Cmd+Shift+R (Mac) or Ctrl+Shift+R (Windows)
2. Clear browser cache
3. Test in incognito mode

### Issue: Account Locked - Can't Login
**Solution:**
Wait 15 minutes OR manually reset in database:
```sql
UPDATE users SET failed_attempts = 0, lockout_until = NULL WHERE username = 'admin';
```

---

## Security Checklist

After all tests pass, verify:

- [ ] No hardcoded credentials in code
- [ ] Passwords stored as hashes in database
- [ ] Cannot access dashboard without login
- [ ] Session persists across pages
- [ ] Logout completely destroys session
- [ ] Account locks after 5 failed attempts
- [ ] Registration validates input properly
- [ ] Duplicate usernames/emails are rejected
- [ ] `create_admin.php` is deleted

---

## Success Criteria

All tests should show:
✅ Unauthorized access redirects to login  
✅ Session persists across pages and tabs  
✅ Logout destroys session completely  
✅ Failed attempts are tracked  
✅ Account locks after 5 attempts  
✅ Registration works with validation  
✅ No security warnings in code  

**Status:** Ready for production! 🎉

---

## Next Steps

After testing is complete:
1. ✅ Delete `create_admin.php`
2. ✅ Change default admin password
3. ✅ Review error logs
4. ✅ Consider additional security features (CSRF, 2FA, etc.)
5. ✅ Move to HTTPS in production

---

**Last Updated:** January 9, 2026  
**Version:** 2.0 - Security Hardened
