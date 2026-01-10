# Customer Segmentation Dashboard (CS0032-DS)

A comprehensive PHP-based customer segmentation dashboard with machine learning clustering capabilities and secure user authentication.

## Features

- **Secure Authentication System**
  - Database-driven user management
  - Password hashing with `password_hash()` and `password_verify()`
  - Account lockout after 5 failed login attempts (15-minute lockout)
  - User registration with email validation
  - Session-based authentication

- **Customer Segmentation Analysis**
  - Multiple segmentation types: Gender, Region, Age Group, Income Bracket, Purchase Tier
  - K-means clustering for advanced customer segmentation
  - Interactive charts and visualizations (Chart.js)
  - Detailed cluster analysis with business recommendations

- **Data Visualization**
  - Bar charts, line charts, and pie charts for distribution analysis
  - Radar charts for cluster feature comparison
  - Scatter plots for income vs purchase analysis
  - Responsive Bootstrap 5 UI

## Security Features

✅ **Eliminated Hardcoded Credentials** - All user data stored securely in database  
✅ **Password Hashing** - Using PHP's `PASSWORD_DEFAULT` algorithm (bcrypt)  
✅ **Rate Limiting** - Account lockout protection against brute-force attacks  
✅ **Session Management** - Secure session-based authentication  
✅ **Input Validation** - Email validation and password strength requirements  

## Installation & Setup

### 1. Import the Database

Import the SQL file into your MySQL database:

```bash
mysql -u root -p customer_segmentation_ph < sql/customer_segmentation_ph.sql
```

Or using phpMyAdmin, import `sql/customer_segmentation_ph.sql`.

### 2. Configure Database Connection

Edit `db.php` with your database credentials:

```php
$host = 'localhost';
$dbname = 'customer_segmentation_ph';
$username = 'root';
$password = 'your_password';
```

### 3. Create Database User

Set up a dedicated database user with minimal privileges:

```bash
# Edit password in the script first
nano sql/setup_db_user.sql

# Run the setup
mysql -u root -p < sql/setup_db_user.sql
```

### 4. Create Initial Admin User

Run the helper script once to create your first admin account:

```bash
php create_admin.php
```

**Important:** After creating the admin user, delete or restrict access to `create_admin.php` for security.

Alternatively, you can register a new user via the registration page at `register.php`.

### 5. Access the Application

- **Login Page:** `http://localhost/csapp/login.php`
- **Registration Page:** `http://localhost/csapp/register.php`
- **Dashboard:** `http://localhost/csapp/index.php` (requires login)

## Default Admin Credentials

After running `create_admin.php`:

- **Username:** `admin`
- **Password:** `Admin@2026!` (change this in the script before running)

**Remember to change the default password after first login!**

## Project Structure

```
csapp/
├── docs/                          # Documentation
│   ├── SETUP_GUIDE.md            # Detailed setup instructions
│   ├── SECURITY_UPGRADE.md       # Security improvements guide
│   ├── DATABASE_ANALYSIS.md      # Database schema analysis
│   ├── TEST_GUIDE.md             # Testing procedures
│   └── TEAM_SETUP.md             # Team member setup guide
├── sql/                           # Database scripts
│   ├── customer_segmentation_ph.sql  # Database schema and data
│   └── setup_db_user.sql         # Database user setup script
├── db.php                         # Database connection configuration
├── login.php                      # Login page with authentication
├── register.php                   # User registration page
├── logout.php                     # Logout handler
├── index.php                      # Main dashboard
├── run_clustering.php             # K-means clustering script
├── create_admin.php               # Helper script to create admin user
├── env.example                    # Environment variables template
└── README.md                      # This file
```

## Database Schema

### Users Table

```sql
CREATE TABLE users (
  user_id INT(11) NOT NULL AUTO_INCREMENT,
  username VARCHAR(100) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  email VARCHAR(255) DEFAULT NULL,
  role VARCHAR(50) DEFAULT 'user',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  last_login DATETIME DEFAULT NULL,
  failed_attempts INT DEFAULT 0,
  lockout_until DATETIME DEFAULT NULL,
  reset_token VARCHAR(128) DEFAULT NULL,
  reset_expires DATETIME DEFAULT NULL,
  PRIMARY KEY (user_id),
  UNIQUE KEY uq_users_username (username),
  UNIQUE KEY uq_users_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

## Usage

1. **Login** - Access `login.php` and enter your credentials
2. **View Dashboard** - After login, you'll see the customer segmentation dashboard
3. **Select Segmentation Type** - Choose from various segmentation options
4. **Run Clustering** - Click "Run Clustering" to generate ML-based customer segments
5. **Analyze Results** - View charts, statistics, and business recommendations

## Security Best Practices

- Change default admin password immediately after setup
- Delete `create_admin.php` after initial setup
- Use strong passwords (minimum 8 characters)
- Regularly review user accounts and failed login attempts
- Keep PHP and MySQL updated
- Use HTTPS in production
- Move sensitive configuration to environment variables in production

## Requirements

- PHP 7.4 or higher
- MySQL 5.7 or higher
- PDO extension enabled
- Apache/Nginx web server
- Modern web browser with JavaScript enabled

## Future Security Enhancements

- Two-factor authentication (2FA)
- Password reset via email
- CSRF token protection
- Rate limiting via IP address
- Environment variable configuration
- Audit logging
- Role-based access control (RBAC)

## License

CS0032-DS - Customer Segmentation Dashboard

## Support

For issues or questions, please contact your system administrator.
