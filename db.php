<?php
/**
 * Secure Database Connection Configuration
 * 
 * Security improvements:
 * - Environment variables for credentials (no hardcoding)
 * - Dedicated database user (not root)
 * - Secure error handling (no information disclosure)
 * - PDO with prepared statements enabled
 * - Character encoding enforced
 */

// Load environment variables from .env file if it exists
if (file_exists(__DIR__ . '/.env')) {
    $env = parse_ini_file(__DIR__ . '/.env');
    foreach ($env as $key => $value) {
        if (!getenv($key)) {
            putenv("$key=$value");
        }
    }
}

// Database configuration from environment variables with fallbacks
$host = getenv('DB_HOST') ?: 'localhost';
$dbname = getenv('DB_NAME') ?: 'customer_segmentation_ph';
$username = getenv('DB_USER') ?: 'csapp_user';  // Dedicated user, not root!
$password = getenv('DB_PASSWORD') ?: '';
$charset = 'utf8mb4';  // Full Unicode support

// PDO options for security and performance
$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,    // Throw exceptions on errors
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,          // Return associative arrays
    PDO::ATTR_EMULATE_PREPARES   => false,                     // Use real prepared statements
    PDO::ATTR_PERSISTENT         => false,                     // Don't use persistent connections
];

try {
    // Create PDO instance with secure connection string
    $dsn = "mysql:host=$host;dbname=$dbname;charset=$charset";
    $pdo = new PDO($dsn, $username, $password, $options);
    
    // Verify connection is working
    $pdo->query('SELECT 1');
    
} catch (PDOException $e) {
    // Log the actual error for debugging (never show to users)
    error_log("Database Connection Error: " . $e->getMessage() . " in " . $e->getFile() . ":" . $e->getLine());
    
    // Show generic error to users (no sensitive information)
    http_response_code(503); // Service Unavailable
    die("Database connection failed. Please try again later or contact support.");
}
?>