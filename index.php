<?php
// Configuration
define('SESSION_TIMEOUT', 1800); // 30 minutes in seconds
define('SESSION_ABSOLUTE_TIMEOUT', 28800); // 8 hours max session lifetime

function configure_secure_session() {
    // Check if we're on HTTPS (for production)
    $is_https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
                || $_SERVER['SERVER_PORT'] == 443;
    
    session_set_cookie_params([
        'lifetime' => 0,              // Until browser closes
        'path' => '/',                // Current domain
        'domain' => '',               // Current domain
        'secure' => $is_https,        // HTTPS only if available
        'httponly' => true,           // No JavaScript access
        'samesite' => 'Strict'        // Strict CSRF protection
    ]);
    
    // Set custom session name
    session_name('CSAPP_SESSION');
}

function check_authentication() {
    if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
        // Not logged in
        header('Location: login.php?error=not_authenticated');
        exit;
    }
}

function check_inactivity_timeout() {
    if (isset($_SESSION['last_activity'])) {
        $inactive_time = time() - $_SESSION['last_activity'];
        
        if ($inactive_time > SESSION_TIMEOUT) {
            // Session expired due to inactivity
            session_unset();
            session_destroy();
            
            // Start new session for error message
            session_start();
            $_SESSION['timeout_message'] = 'Your session expired due to inactivity. Please login again.';
            
            header('Location: login.php?error=timeout');
            exit;
        }
    }
    // Update last activity time
    $_SESSION['last_activity'] = time();
}

function check_absolute_timeout() {
    if (isset($_SESSION['created_at'])) {
        $session_lifetime = time() - $_SESSION['created_at'];
        
        if ($session_lifetime > SESSION_ABSOLUTE_TIMEOUT) {
            // Session exceeded maximum lifetime
            session_unset();
            session_destroy();
            
            // Start new session for error message
            session_start();
            $_SESSION['timeout_message'] = 'Your session has reached its maximum lifetime (8 hours). Please login again.';
            
            header('Location: login.php?error=absolute_timeout');
            exit;
        }
    }
}

function validate_session_fingerprint() {
    $current_fingerprint = md5(
        $_SERVER['HTTP_USER_AGENT'] ?? '' .
        $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? ''
    );
    
    if (!isset($_SESSION['fingerprint'])) {
        // First time - set fingerprint
        $_SESSION['fingerprint'] = $current_fingerprint;
    } else if ($_SESSION['fingerprint'] !== $current_fingerprint) {
        // Fingerprint mismatch - possible session hijacking
        session_unset();
        session_destroy();
        
        // Start new session for error message
        session_start();
        $_SESSION['timeout_message'] = 'Session validation failed. Please login again.';
        
        header('Location: login.php?error=security');
        exit;
    }
}

/** Main session check function - call this at top of protected pages */
function secure_session_check() {
    check_authentication();
    check_inactivity_timeout();
    check_absolute_timeout();
    validate_session_fingerprint();
}

// Generate CSRF token
function generate_csrf_token() {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    
    return $_SESSION['csrf_token'];
}

// Get CSRF token (or generate if not exists)
function get_csrf_token() {
    return generate_csrf_token();
}

// Validate CSRF token
function validate_csrf_token($token) {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    
    if (!isset($_SESSION['csrf_token'])) {
        return false;
    }
    
    // Use hash_equals to prevent timing attacks
    return hash_equals($_SESSION['csrf_token'], $token);
}

// Output CSRF token as hidden input field
function csrf_token_field() {
    $token = get_csrf_token();
    return '<input type="hidden" name="csrf_token" value="' . htmlspecialchars($token, ENT_QUOTES, 'UTF-8') . '">';
}

// Verify CSRF token from POST request, kills script if invalid
function verify_csrf_token() {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $token = $_POST['csrf_token'] ?? '';
        
        if (!validate_csrf_token($token)) {
            // CSRF attack detected
            error_log("CSRF attack detected from IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
            
            http_response_code(403);
            die(json_encode([
                'error' => 'Invalid security token. Please refresh the page and try again.',
                'code' => 'CSRF_INVALID'
            ]));
        }
    }
}

// Run configuration
configure_secure_session();
session_start();
secure_session_check();

require_once 'db.php';

// Handle Form Submission & Security Validation
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Verify CSRF token
    verify_csrf_token();
    
    $segmentationType = filter_input(INPUT_POST, 'segmentation_type', FILTER_SANITIZE_STRING);

     // CSRF Validation
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        http_response_code(403);
        die("Security Error: CSRF Token Validation Failed.");
    }

    $cluster_metadata = [];
    $cluster_details = [];

    // --- CACHING LAYER START ---
    // 1. Setup Cache Location (Creates a 'cache' folder if missing)
    $cacheDir = __DIR__ . '/cache';
    if (!is_dir($cacheDir)) {
        mkdir($cacheDir, 0777, true);
    }

    // 2. Define Cache Key and Lifetime (1 Hour)
    $cacheFile = $cacheDir . '/segment_' . $segmentationType . '.json';
    $cacheLifetime = 3600; 
    $isCached = false;

    // 3. CHECK CACHE: If file exists and is less than 1 hour old
    if (file_exists($cacheFile) && (time() - filemtime($cacheFile) < $cacheLifetime)) {
        // LOAD FROM FILE (Fast!)
        $results = json_decode(file_get_contents($cacheFile), true);
        $isCached = true;
        
        // Set a dummy SQL for export just so it doesn't break
        $_SESSION['export_sql'] = "SELECT 'Data loaded from cache for $segmentationType'";
        $_SESSION['is_cached'] = true; // Optional: To show a badge in UI

        if ($segmentationType === 'cluster') {
            try {
                $metadata_sql = "SELECT * FROM cluster_metadata ORDER BY cluster_id";
                $metadata_stmt = $pdo->query($metadata_sql);
                $cluster_metadata = $metadata_stmt->fetchAll(PDO::FETCH_ASSOC);

                $detail_sql = "SELECT c.customer_id, c.age, c.income, c.purchase_amount, sr.cluster_label
                               FROM customers c
                               JOIN segmentation_results sr ON c.customer_id = sr.customer_id
                               ORDER BY sr.cluster_label";
                $detail_stmt = $pdo->query($detail_sql);
                $cluster_details = $detail_stmt->fetchAll(PDO::FETCH_ASSOC);
            } catch (PDOException $e) {
                $cluster_metadata = [];
                $cluster_details = [];
            }
        }
    } 
    else {
        
    switch ($segmentationType) {
        case 'gender':
            $sql = "SELECT gender, COUNT(*) AS total_customers, ROUND(AVG(income), 2) AS avg_income, ROUND(AVG(purchase_amount), 2) AS avg_purchase_amount FROM customers GROUP BY gender";
            break;

        case 'region':
            $sql = "SELECT region, COUNT(*) AS total_customers, ROUND(AVG(income), 2) AS avg_income, ROUND(AVG(purchase_amount), 2) AS avg_purchase_amount FROM customers GROUP BY region ORDER BY total_customers DESC";
            break;

        case 'age_group':
            $sql = "SELECT
                        CASE
                            WHEN age IS NULL THEN 'Unknown'
                            WHEN age BETWEEN 0 AND 17 THEN '0-17'
                            WHEN age BETWEEN 18 AND 25 THEN '18-25'
                            WHEN age BETWEEN 26 AND 35 THEN '26-35'
                            WHEN age BETWEEN 36 AND 50 THEN '36-50'
                            WHEN age BETWEEN 51 AND 65 THEN '51-65'
                            WHEN age >= 66 THEN '66+'
                            ELSE 'Invalid'
                        END AS age_group,
                        COUNT(*) AS total_customers,
                        ROUND(AVG(income), 2) AS avg_income,
                        ROUND(AVG(purchase_amount), 2) AS avg_purchase_amount,
                        ROUND(MIN(purchase_amount), 2) AS min_purchase,  
                        ROUND(MAX(purchase_amount), 2) AS max_purchase,      
                        ROUND(MAX(purchase_amount) - MIN(purchase_amount), 2) AS purchase_range  
                    FROM customers
                    GROUP BY age_group
                    ORDER BY 
                        CASE age_group
                            WHEN 'Unknown' THEN 0
                            WHEN '0-17' THEN 1
                            WHEN '18-25' THEN 2
                            WHEN '26-35' THEN 3
                            WHEN '36-50' THEN 4
                            WHEN '51-65' THEN 5
                            WHEN '66+' THEN 6
                            ELSE 7
                        END;";
            break;

        case 'income_bracket':
            $sql = "SELECT CASE WHEN income < 30000 THEN 'Low Income (<30k)' WHEN income BETWEEN 30000 AND 70000 THEN 'Middle Income (30k-70k)' ELSE 'High Income (>70k)' END AS income_bracket, COUNT(*) AS total_customers, ROUND(AVG(purchase_amount), 2) AS avg_purchase_amount FROM customers GROUP BY income_bracket ORDER BY income_bracket";
            break;

        case 'cluster':
            $sql = "SELECT 
                        sr.cluster_label, 
                        COUNT(*) AS total_customers, 
                        ROUND(AVG(c.income), 2) AS avg_income, 
                        ROUND(AVG(c.purchase_amount), 2) AS avg_purchase_amount, 
                        MIN(c.age) AS min_age, 
                        MAX(c.age) AS max_age,
                        -- Find the most common gender in each cluster
                        (SELECT c2.gender
                         FROM segmentation_results sr2
                         JOIN customers c2 ON sr2.customer_id = c2.customer_id
                         WHERE sr2.cluster_label = sr.cluster_label
                         GROUP BY c2.gender
                         ORDER BY COUNT(*) DESC
                         LIMIT 1
                        ) AS dominant_gender
                    FROM segmentation_results sr
                    JOIN customers c ON sr.customer_id = c.customer_id
                    GROUP BY sr.cluster_label
                    ORDER BY sr.cluster_label";

            // Fetch cluster metadata for enhanced visualizations
            try {
                $metadata_sql = "SELECT * FROM cluster_metadata ORDER BY cluster_id";
                $metadata_stmt = $pdo->query($metadata_sql);
                $cluster_metadata = $metadata_stmt->fetchAll(PDO::FETCH_ASSOC);

                // Fetch detailed customer data for scatter plots
                $detail_sql = "SELECT c.customer_id, c.age, c.income, c.purchase_amount, sr.cluster_label
                               FROM customers c
                               JOIN segmentation_results sr ON c.customer_id = sr.customer_id
                               ORDER BY sr.cluster_label";
                $detail_stmt = $pdo->query($detail_sql);
                $cluster_details = $detail_stmt->fetchAll(PDO::FETCH_ASSOC);
            } catch (PDOException $e) {
                // If cluster_metadata table doesn't exist yet, set to empty arrays
                $cluster_metadata = [];
                $cluster_details = [];
            }
            break;

        case 'purchase_tier':
            $sql = "SELECT CASE WHEN purchase_amount < 1000 THEN 'Low Spender (<1k)' WHEN purchase_amount BETWEEN 1000 AND 3000 THEN 'Medium Spender (1k-3k)' ELSE 'High Spender (>3k)' END AS purchase_tier, COUNT(*) AS total_customers, ROUND(AVG(income), 2) AS avg_income FROM customers GROUP BY purchase_tier ORDER BY purchase_tier";
            break;
        case 'clv_tier':
            // Note: Simplified CLV estimation using purchase_amount only
            // Tiers: Bronze (<5k), Silver (5k-10k), Gold (10k-20k), Platinum (>20k)
            $sql = "SELECT 
                        CASE 
                            WHEN purchase_amount < 5000 THEN 'Bronze (<5k)'
                            WHEN purchase_amount BETWEEN 5000 AND 9999 THEN 'Silver (5k-10k)'
                            WHEN purchase_amount BETWEEN 10000 AND 19999 THEN 'Gold (10k-20k)'
                            ELSE 'Platinum (>20k)'
                        END AS clv_tier, 
                        COUNT(*) AS total_customers, 
                        ROUND(AVG(income), 2) AS avg_income, 
                        ROUND(AVG(purchase_amount), 2) AS avg_purchase_amount 
                    FROM customers 
                    GROUP BY clv_tier 
                    ORDER BY avg_purchase_amount ASC";
            break;        
        case 'unassigned':
            $sql = "SELECT
                        c.customer_id,
                        c.name,
                        c.age,
                        c.gender,
                        c.income,
                        c.region,
                        c.purchase_amount
                    FROM customers c
                    WHERE c.customer_id NOT IN (
                        SELECT customer_id
                        FROM segmentation_results
                        WHERE customer_id IS NOT NULL
                    )
                    ORDER BY c.customer_id";
            break;

        default:
            $sql = "SELECT * FROM customers LIMIT 10"; // Default query
            break;
    }

        $_SESSION['export_sql'] = $sql;
        $_SESSION['is_cached'] = false;

        try {
            $stmt = $pdo->query($sql);
            $results = $stmt->fetchAll(PDO::FETCH_ASSOC);

            // 4. SAVE TO CACHE (Only if we have results)
            if (!empty($results)) {
                file_put_contents($cacheFile, json_encode($results));
            }

        } catch (PDOException $e) {
            die("Query execution failed: " . $e->getMessage());
        }
    }
}
// CSRF Token Initialization (For next form display)
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Customer Segmentation Dashboard</title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Chart.js -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>

<body>
    <div class="container mt-5">
        <h1 class="text-center mb-4">Customer Segmentation Dashboard</h1>

        <!-- Action Buttons -->
        <div class="d-flex justify-content-between align-items-center mb-3">
            <div>
                <a href="run_clustering.php?clusters=5" class="btn btn-success" target="_blank"
                    title="Run k-means clustering to segment customers">
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor"
                        class="bi bi-gear-fill" viewBox="0 0 16 16" style="vertical-align: -2px;">
                        <path
                            d="M9.405 1.05c-.413-1.4-2.397-1.4-2.81 0l-.1.34a1.464 1.464 0 0 1-2.105.872l-.31-.17c-1.283-.698-2.686.705-1.987 1.987l.169.311c.446.82.023 1.841-.872 2.105l-.34.1c-1.4.413-1.4 2.397 0 2.81l.34.1a1.464 1.464 0 0 1 .872 2.105l-.17.31c-.698 1.283.705 2.686 1.987 1.987l.311-.169a1.464 1.464 0 0 1 2.105.872l.1.34c.413 1.4 2.397 1.4 2.81 0l.1-.34a1.464 1.464 0 0 1 2.105-.872l.31.17c1.283.698 2.686-.705 1.987-1.987l-.169-.311a1.464 1.464 0 0 1 .872-2.105l.34-.1c1.4-.413 1.4-2.397 0-2.81l-.34-.1a1.464 1.464 0 0 1-.872-2.105l.17-.31c.698-1.283-.705-2.686-1.987-1.987l-.311.169a1.464 1.464 0 0 1-2.105-.872l-.1-.34zM8 10.93a2.929 2.929 0 1 1 0-5.86 2.929 2.929 0 0 1 0 5.858z" />
                    </svg>
                    Run Clustering
                </a>
                <small class="text-muted ms-2">Generate customer segments</small>
            </div>
            <div class="d-flex align-items-center gap-3">
                <span class="text-muted">Welcome, <strong><?= htmlspecialchars($_SESSION['username']) ?></strong></span>
                <a href="logout.php" class="btn btn-danger">Logout</a>
            </div>
        </div>

        <button type="button" class="btn btn-primary ms-0" data-bs-toggle="modal" data-bs-target="#exportModal">
            <svg xmlns="http://www.w3.org/2000/svg" width="22" height="16" fill="currentColor" class="bi bi-download" viewBox="0 0 16 16" style="vertical-align: -1px;">
             <path d="M.5 9.9a.5.5 0 0 1 .5.5v2.5a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-2.5a.5.5 0 0 1 1 0v2.5a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2v-2.5a.5.5 0 0 1 .5-.5z"/>
                <path d="M7.646 11.854a.5.5 0 0 0 .708 0l3-3a.5.5 0 0 0-.708-.708L8.5 10.293V1.5a.5.5 0 0 0-1 0v8.793L5.354 8.146a.5.5 0 1 0-.708.708l3 3z"/>
          </svg>
         Export Results
        </button>
        <a href="history.php" class="btn btn-outline-secondary px-1 py-0 ms-1">
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-clock-history" viewBox="0 0 16 16" style="vertical-align: -1px;">
                <path d="M8.515 1.019A7 7 0 0 0 8 1V0a8 8 0 0 1 .589.022l-.074.997zm2.004.45a7.003 7.003 0 0 0-.985-.299l.219-.976c.383.086.76.2 1.126.342l-.36.933zm1.37.71a7.01 7.01 0 0 0-.439-.27l.493-.87a8.025 8.025 0 0 1 .979.654l-.615.789a6.996 6.996 0 0 0-.418-.302zm1.834 1.79a6.99 6.99 0 0 0-.653-.796l.724-.69c.27.285.52.59.747.91l-.818.576zm.744 1.352a7.08 7.08 0 0 0-.214-.468l.893-.45a7.976 7.976 0 0 1 .45 1.088l-.95.313a7.023 7.023 0 0 0-.179-.483zm.53 2.507a6.991 6.991 0 0 0-.1-1.025l.985-.17c.067.386.106.778.116 1.17l-1 .025zm-.131 1.538c.033-.17.06-.339.081-.51l.993.123a7.957 7.957 0 0 1-.23 1.155l-.964-.267c.046-.165.086-.332.12-.501zm-.952 2.379c.184-.29.346-.594.486-.908l.914.405c-.16.36-.345.706-.555 1.038l-.845-.535zm-.964 1.205c.122-.122.239-.248.35-.378l.758.653a8.073 8.073 0 0 1-.401.432l-.707-.707z"/>
                <path d="M8 1a7 7 0 1 0 4.95 11.95l.707.707A8.001 8.001 0 1 1 8 0v1z"/>
                <path d="M7.5 3a.5.5 0 0 1 .5.5v5.21l3.248 1.856a.5.5 0 0 1-.496.868l-3.5-2A.5.5 0 0 1 7.5 8.5V3z"/>
            </svg>
            History
        </a>
        <div class="modal fade" id="exportModal" tabindex="-1">
           <div class="modal-dialog">
            <div class="modal-content text-dark"> <form action="export.php" method="POST" id="exportForm">
                <div class="modal-header">
                <h5 class="modal-title">Export Options</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
                <div class="modal-body">
                <div class="mb-3">
                     <label class="form-label">Format:</label>
                     <select name="format" class="form-select">
                         <option value="csv">CSV (Data Only)</option>
                        <option value="pdf">PDF (Includes Charts)</option>
                        <option value="excel">Excel (Includes Charts)</option>
                     </select>
                </div>

                <div class="mb-3">
                    <label class="form-label fw-bold">Select Columns to Export:</label>
                    <div class="border p-2 rounded" style="max-height: 200px; overflow-y: auto;">
                        <?php if (isset($results) && !empty($results)): ?>
                            <?php 
                            // Get column names from the first row of the results
                            $columns = array_keys($results[0]); 
                            foreach ($columns as $col): 
                                // Create a nice label (e.g., "avg_income" -> "Avg Income")
                                $label = ucwords(str_replace('_', ' ', $col));
                            ?>
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" name="cols[]" value="<?= $col ?>" checked id="col_<?= $col ?>"> 
                                    <label class="form-check-label" for="col_<?= $col ?>">
                                        <?= $label ?>
                                    </label>
                                </div>
                            <?php endforeach; ?>
                        <?php else: ?>
                            <p class="text-muted small">Please run a segmentation query first to see available columns.</p>
                        <?php endif; ?>
                    </div>
                </div>

                <input type="hidden" name="chart_image_main" id="chart_image_main">
                <input type="hidden" name="chart_image_pie" id="chart_image_pie">
                <input type="hidden" name="analysis_insights" id="analysis_insights_input">
            </div>
        <div class="modal-footer">
        <button type="submit" class="btn btn-primary" onclick="prepareExport()">Download</button>
        </div>
      </form>
    </div>
  </div>
</div>

        <!-- High severity alert -->
        <div class="d-none alert alert-danger alert-dismissible fade show d-flex align-items-start mb-3" role="alert">
            <div class="me-3 fs-4">⚠</div>
            <div class="flex-grow-1">
                <h6 class="alert-heading mb-1">Critical Segment Decline</h6>
                <p class="mb-1">
                    High-Income Young Premium segment revenue dropped by <strong>12%</strong> compared to last week.
                </p>
                <small class="text-muted">
                    Detected on 2026-01-15 at 09:42 AM
                </small>
            </div>
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>

        <!-- Segmentation Form -->
        <form method="POST" class="mb-4">
            <?= csrf_token_field() ?>
            <div class="row justify-content-center">
                <div class="col-md-6">
                    <div class="input-group">
                        <select name="segmentation_type" class="form-select" required>
                            <option value="" disabled <?= !isset($segmentationType) ? 'selected' : '' ?>>Select Segmentation Type</option>
                            <option value="gender" <?= isset($segmentationType) && $segmentationType === 'gender' ? 'selected' : '' ?>>By Gender</option>
                            <option value="region" <?= isset($segmentationType) && $segmentationType === 'region' ? 'selected' : '' ?>>By Region</option>
                            <option value="age_group" <?= isset($segmentationType) && $segmentationType === 'age_group' ? 'selected' : '' ?>>By Age Group</option>
                            <option value="income_bracket" <?= isset($segmentationType) && $segmentationType === 'income_bracket' ? 'selected' : '' ?>>By Income Bracket</option>
                            <option value="cluster" <?= isset($segmentationType) && $segmentationType === 'cluster' ? 'selected' : '' ?>>By Cluster</option>
                            <option value="purchase_tier" <?= isset($segmentationType) && $segmentationType === 'purchase_tier' ? 'selected' : '' ?>>By Purchase Tier</option>
                            <option value="clv_tier" <?= isset($segmentationType) && $segmentationType === 'clv_tier' ? 'selected' : '' ?>>By CLV Tier</option>
                            <option value="unassigned" <?= isset($segmentationType) && $segmentationType === 'unassigned' ? 'selected' : '' ?>>By Unassigned</option>
                        </select>
                        <button type="submit" class="btn btn-primary">Show Results</button>
                        <button type="button" class="btn btn-secondary" onclick="exportResults()">Export
                            Results</button>
                    </div>
                </div>
            </div>
        </form>

        <!-- Results Table -->
        <?php if (isset($results) && !empty($results)): ?>
            <table class="table table-striped table-bordered">
                <thead class="table-dark">
                    <tr>
                        <?php foreach (array_keys($results[0]) as $header): ?>
                            <th><?= ucfirst(str_replace('_', ' ', $header)) ?></th>
                        <?php endforeach; ?>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($results as $row): ?>
                        <tr>
                            <?php foreach ($row as $value): ?>
                                <td><?= htmlspecialchars($value) ?></td>
                            <?php endforeach; ?>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>

            <!-- Insights Section -->
            <div class="alert alert-info mb-4">
                <h5>Analysis Insights:</h5>
                <div id="insights"></div>
            </div>

            <!-- Charts Section -->
            <div class="row mb-4">
                <div class="col-md-8">
                    <canvas id="mainChart" width="400" height="200"></canvas>
                </div>
                <div class="col-md-4">
                    <canvas id="pieChart" width="200" height="200"></canvas>
                </div>
            </div>

            <?php if (!empty($results)): ?>
            <script>
                // 1. Initialize Data from PHP
                const segmentationType = '<?= htmlspecialchars($segmentationType, ENT_QUOTES, 'UTF-8') ?>';
                const results = <?= json_encode($results, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;

                // 2. Data Parsing Logic
                let labels, data, totalCustomers;
                
                if (segmentationType === 'unassigned') {
                    // Unassigned doesn't have aggregated data, just raw lists
                    labels = [];
                    data = [];
                    totalCustomers = results.length;
                } else {
                    // Dynamically grab keys: [0] is usually label (e.g., gender), [1] is count
                    if(results.length > 0) {
                        const keys = Object.keys(results[0]);
                        labels = results.map(row => row[keys[0]]);
                        data = results.map(row => row[keys[1]]); 
                        totalCustomers = data.reduce((a, b) => parseFloat(a) + parseFloat(b), 0);
                    } else {
                        labels = []; data = []; totalCustomers = 0;
                    }
                }

                // 3. Generate Insights Text
                let insights = '';
                if (totalCustomers === 0 && segmentationType !== 'unassigned') {
                    insights = '<p class="text-warning">No customer data available for analysis.</p>';
                } else {
                    insights = `<ul><li>Total records analyzed: <strong>${totalCustomers.toLocaleString()}</strong></li></ul>`;
                }
                
                // Update the insights div and hidden input for export
                const insightContainer = document.getElementById('insights');
                if(insightContainer) {
                    insightContainer.innerHTML = insights;
                    document.getElementById('analysis_insights_input').value = insightContainer.innerText;
                }

                // 4. Chart Generation
                const ctx1 = document.getElementById('mainChart').getContext('2d');
                const ctx2 = document.getElementById('pieChart').getContext('2d');
                
                const colors = [
                    'rgba(255, 99, 132, 0.8)', 'rgba(54, 162, 235, 0.8)',
                    'rgba(255, 206, 86, 0.8)', 'rgba(75, 192, 192, 0.8)',
                    'rgba(153, 102, 255, 0.8)', 'rgba(255, 159, 64, 0.8)'
                ];

                // --- Main Chart ---
                if (segmentationType === 'unassigned') {
                    // Special handling for Unassigned: Bar chart of Genders
                    const genderCounts = {};
                    results.forEach(r => { genderCounts[r.gender] = (genderCounts[r.gender] || 0) + 1; });
                    
                    new Chart(ctx1, {
                        type: 'bar',
                        data: {
                            labels: Object.keys(genderCounts),
                            datasets: [{
                                label: 'Count by Gender',
                                data: Object.values(genderCounts),
                                backgroundColor: 'rgba(54, 162, 235, 0.6)',
                                borderColor: 'rgba(54, 162, 235, 1)',
                                borderWidth: 1
                            }]
                        },
                        options: { responsive: true, plugins: { title: { display: true, text: 'Unassigned: Gender Distribution' } } }
                    });
                } else {
                    // Standard Logic for other types
                    const isLine = (segmentationType === 'age_group' || segmentationType === 'income_bracket');
                    const isHorizontal = (segmentationType === 'purchase_tier' || segmentationType === 'region');
                    
                    new Chart(ctx1, {
                        type: isLine ? 'line' : 'bar',
                        data: {
                            labels: labels,
                            datasets: [{
                                label: 'Total Customers',
                                data: data,
                                backgroundColor: 'rgba(54, 162, 235, 0.6)',
                                borderColor: 'rgba(54, 162, 235, 1)',
                                borderWidth: 1,
                                fill: isLine
                            }]
                        },
                        options: {
                            indexAxis: isHorizontal ? 'y' : 'x',
                            responsive: true,
                            plugins: {
                                title: { display: true, text: `Distribution by ${segmentationType.replace('_', ' ').toUpperCase()}` },
                                legend: { display: false }
                            }
                        }
                    });
                }

                // --- Pie Chart ---
                let pieLabels, pieData;
                if (segmentationType === 'unassigned') {
                    const regionCounts = {};
                    results.forEach(r => { regionCounts[r.region] = (regionCounts[r.region] || 0) + 1; });
                    pieLabels = Object.keys(regionCounts);
                    pieData = Object.values(regionCounts);
                } else {
                    pieLabels = labels;
                    pieData = data;
                }

                new Chart(ctx2, {
                    type: 'doughnut',
                    data: {
                        labels: pieLabels,
                        datasets: [{
                            data: pieData,
                            backgroundColor: colors.slice(0, pieLabels.length),
                            borderWidth: 1
                        }]
                    },
                    options: {
                        responsive: true,
                        plugins: {
                            title: { display: true, text: 'Distribution %' },
                            legend: { position: 'bottom', labels: { boxWidth: 12, font: { size: 10 } } }
                        }
                    }
                });

                // 5. REQUIRED: Export Helper Function
                // This makes the "Download" button work by capturing the charts
                function prepareExport() {
                    const mainChart = Chart.getChart("mainChart");
                    const pieChart = Chart.getChart("pieChart");
                    
                    if (mainChart) {
                        document.getElementById('chart_image_main').value = mainChart.toBase64Image();
                    }
                    if (pieChart) {
                        document.getElementById('chart_image_pie').value = pieChart.toBase64Image();
                    }
                    
                    const insightsDiv = document.getElementById('insights');
                    if(insightsDiv) {
                        document.getElementById('analysis_insights_input').value = insightsDiv.innerText;
                    }
                }
            </script>
            <?php else: ?>
                <div class="alert alert-warning text-center mt-4">
                    No data available for this segmentation.
                </div>
            <?php endif; ?>
                                
            </script>

            <!-- Enhanced Cluster Visualizations -->
            <?php 
                if ($segmentationType === 'cluster' && !empty($cluster_metadata)): ?>
                <hr class="my-5">

                <!-- Section 1: Cluster Characteristics -->
                <div class="row mb-4">
                    <div class="col-12">
                        <h4 class="mb-3">Cluster Characteristics</h4>
                    </div>
                    <?php
                    $total_customers = array_sum(array_column($cluster_metadata, 'customer_count'));
                    foreach ($cluster_metadata as $cluster):
                        $percentage = round(($cluster['customer_count'] / $total_customers) * 100, 1);
                        ?>
                        <div class="col-md-6 col-lg-4 mb-3">
                            <div class="card border-primary h-100">
                                <div class="card-header bg-primary text-white">
                                    <h6 class="mb-0">Cluster <?= $cluster['cluster_id'] ?>:
                                        <?= htmlspecialchars($cluster['cluster_name']) ?></h6>
                                </div>
                                <div class="card-body">
                                    <p class="card-text"><?= htmlspecialchars($cluster['description']) ?></p>
                                    <p class="text-muted mb-0">
                                        <strong><?= number_format($cluster['customer_count']) ?></strong> customers
                                        (<?= $percentage ?>%)
                                    </p>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>

                <!-- Section 2: Statistical Summaries -->
                <div class="row mb-4">
                    <div class="col-12">
                        <h4 class="mb-3">Cluster Statistics</h4>
                        <div class="table-responsive">
                            <table class="table table-striped table-bordered">
                                <thead class="table-dark">
                                    <tr>
                                        <th>Cluster</th>
                                        <th>Customers</th>
                                        <th>Age Range</th>
                                        <th>Avg Age</th>
                                        <th>Avg Income</th>
                                        <th>Avg Purchase</th>
                                        <th>Top Gender</th>
                                        <th>Top Region</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($cluster_metadata as $cluster): ?>
                                        <tr>
                                            <td><strong><?= htmlspecialchars($cluster['cluster_name']) ?></strong></td>
                                            <td><?= number_format($cluster['customer_count']) ?></td>
                                            <td><?= $cluster['age_min'] ?>-<?= $cluster['age_max'] ?></td>
                                            <td><?= round($cluster['avg_age'], 1) ?></td>
                                            <td>$<?= number_format($cluster['avg_income'], 2) ?></td>
                                            <td>$<?= number_format($cluster['avg_purchase_amount'], 2) ?></td>
                                            <td><?= htmlspecialchars($cluster['dominant_gender']) ?></td>
                                            <td><?= htmlspecialchars($cluster['dominant_region']) ?></td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <!-- Section 3: Cluster Feature Visualizations -->
                <div class="row mb-4">
                    <div class="col-12">
                        <h4 class="mb-3">Cluster Feature Comparisons</h4>
                    </div>

                    <div class="col-md-6 mb-3">
                        <div class="card">
                            <div class="card-body">
                                <canvas id="clusterRadarChart"></canvas>
                            </div>
                        </div>
                    </div>

                    <div class="col-md-6 mb-3">
                        <div class="card">
                            <div class="card-body">
                                <canvas id="clusterComparisonChart"></canvas>
                            </div>
                        </div>
                    </div>

                    <div class="col-12 mb-3">
                        <div class="card">
                            <div class="card-body">
                                <canvas id="clusterScatterChart" height="100"></canvas>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Section 4: Business Recommendations -->
                <div class="row mb-4">
                    <div class="col-12">
                        <h4 class="mb-3">Recommended Marketing Strategies</h4>
                    </div>
                    <?php foreach ($cluster_metadata as $cluster): ?>
                        <div class="col-md-6 mb-3">
                            <div class="card h-100">
                                <div class="card-header bg-success text-white">
                                    <h6 class="mb-0"><?= htmlspecialchars($cluster['cluster_name']) ?>
                                        (<?= number_format($cluster['customer_count']) ?> customers)</h6>
                                </div>
                                <div class="card-body">
                                    <ul class="mb-0">
                                        <?php
                                        $recommendations = explode(';', $cluster['business_recommendation']);
                                        foreach ($recommendations as $rec):
                                            ?>
                                            <li><?= htmlspecialchars(trim($rec)) ?></li>
                                        <?php endforeach; ?>
                                    </ul>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>

                <!-- Additional Charts JavaScript -->
                <script>
                    // Prepare data for advanced visualizations
                    const clusterMetadata = <?= json_encode($cluster_metadata) ?>;
                    const clusterDetails = <?= json_encode($cluster_details) ?>;

                    // Chart colors for clusters
                    const clusterColors = [
                        'rgba(255, 99, 132, 0.8)',
                        'rgba(54, 162, 235, 0.8)',
                        'rgba(255, 206, 86, 0.8)',
                        'rgba(75, 192, 192, 0.8)',
                        'rgba(153, 102, 255, 0.8)',
                        'rgba(255, 159, 64, 0.8)'
                    ];

                    // 1. Radar Chart - Normalized Feature Comparison
                    const radarCtx = document.getElementById('clusterRadarChart').getContext('2d');

                    // Normalize features to 0-1 scale
                    const allAges = clusterMetadata.map(c => parseFloat(c.avg_age));
                    const allIncomes = clusterMetadata.map(c => parseFloat(c.avg_income));
                    const allPurchases = clusterMetadata.map(c => parseFloat(c.avg_purchase_amount));

                    const minAge = Math.min(...allAges), maxAge = Math.max(...allAges);
                    const minIncome = Math.min(...allIncomes), maxIncome = Math.max(...allIncomes);
                    const minPurchase = Math.min(...allPurchases), maxPurchase = Math.max(...allPurchases);

                    const radarDatasets = clusterMetadata.map((cluster, index) => ({
                        label: cluster.cluster_name,
                        data: [
                            (parseFloat(cluster.avg_age) - minAge) / (maxAge - minAge),
                            (parseFloat(cluster.avg_income) - minIncome) / (maxIncome - minIncome),
                            (parseFloat(cluster.avg_purchase_amount) - minPurchase) / (maxPurchase - minPurchase)
                        ],
                        borderColor: clusterColors[index],
                        backgroundColor: clusterColors[index].replace('0.8', '0.2'),
                        borderWidth: 2
                    }));

                    new Chart(radarCtx, {
                        type: 'radar',
                        data: {
                            labels: ['Age', 'Income', 'Purchase Amount'],
                            datasets: radarDatasets
                        },
                        options: {
                            responsive: true,
                            plugins: {
                                title: {
                                    display: true,
                                    text: 'Cluster Feature Profile Comparison'
                                },
                                legend: {
                                    position: 'bottom',
                                    labels: {
                                        boxWidth: 15,
                                        font: { size: 10 }
                                    }
                                }
                            },
                            scales: {
                                r: {
                                    beginAtZero: true,
                                    max: 1,
                                    ticks: {
                                        stepSize: 0.2
                                    }
                                }
                            }
                        }
                    });

                    // 2. Grouped Bar Chart - Average Metrics
                    const groupedBarCtx = document.getElementById('clusterComparisonChart').getContext('2d');

                    new Chart(groupedBarCtx, {
                        type: 'bar',
                        data: {
                            labels: clusterMetadata.map(c => c.cluster_name),
                            datasets: [
                                {
                                    label: 'Average Income',
                                    data: clusterMetadata.map(c => parseFloat(c.avg_income)),
                                    backgroundColor: 'rgba(54, 162, 235, 0.6)',
                                    borderColor: 'rgba(54, 162, 235, 1)',
                                    borderWidth: 1,
                                    yAxisID: 'y'
                                },
                                {
                                    label: 'Average Purchase',
                                    data: clusterMetadata.map(c => parseFloat(c.avg_purchase_amount)),
                                    backgroundColor: 'rgba(255, 206, 86, 0.6)',
                                    borderColor: 'rgba(255, 206, 86, 1)',
                                    borderWidth: 1,
                                    yAxisID: 'y1'
                                }
                            ]
                        },
                        options: {
                            responsive: true,
                            plugins: {
                                title: {
                                    display: true,
                                    text: 'Average Income and Purchase by Cluster'
                                },
                                legend: {
                                    position: 'bottom'
                                }
                            },
                            scales: {
                                y: {
                                    type: 'linear',
                                    display: true,
                                    position: 'left',
                                    title: {
                                        display: true,
                                        text: 'Income ($)'
                                    }
                                },
                                y1: {
                                    type: 'linear',
                                    display: true,
                                    position: 'right',
                                    title: {
                                        display: true,
                                        text: 'Purchase ($)'
                                    },
                                    grid: {
                                        drawOnChartArea: false
                                    }
                                }
                            }
                        }
                    });

                    // 3. Scatter Plot - Income vs Purchase by Cluster
                    const scatterCtx = document.getElementById('clusterScatterChart').getContext('2d');

                    // Group customer data by cluster
                    const scatterDatasets = [];
                    const maxCluster = Math.max(...clusterDetails.map(c => parseInt(c.cluster_label)));

                    for (let i = 0; i <= maxCluster; i++) {
                        const clusterData = clusterDetails.filter(c => parseInt(c.cluster_label) === i);
                        const clusterName = clusterMetadata.find(m => m.cluster_id == i)?.cluster_name || `Cluster ${i}`;

                        scatterDatasets.push({
                            label: clusterName,
                            data: clusterData.map(c => ({
                                x: parseFloat(c.income),
                                y: parseFloat(c.purchase_amount)
                            })),
                            backgroundColor: clusterColors[i],
                            borderColor: clusterColors[i].replace('0.8', '1'),
                            borderWidth: 1,
                            pointRadius: 3,
                            pointHoverRadius: 5
                        });
                    }

                    new Chart(scatterCtx, {
                        type: 'scatter',
                        data: {
                            datasets: scatterDatasets
                        },
                        options: {
                            responsive: true,
                            plugins: {
                                title: {
                                    display: true,
                                    text: 'Customer Distribution: Income vs Purchase Amount by Cluster'
                                },
                                legend: {
                                    position: 'bottom',
                                    labels: {
                                        boxWidth: 15,
                                        font: { size: 10 }
                                    }
                                }
                            },
                            scales: {
                                x: {
                                    title: {
                                        display: true,
                                        text: 'Income ($)'
                                    }
                                },
                                y: {
                                    title: {
                                        display: true,
                                        text: 'Purchase Amount ($)'
                                    }
                                }
                            }
                        }
                    });
                </script>
            <?php endif; ?>
        <?php else: ?>
            <div class="alert alert-warning">
                <strong>No results found.</strong> 
                <?php if (isset($segmentationType) && $segmentationType === 'unassigned'): ?>
                    All customers have been assigned to clusters.
                <?php else: ?>
                    No data available for this segmentation type.
                <?php endif; ?>
            </div>
        <?php endif; ?>
    </div>

    <!-- Logout Script -->
    <script>
        document.querySelector('.btn-danger').addEventListener('click', function (e) {
            e.preventDefault();
            fetch('logout.php')
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        window.location.href = 'login.php';
                    }
                });
        });
    </script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
</body>

</html>