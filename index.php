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

            

            "WITH agg AS (
            SELECT
                sr.cluster_label,
                COUNT(*) AS total_customers,
                ROUND(AVG(c.income),2) AS avg_income,
                ROUND(AVG(c.purchase_amount),2) AS avg_purchase_amount,
                MIN(c.age) AS min_age,
                MAX(c.age) AS max_age
            FROM segmentation_results sr
            JOIN customers c USING (customer_id)
            GROUP BY sr.cluster_label
            ),
            dominant_gender AS (
            SELECT cluster_label, gender AS dominant_gender
            FROM (
                SELECT sr2.cluster_label, c2.gender,
                    ROW_NUMBER() OVER (PARTITION BY sr2.cluster_label ORDER BY COUNT(*) DESC) rn
                FROM segmentation_results sr2
                JOIN customers c2 USING (customer_id)
                GROUP BY sr2.cluster_label, c2.gender
            ) t
            WHERE rn = 1
            )
            SELECT a.*, dg.dominant_gender, cm.cluster_name, cm.customer_count, cm.description, cm.avg_income AS meta_avg_income
            FROM agg a
            LEFT JOIN dominant_gender dg ON dg.cluster_label = a.cluster_label
            LEFT JOIN cluster_metadata cm ON cm.cluster_id = a.cluster_label
            ORDER BY a.cluster_label;";
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
            // Logic: CLV = Purchase Amount * Frequency * Lifespan
            // Tiers: Bronze (<50k), Silver (50k-150k), Gold (150k-300k), Platinum (>300k)
            $sql = "SELECT 
                        CASE 
                            WHEN (purchase_amount * purchase_frequency * customer_lifespan) < 50000 THEN 'Bronze (<50k)'
                            WHEN (purchase_amount * purchase_frequency * customer_lifespan) BETWEEN 50000 AND 150000 THEN 'Silver (50k-150k)'
                            WHEN (purchase_amount * purchase_frequency * customer_lifespan) BETWEEN 150001 AND 300000 THEN 'Gold (150k-300k)'
                            ELSE 'Platinum (>300k)'
                        END AS clv_tier, 
                        COUNT(*) AS total_customers, 
                        ROUND(AVG(income), 2) AS avg_income, 
                        ROUND(AVG(purchase_amount * purchase_frequency * customer_lifespan), 2) AS avg_clv 
                    FROM customers 
                    GROUP BY clv_tier 
                    ORDER BY avg_clv ASC";
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
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-gear-fill" viewBox="0 0 16 16" style="vertical-align: -2px;">
                        <path d="M9.405 1.05c-.413-1.4-2.397-1.4-2.81 0l-.1.34a1.464 1.464 0 0 1-2.105.872l-.31-.17c-1.283-.698-2.686.705-1.987 1.987l.169.311c.446.82.023 1.841-.872 2.105l-.34.1c-1.4.413-1.4 2.397 0 2.81l.34.1a1.464 1.464 0 0 1 .872 2.105l-.17.31c-.698 1.283.705 2.686 1.987 1.987l.311-.169a1.464 1.464 0 0 1 2.105.872l.1.34c.413 1.4 2.397 1.4 2.81 0l.1-.34a1.464 1.464 0 0 1 2.105-.872l.31.17c1.283.698 2.686-.705 1.987-1.987l-.169-.311a1.464 1.464 0 0 1 .872-2.105l.34-.1c1.4-.413 1.4-2.397 0-2.81l-.34-.1a1.464 1.464 0 0 1-.872-2.105l.17-.31c.698-1.283-.705-2.686-1.987-1.987l-.311.169a1.464 1.464 0 0 1-2.105-.872l-.1-.34zM8 10.93a2.929 2.929 0 1 1 0-5.86 2.929 2.929 0 0 1 0 5.858z"/>
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
                            <option value="unassigned" <?= isset($segmentationType) && $segmentationType === 'unassigned' ? 'selected' : '' ?>>By Unassigned</option>
                        </select>
                        <button type="submit" class="btn btn-primary">Show Results</button>
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

            <script>
                const segmentationType = '<?= htmlspecialchars($segmentationType, ENT_QUOTES, 'UTF-8') ?>';
                const results = <?= json_encode($results, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
                
                // HTML escaping function to prevent XSS in dynamic content
                function escapeHtml(text) {
                    const div = document.createElement('div');
                    div.textContent = text;
                    return div.innerHTML;
                }
                
                // For unassigned, we don't have aggregated data, so handle differently
                let labels, data, totalCustomers;
                
                if (segmentationType === 'unassigned') {
                    labels = [];
                    data = [];
                    totalCustomers = results.length;
                } else {
                    labels = <?= json_encode(array_column($results, array_keys($results[0])[0])) ?>;
                    data = <?= json_encode(array_column($results, array_keys($results[0])[1])) ?>;
                    totalCustomers = data.reduce((a, b) => a + b, 0);
                }

                // Generate insights based on segmentation type
                let insights = '';
                const totalCustomers = data.reduce((a, b) => a + b, 0);
                if (totalCustomers === 0) {
                    insights = '<p class="text-warning">No customer data available for analysis.</p>';
                }else{
                switch(segmentationType) {
                    case 'gender':
                        const incomes = results.map(r => parseFloat(r.avg_income));
                        const incomeGap = results.length > 1 ? (Math.max(...incomes) - Math.min(...incomes)).toFixed(2) : 0;
                        insights = `<ul>
                            <li>Total customers analyzed: ${totalCustomers.toLocaleString()}</li>
                            <li>Gender distribution shows ${labels.length} categories</li>
                            <li>Largest segment: ${labels[data.indexOf(Math.max(...data))]} with ${Math.max(...data).toLocaleString()} customers (${(Math.max(...data)/totalCustomers*100).toFixed(1)}%)</li>
                            <li>Income gap between genders: $${parseFloat(incomeGap).toLocaleString()}</li>
                            ${results.length > 0 && results[0].avg_income ? `<li>Average income across genders ranges from $${Math.min(...results.map(r => parseFloat(r.avg_income))).toLocaleString()} to $${Math.max(...results.map(r => parseFloat(r.avg_income))).toLocaleString()}</li>` : ''}
                        </ul>`;
                        break;

                    case 'region':
                        insights = `<ul>
                            <li>Total customers across ${labels.length} regions: ${totalCustomers.toLocaleString()}</li>
                            <li>Top region: ${escapeHtml(labels[0])} with ${data[0].toLocaleString()} customers</li>
                            <li>Regional concentration: Top 3 regions represent ${((data[0] + (data[1]||0) + (data[2]||0))/totalCustomers*100).toFixed(1)}% of total customers</li>
                            ${results.length > 0 && results[0].avg_purchase_amount ? `<li>Purchase amounts vary from $${Math.min(...results.map(r => parseFloat(r.avg_purchase_amount))).toLocaleString()} to $${Math.max(...results.map(r => parseFloat(r.avg_purchase_amount))).toLocaleString()} across regions</li>` : ''}
                        </ul>`;
                        break;

                    case 'age_group':
                        insights = `<ul>
                            <li>Customer base distributed across ${labels.length} age groups</li>
                            <li>Dominant age group: ${escapeHtml(labels[data.indexOf(Math.max(...data))])} with ${Math.max(...data).toLocaleString()} customers (${(Math.max(...data)/totalCustomers*100).toFixed(1)}%)</li>
                            ${results.length > 0 && results[0].avg_income ? `<li>Income peaks in the ${escapeHtml(results.reduce((max, r) => parseFloat(r.avg_income) > parseFloat(max.avg_income) ? r : max).age_group || results[0].age_group)} age group at $${Math.max(...results.map(r => parseFloat(r.avg_income))).toLocaleString()}</li>` : ''}
                            ${results.length > 0 && results[0].avg_purchase_amount ? `<li>Highest spending age group: ${escapeHtml(results.reduce((max, r) => parseFloat(r.avg_purchase_amount) > parseFloat(max.avg_purchase_amount) ? r : max).age_group || results[0].age_group)}</li>` : ''}
                        </ul>`;
                        break;

                    case 'income_bracket':
                        insights = `<ul>
                            <li>Customers segmented into ${labels.length} income brackets</li>
                            <li>Largest income segment: ${escapeHtml(labels[data.indexOf(Math.max(...data))])} (${(Math.max(...data)/totalCustomers*100).toFixed(1)}% of customers)</li>
                            ${results.length > 0 && results[0].avg_purchase_amount ? `<li>Purchase behavior: ${escapeHtml(results.reduce((max, r) => parseFloat(r.avg_purchase_amount) > parseFloat(max.avg_purchase_amount) ? r : max).income_bracket || results[0].income_bracket)} shows highest average spending at $${Math.max(...results.map(r => parseFloat(r.avg_purchase_amount))).toLocaleString()}</li>` : ''}
                            <li>Income-purchase correlation can guide targeted marketing strategies</li>
                        </ul>`;
                        break;

                    case 'cluster':
                        // Check if we have enhanced metadata
                        if (typeof clusterMetadata !== 'undefined' && clusterMetadata.length > 0) {
                            const largestCluster = clusterMetadata.reduce((max, c) =>
                                c.customer_count > max.customer_count ? c : max
                            );
                            insights = `<ul>
                                <li>Advanced k-means clustering identified <strong>${clusterMetadata.length} distinct customer segments</strong></li>
                                <li>Largest segment: <strong>${escapeHtml(largestCluster.cluster_name)}</strong> with ${parseInt(largestCluster.customer_count).toLocaleString()} customers (${((largestCluster.customer_count/totalCustomers)*100).toFixed(1)}%)</li>
                                <li>Clusters range from "${escapeHtml(clusterMetadata[0].cluster_name)}" to "${escapeHtml(clusterMetadata[clusterMetadata.length-1].cluster_name)}"</li>
                                <li>Each cluster has unique demographics, income levels, and purchasing behaviors - view detailed analysis below</li>
                                <li><strong>Actionable insights:</strong> Scroll down to see cluster characteristics, statistics, visualizations, and marketing recommendations</li>
                            </ul>`;
                        } else {
                            // Fallback to original insights if metadata not available
                            insights = `<ul>
                                <li>Machine learning clustering identified ${labels.length} distinct customer segments</li>
                                <li>Largest cluster: ${escapeHtml(labels[data.indexOf(Math.max(...data))])} with ${Math.max(...data).toLocaleString()} customers</li>
                                ${results.length > 0 && results[0].min_age && results[0].max_age ? `<li>Age ranges vary across clusters, providing demographic differentiation</li>` : ''}
                                <li>Each cluster represents a unique customer profile for targeted campaigns</li>
                                <li><em>Note: Run the Python clustering script to generate enhanced cluster analysis with detailed explanations</em></li>
                            </ul>`;
                        }
                        break;

                    case 'purchase_tier':
                        insights = `<ul>
                            <li>Customers categorized into ${labels.length} spending tiers</li>
                            <li>Largest tier: ${escapeHtml(labels[data.indexOf(Math.max(...data))])} (${(Math.max(...data)/totalCustomers*100).toFixed(1)}% of customers)</li>
                            ${results.length > 0 && results[0].avg_income ? `<li>High spenders correlate with income levels averaging $${Math.max(...results.map(r => parseFloat(r.avg_income))).toLocaleString()}</li>` : ''}
                            <li>Understanding spending tiers enables personalized product recommendations</li>
                        </ul>`;
                        break;
                    case 'clv_tier':
                        insights = `<ul>
                            <li><strong>Customer Value Hierarchy:</strong> Segmented by Lifetime Value (Avg Purchase × Freq × Lifespan).</li>
                            <li><strong>Dominant Tier:</strong> ${labels[data.indexOf(Math.max(...data))]} with ${Math.max(...data).toLocaleString()} customers.</li>
                            ${results.length > 0 && results[0].avg_clv ? `<li><strong>Value Gap:</strong> The average Platinum customer is worth $${Math.max(...results.map(r => parseFloat(r.avg_clv))).toLocaleString()}, significantly higher than Bronze users ($${Math.min(...results.map(r => parseFloat(r.avg_clv))).toLocaleString()}).</li>` : ''}
                            <li><strong>Strategy:</strong> Focus on moving 'Silver' customers to 'Gold' by increasing their purchase frequency or retention (lifespan).</li>
                        </ul>`;
                        break;
                }

                    case 'unassigned':
                        const unassignedCount = results.length;
                        if (unassignedCount > 0) {
                            const ages = results.filter(r => r.age).map(r => parseInt(r.age));
                            const incomes = results.filter(r => r.income).map(r => parseFloat(r.income));
                            const purchases = results.filter(r => r.purchase_amount).map(r => parseFloat(r.purchase_amount));
                            
                            insights = `<ul>
                                <li>Found <strong>${unassignedCount.toLocaleString()} customers</strong> not assigned to any cluster</li>
                                <li>These customers represent potential segments that need analysis</li>
                                ${ages.length > 0 ? `<li>Age range: ${Math.min(...ages)} to ${Math.max(...ages)} years</li>` : ''}
                                ${incomes.length > 0 ? `<li>Income range: $${Math.min(...incomes).toLocaleString()} to $${Math.max(...incomes).toLocaleString()}</li>` : ''}
                                ${purchases.length > 0 ? `<li>Purchase range: $${Math.min(...purchases).toLocaleString()} to $${Math.max(...purchases).toLocaleString()}</li>` : ''}
                                <li><strong>Recommendation:</strong> Run the clustering script to include these customers in your segmentation analysis</li>
                            </ul>`;
                        } else {
                            insights = `<ul>
                                <li><strong>All customers have been assigned to clusters</strong></li>
                                <li>Your segmentation coverage is complete</li>
                                <li>Consider re-running clustering if you add new customers</li>
                            </ul>`;
                        }
                        break;
                }

                document.getElementById('insights').innerHTML = insights;

                // Main Bar/Line Chart
                const ctx1 = document.getElementById('mainChart').getContext('2d');
                const chartType = (segmentationType === 'age_group' || segmentationType === 'income_bracket') ? 'line' : 'bar';
                
                if (segmentationType === 'purchase_tier') {
                    new Chart(ctx1, {
                        type: 'bar',
                        data: {
                            labels: labels,
                            datasets: [{
                                label: 'Total Customers',
                                data: data,
                                backgroundColor: 'rgba(54, 162, 235, 0.6)',
                                borderColor: 'rgba(54, 162, 235, 1)',
                                borderWidth: 2
                            }]
                        },
                        options: {
                            indexAxis: 'y', 
                            responsive: true,
                            plugins: {
                                title: {
                                    display: true,
                                    text: 'Customer Distribution by Purchase Tier'
                                },
                                legend: {
                                    display: true
                                }
                            },
                            scales: {
                                x: {
                                    beginAtZero: true,
                                    title: {
                                        display: true,
                                        text: 'Number of Customers'
                                    }
                                }
                            }
                        }
                    });
                }else if (segmentationType === 'region') {
                    new Chart(ctx1, {
                        type: 'bar',
                        data: {
                            labels: labels,
                            datasets: [{
                                label: 'Total Customers',
                                data: data,
                                backgroundColor: 'rgba(75, 192, 192, 0.6)',
                                borderColor: 'rgba(75, 192, 192, 1)',
                                borderWidth: 2
                            }]
                        },
                        options: {
                            indexAxis: 'y', 
                            responsive: true,
                            plugins: {
                                title: {
                                    display: true,
                                    text: 'Customer Distribution by Region'
                                },
                                legend: {
                                    display: true
                                }
                            },
                            scales: {
                                x: {
                                    beginAtZero: true,
                                    title: {
                                        display: true,
                                        text: 'Number of Customers'
                                    }
                                }
                            }
                        }
                    });
                }else {
                    if (segmentationType === 'unassigned') {
                    // For unassigned, show demographic breakdown instead
                    const genderCounts = {};
                    const regionCounts = {};
                    results.forEach(r => {
                        genderCounts[r.gender] = (genderCounts[r.gender] || 0) + 1;
                        regionCounts[r.region] = (regionCounts[r.region] || 0) + 1;
                    });

                    new Chart(ctx1, {
                        type: 'bar',
                        data: {
                            labels: Object.keys(genderCounts),
                            datasets: [{
                                label: 'Count by Gender',
                                data: Object.values(genderCounts),
                                backgroundColor: 'rgba(54, 162, 235, 0.6)',
                                borderColor: 'rgba(54, 162, 235, 1)',
                                borderWidth: 2
                            }]
                        },
                        options: {
                            responsive: true,
                            plugins: {
                                title: {
                                    display: true,
                                    text: 'Unassigned Customers - Gender Distribution'
                                },
                                legend: {
                                    display: true
                                }
                            },
                            scales: {
                                y: {
                                    beginAtZero: true
                                }
                            }
                        }
                    });
                } else {
                    new Chart(ctx1, {
                        type: chartType,
                        data: {
                            labels: labels,
                            datasets: [{
                                label: '<?= ucfirst(str_replace('_', ' ', array_keys($results[0])[1])) ?>',
                                data: data,
                                backgroundColor: chartType === 'bar' ? 'rgba(54, 162, 235, 0.6)' : 'rgba(54, 162, 235, 0.2)',
                                borderColor: 'rgba(54, 162, 235, 1)',
                                borderWidth: 2,
                                fill: chartType === 'line'
                            }]
                        },
                        options: {
                            responsive: true,
                            plugins: {
                                title: {
                                    display: true,
                                    text: 'Customer Distribution by <?= ucfirst(str_replace('_', ' ', $segmentationType)) ?>'
                                },
                                legend: {
                                    display: true
                                }
                            },
                            scales: {
                                y: {
                                    beginAtZero: true
                                }
                            }
                        }
                    });
                }
                }
            const ctx2 = document.getElementById('pieChart').getContext('2d');
            const colors = [
                'rgba(255, 99, 132, 0.8)',
                'rgba(54, 162, 235, 0.8)',
                'rgba(255, 206, 86, 0.8)',
                'rgba(75, 192, 192, 0.8)',
                'rgba(153, 102, 255, 0.8)',
                'rgba(255, 159, 64, 0.8)'
            ];

                if (segmentationType === 'unassigned') {
                    // For unassigned, show region breakdown
                    const regionCounts = {};
                    results.forEach(r => {
                        regionCounts[r.region] = (regionCounts[r.region] || 0) + 1;
                    });

                    new Chart(ctx2, {
                        type: 'pie',
                        data: {
                            labels: Object.keys(regionCounts),
                            datasets: [{
                                data: Object.values(regionCounts),
                                backgroundColor: colors.slice(0, Object.keys(regionCounts).length),
                                borderWidth: 2,
                                borderColor: '#fff'
                            }]
                        },
                        options: {
                            responsive: true,
                            plugins: {
                                title: {
                                    display: true,
                                    text: 'Region Distribution %'
                                },
                                legend: {
                                    position: 'bottom',
                                    labels: {
                                        boxWidth: 15,
                                        font: {
                                            size: 10
                                        }
                                    }
                                }
                            }
                        }
                    });
                } else {
                new Chart(ctx2, {
                    type: 'doughnut',
                    data: {
                        labels: labels,
                        datasets: [{
                            data: data,
                            backgroundColor: colors.slice(0, labels.length),
                            borderWidth: 2,
                            borderColor: '#fff'
                        }]
                    },
                    options: {
                        responsive: true,
                        plugins: {
                            title: {
                                display: true,
                                text: 'Distribution %'
                            },
                            legend: {
                                position: 'bottom',
                                labels: {
                                    boxWidth: 15,
                                    font: {
                                        size: 10
                                    }
                                }
                            }
                        }
                    }
                    });
                }
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
                                <h6 class="mb-0">Cluster <?= $cluster['cluster_id'] ?>: <?= htmlspecialchars($cluster['cluster_name']) ?></h6>
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
                                <h6 class="mb-0"><?= htmlspecialchars($cluster['cluster_name']) ?> (<?= number_format($cluster['customer_count']) ?> customers)</h6>
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
        document.querySelector('.btn-danger').addEventListener('click', function(e) {
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