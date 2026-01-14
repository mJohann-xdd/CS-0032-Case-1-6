<?php
// export.php - Handles CSV, Excel, and PDF generation

// 1. Security & Session Setup (Must match index.php)
define('SESSION_TIMEOUT', 1800);
define('SESSION_ABSOLUTE_TIMEOUT', 28800);

function configure_secure_session() {
    $is_https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || $_SERVER['SERVER_PORT'] == 443;
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'domain' => '',
        'secure' => $is_https,
        'httponly' => true,
        'samesite' => 'Strict'
    ]);
    session_name('CSAPP_SESSION');
}
configure_secure_session();
session_start();

// 2. Authentication Check
if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
    header('Location: login.php');
    exit;
}

require_once 'db.php';

// 3. Retrieve Data from Session
// We use the SQL query saved by index.php to ensure we export exactly what the user saw.
$sql = $_SESSION['export_sql'] ?? '';

if (empty($sql)) {
    die("Error: No data found to export. Please run a segmentation query first.");
}

// 4. Execute Query
try {
    $stmt = $pdo->query($sql);
    $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    die("Export Error: " . $e->getMessage());
}

if (empty($results)) {
    die("The query returned no results to export.");
}

// 5. Get Export Options from POST
$format = $_POST['format'] ?? 'csv';
$selected_cols = $_POST['cols'] ?? array_keys($results[0]); // Default to all columns if none selected

// Filter results to only include selected columns
$filtered_results = [];
foreach ($results as $row) {
    $new_row = [];
    foreach ($selected_cols as $col) {
        if (array_key_exists($col, $row)) {
            $new_row[$col] = $row[$col];
        }
    }
    $filtered_results[] = $new_row;
}

// 6. Handle Formatting
$filename = 'segmentation_export_' . date('Y-m-d_H-i');

switch ($format) {
    case 'csv':
        // --- CSV EXPORT ---
        header('Content-Type: text/csv');
        header('Content-Disposition: attachment; filename="' . $filename . '.csv"');
        
        $output = fopen('php://output', 'w');
        
        // Output Header
        // Make headers readable (e.g., avg_income -> Avg Income)
        $headers = array_map(function($col) {
            return ucwords(str_replace('_', ' ', $col));
        }, $selected_cols);
        fputcsv($output, $headers);
        
        // Output Data
        foreach ($filtered_results as $row) {
            fputcsv($output, $row);
        }
        fclose($output);
        exit;

    case 'excel':
        // --- EXCEL EXPORT (HTML Table Method) ---
        // This is a simple way to generate Excel files without needing libraries like PhpSpreadsheet
        header('Content-Type: application/vnd.ms-excel');
        header('Content-Disposition: attachment; filename="' . $filename . '.xls"');
        
        echo '<html xmlns:x="urn:schemas-microsoft-com:office:excel">';
        echo '<head><meta charset="UTF-8"></head>';
        echo '<body>';
        echo '<table border="1">';
        
        // Header
        echo '<tr style="background-color: #f0f0f0; font-weight: bold;">';
        foreach ($selected_cols as $col) {
            echo '<td>' . htmlspecialchars(ucwords(str_replace('_', ' ', $col))) . '</td>';
        }
        echo '</tr>';
        
        // Data
        foreach ($filtered_results as $row) {
            echo '<tr>';
            foreach ($row as $val) {
                echo '<td>' . htmlspecialchars($val) . '</td>';
            }
            echo '</tr>';
        }
        echo '</table>';
        
        // Add Insights if available
        if (!empty($_POST['analysis_insights'])) {
            echo '<br><h3>Analysis Insights</h3>';
            echo '<div>' . $_POST['analysis_insights'] . '</div>';
        }

        // Add Charts (Images are hard in this Excel format, usually skipped or require complex libraries)
        // We stick to data + insights for Excel.
        
        echo '</body></html>';
        exit;

    case 'pdf':
        // --- PDF / PRINT VIEW ---
        // Generating a real PDF in PHP requires a library (FPDF/TCPDF). 
        // A robust "Zero-Dependency" alternative is to generate a clean HTML print view 
        // that automatically triggers the browser's "Save as PDF" dialog.
        
        $chartMain = $_POST['chart_image_main'] ?? '';
        $chartPie = $_POST['chart_image_pie'] ?? '';
        $insights = $_POST['analysis_insights'] ?? '';
        ?>
        <!DOCTYPE html>
        <html>
        <head>
            <title>Export Result</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
            <style>
                body { padding: 20px; }
                .chart-container { display: flex; justify-content: space-around; margin: 20px 0; }
                .chart-box { width: 45%; text-align: center; border: 1px solid #ddd; padding: 10px; }
                img { max-width: 100%; height: auto; }
                @media print {
                    .no-print { display: none; }
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <h1>Segmentation Analysis Report</h1>
                    <button class="btn btn-primary no-print" onclick="window.print()">🖨 Print / Save as PDF</button>
                </div>
                
                <p class="text-muted">Generated on: <?= date('F j, Y, g:i a') ?></p>
                <hr>

                <?php if($insights): ?>
                <div class="card mb-4">
                    <div class="card-header bg-info text-white">Key Insights</div>
                    <div class="card-body">
                        <?= $insights ?> </div>
                </div>
                <?php endif; ?>

                <div class="chart-container">
                    <?php if($chartMain): ?>
                    <div class="chart-box">
                        <h5>Distribution Chart</h5>
                        <img src="<?= htmlspecialchars($chartMain) ?>" alt="Main Chart">
                    </div>
                    <?php endif; ?>
                    
                    <?php if($chartPie): ?>
                    <div class="chart-box">
                        <h5>Ratio Chart</h5>
                        <img src="<?= htmlspecialchars($chartPie) ?>" alt="Pie Chart">
                    </div>
                    <?php endif; ?>
                </div>

                <h3>Data Details</h3>
                <table class="table table-striped table-bordered table-sm">
                    <thead class="table-dark">
                        <tr>
                            <?php foreach ($selected_cols as $col): ?>
                                <th><?= htmlspecialchars(ucwords(str_replace('_', ' ', $col))) ?></th>
                            <?php endforeach; ?>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($filtered_results as $row): ?>
                            <tr>
                                <?php foreach ($row as $val): ?>
                                    <td><?= htmlspecialchars($val) ?></td>
                                <?php endforeach; ?>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
            
            <script>
                // Automatically open print dialog when loaded
                window.onload = function() {
                    setTimeout(function() { window.print(); }, 500);
                }
            </script>
        </body>
        </html>
        <?php
        exit;
}
?>