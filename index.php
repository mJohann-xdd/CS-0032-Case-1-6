<?php
session_start();
if (!isset($_SESSION['logged_in'])) {
    header('Location: login.php');
    exit;
}

require_once 'db.php';

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $segmentationType = filter_input(INPUT_POST, 'segmentation_type', FILTER_SANITIZE_STRING);

    switch ($segmentationType) {
        case 'gender':
            $sql = "SELECT gender, COUNT(*) AS total_customers, ROUND(AVG(income), 2) AS avg_income, ROUND(AVG(purchase_amount), 2) AS avg_purchase_amount FROM customers GROUP BY gender";
            break;

        case 'region':
            $sql = "SELECT region, COUNT(*) AS total_customers, ROUND(AVG(income), 2) AS avg_income, ROUND(AVG(purchase_amount), 2) AS avg_purchase_amount FROM customers GROUP BY region ORDER BY total_customers DESC";
            break;

        case 'age_group':
            $sql = "SELECT CASE WHEN age BETWEEN 18 AND 25 THEN '18-25' WHEN age BETWEEN 26 AND 40 THEN '26-40' WHEN age BETWEEN 41 AND 60 THEN '41-60' ELSE '61+' END AS age_group, COUNT(*) AS total_customers, ROUND(AVG(income), 2) AS avg_income, ROUND(AVG(purchase_amount), 2) AS avg_purchase_amount FROM customers GROUP BY age_group ORDER BY age_group";
            break;

        case 'income_bracket':
            $sql = "SELECT CASE WHEN income < 30000 THEN 'Low Income (<30k)' WHEN income BETWEEN 30000 AND 70000 THEN 'Middle Income (30k-70k)' ELSE 'High Income (>70k)' END AS income_bracket, COUNT(*) AS total_customers, ROUND(AVG(purchase_amount), 2) AS avg_purchase_amount FROM customers GROUP BY income_bracket ORDER BY income_bracket";
            break;

        case 'cluster':
            $sql = "SELECT sr.cluster_label, COUNT(*) AS total_customers, ROUND(AVG(c.income), 2) AS avg_income, ROUND(AVG(c.purchase_amount), 2) AS avg_purchase_amount, MIN(c.age) AS min_age, MAX(c.age) AS max_age FROM segmentation_results sr JOIN customers c ON sr.customer_id = c.customer_id GROUP BY sr.cluster_label ORDER BY sr.cluster_label";

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

        default:
            $sql = "SELECT * FROM customers LIMIT 10"; // Default query
    }

    try {
        $stmt = $pdo->query($sql);
        $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
    } catch (PDOException $e) {
        die("Query execution failed: " . $e->getMessage());
    }
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
            <div>
                <a href="logout.php" class="btn btn-danger">Logout</a>
            </div>
        </div>

        <!-- Segmentation Form -->
        <form method="POST" class="mb-4">
            <div class="row justify-content-center">
                <div class="col-md-6">
                    <div class="input-group">
                        <select name="segmentation_type" class="form-select" required>
                            <option value="" disabled selected>Select Segmentation Type</option>
                            <option value="gender">By Gender</option>
                            <option value="region">By Region</option>
                            <option value="age_group">By Age Group</option>
                            <option value="income_bracket">By Income Bracket</option>
                            <option value="cluster">By Cluster</option>
                            <option value="purchase_tier">By Purchase Tier</option>
                        </select>
                        <button type="submit" class="btn btn-primary">Show Results</button>
                    </div>
                </div>
            </div>
        </form>

        <!-- Results Table -->
        <?php if (isset($results)): ?>
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
                const segmentationType = '<?= $segmentationType ?>';
                const labels = <?= json_encode(array_column($results, array_keys($results[0])[0])) ?>;
                const data = <?= json_encode(array_column($results, array_keys($results[0])[1])) ?>;
                const results = <?= json_encode($results) ?>;

                // Generate insights based on segmentation type
                let insights = '';
                const totalCustomers = data.reduce((a, b) => a + b, 0);

                switch(segmentationType) {
                    case 'gender':
                        insights = `<ul>
                            <li>Total customers analyzed: ${totalCustomers.toLocaleString()}</li>
                            <li>Gender distribution shows ${labels.length} categories</li>
                            <li>Largest segment: ${labels[data.indexOf(Math.max(...data))]} with ${Math.max(...data).toLocaleString()} customers (${(Math.max(...data)/totalCustomers*100).toFixed(1)}%)</li>
                            ${results.length > 0 && results[0].avg_income ? `<li>Average income across genders ranges from $${Math.min(...results.map(r => parseFloat(r.avg_income))).toLocaleString()} to $${Math.max(...results.map(r => parseFloat(r.avg_income))).toLocaleString()}</li>` : ''}
                        </ul>`;
                        break;

                    case 'region':
                        insights = `<ul>
                            <li>Total customers across ${labels.length} regions: ${totalCustomers.toLocaleString()}</li>
                            <li>Top region: ${labels[0]} with ${data[0].toLocaleString()} customers</li>
                            <li>Regional concentration: Top 3 regions represent ${((data[0] + (data[1]||0) + (data[2]||0))/totalCustomers*100).toFixed(1)}% of total customers</li>
                            ${results.length > 0 && results[0].avg_purchase_amount ? `<li>Purchase amounts vary from $${Math.min(...results.map(r => parseFloat(r.avg_purchase_amount))).toLocaleString()} to $${Math.max(...results.map(r => parseFloat(r.avg_purchase_amount))).toLocaleString()} across regions</li>` : ''}
                        </ul>`;
                        break;

                    case 'age_group':
                        insights = `<ul>
                            <li>Customer base distributed across ${labels.length} age groups</li>
                            <li>Dominant age group: ${labels[data.indexOf(Math.max(...data))]} with ${Math.max(...data).toLocaleString()} customers (${(Math.max(...data)/totalCustomers*100).toFixed(1)}%)</li>
                            ${results.length > 0 && results[0].avg_income ? `<li>Income peaks in the ${results.reduce((max, r) => parseFloat(r.avg_income) > parseFloat(max.avg_income) ? r : max).age_group || results[0].age_group} age group at $${Math.max(...results.map(r => parseFloat(r.avg_income))).toLocaleString()}</li>` : ''}
                            ${results.length > 0 && results[0].avg_purchase_amount ? `<li>Highest spending age group: ${results.reduce((max, r) => parseFloat(r.avg_purchase_amount) > parseFloat(max.avg_purchase_amount) ? r : max).age_group || results[0].age_group}</li>` : ''}
                        </ul>`;
                        break;

                    case 'income_bracket':
                        insights = `<ul>
                            <li>Customers segmented into ${labels.length} income brackets</li>
                            <li>Largest income segment: ${labels[data.indexOf(Math.max(...data))]} (${(Math.max(...data)/totalCustomers*100).toFixed(1)}% of customers)</li>
                            ${results.length > 0 && results[0].avg_purchase_amount ? `<li>Purchase behavior: ${results.reduce((max, r) => parseFloat(r.avg_purchase_amount) > parseFloat(max.avg_purchase_amount) ? r : max).income_bracket || results[0].income_bracket} shows highest average spending at $${Math.max(...results.map(r => parseFloat(r.avg_purchase_amount))).toLocaleString()}</li>` : ''}
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
                                <li>Largest segment: <strong>${largestCluster.cluster_name}</strong> with ${parseInt(largestCluster.customer_count).toLocaleString()} customers (${((largestCluster.customer_count/totalCustomers)*100).toFixed(1)}%)</li>
                                <li>Clusters range from "${clusterMetadata[0].cluster_name}" to "${clusterMetadata[clusterMetadata.length-1].cluster_name}"</li>
                                <li>Each cluster has unique demographics, income levels, and purchasing behaviors - view detailed analysis below</li>
                                <li><strong>Actionable insights:</strong> Scroll down to see cluster characteristics, statistics, visualizations, and marketing recommendations</li>
                            </ul>`;
                        } else {
                            // Fallback to original insights if metadata not available
                            insights = `<ul>
                                <li>Machine learning clustering identified ${labels.length} distinct customer segments</li>
                                <li>Largest cluster: ${labels[data.indexOf(Math.max(...data))]} with ${Math.max(...data).toLocaleString()} customers</li>
                                ${results.length > 0 && results[0].min_age && results[0].max_age ? `<li>Age ranges vary across clusters, providing demographic differentiation</li>` : ''}
                                <li>Each cluster represents a unique customer profile for targeted campaigns</li>
                                <li><em>Note: Run the Python clustering script to generate enhanced cluster analysis with detailed explanations</em></li>
                            </ul>`;
                        }
                        break;

                    case 'purchase_tier':
                        insights = `<ul>
                            <li>Customers categorized into ${labels.length} spending tiers</li>
                            <li>Largest tier: ${labels[data.indexOf(Math.max(...data))]} (${(Math.max(...data)/totalCustomers*100).toFixed(1)}% of customers)</li>
                            ${results.length > 0 && results[0].avg_income ? `<li>High spenders correlate with income levels averaging $${Math.max(...results.map(r => parseFloat(r.avg_income))).toLocaleString()}</li>` : ''}
                            <li>Understanding spending tiers enables personalized product recommendations</li>
                        </ul>`;
                        break;
                }

                document.getElementById('insights').innerHTML = insights;

                // Main Bar/Line Chart
                const ctx1 = document.getElementById('mainChart').getContext('2d');

                // changes are here for dynamic chart type
                let chartType = 'bar';
                let indexAxis = 'x';

                if(segmentationType === 'age_group' || segmentationType === 'income_bracket'){
                    chartType = 'line';
                }else if(segmentationType === 'region'){
                    chartType = 'bar';
                    indexAxis = 'y';
                }
                //const chartType = (segmentationType === 'age_group' || segmentationType === 'income_bracket') ? 'line' : 'bar';

                if (segmentation_type === 'purchase_tier'){
                    new Chart(ctx1, {
                        type: 'radar',
                        data: {
                            labels: labels,
                            datasets: [{
                                label: 'Purchase Tier Segmentation',
                                data: data,
                                backgroundColor: 'rgba(54, 162, 235, 0.2)',
                                borderColor: 'rgba(54, 162, 235, 1)',
                                pointBackgroundColor: 'rgba(54, 162, 235, 1)',
                                borderWidth: 2,
                            }]
                        },
                        options:{
                            responsive: true,
                            scales: {
                                r: {
                                    beginAtZero: true
                                }
                            }
                        }
                    });
                    return;
                }
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

                // Pie Chart for Distribution
                const ctx2 = document.getElementById('pieChart').getContext('2d');
                const colors = [
                    'rgba(255, 99, 132, 0.8)',
                    'rgba(54, 162, 235, 0.8)',
                    'rgba(255, 206, 86, 0.8)',
                    'rgba(75, 192, 192, 0.8)',
                    'rgba(153, 102, 255, 0.8)',
                    'rgba(255, 159, 64, 0.8)'
                ];

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
                        cutout: '60%',
                        plugins: {
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
            </script>

            <!-- Enhanced Cluster Visualizations -->
            <?php if ($segmentationType === 'cluster' && !empty($cluster_metadata)): ?>
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
</body>
</html>