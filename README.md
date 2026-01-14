
# Customer Segmentation Dashboard - Case Study

## Learning Objectives

By completing this case study, students will demonstrate:

1. **Technical Proficiency**
   - PHP programming and session management
   - MySQL database design and complex SQL queries
   - JavaScript and Chart.js for data visualization
   - Understanding of k-means clustering algorithm

2. **Security Awareness**
   - Identification of common web vulnerabilities
   - Implementation of security best practices
   - Secure coding techniques

3. **Software Engineering**
   - Code quality assessment and refactoring
   - Performance optimization strategies
   - Testing methodologies (unit, integration, UAT)
   - Scalability considerations

4. **Business Acumen**
   - Translation of technical features to business value
   - Marketing strategy based on data insights
   - ROI analysis and decision-making

5. **Critical Thinking**
   - Analysis of existing code and architecture
   - Problem-solving and design skills
   - Trade-off evaluation (e.g., security vs usability)


## Project Overview

This case study examines a PHP-based customer segmentation dashboard application that demonstrates data-driven marketing analytics. The application provides business intelligence through multiple customer segmentation strategies and includes a pure PHP implementation of k-means clustering algorithm for advanced customer profiling.

**Key Technologies:**
- Backend: PHP 7+, PDO for database access
- Database: MySQL
- Frontend: HTML5, Bootstrap 5.3, JavaScript
- Data Visualization: Chart.js
- Server: XAMPP (Apache + MySQL)

**Core Features:**
1. Session-based authentication system
2. Six customer segmentation types (Gender, Region, Age Group, Income Bracket, Purchase Tier, ML Clusters)
3. Interactive data visualizations (bar charts, line charts, pie charts, radar charts, scatter plots)
4. Pure PHP k-means clustering implementation 
5. Automated business insights generation
6. Marketing recommendations based on cluster analysis

---

## Part 1: Understanding the Architecture

### Question 1.1: Authentication Flow 

Analyze the authentication system implemented in this application.

**Tasks:**
1. Trace the complete authentication flow from login to logout
2. Identify where session data is stored and how it's validated
3. List all security measures implemented in the login system
4. Identify at least THREE security vulnerabilities in the current implementation
5. Propose improvements for the authentication system

**Files to examine:** `login.php:1-56`, `index.php:2-6`, `logout.php`


---

### Question 1.2: Database Architecture

Examine the database design and connection strategy.

**Tasks:**
1. Draw an Entity-Relationship Diagram (ERD) showing all three tables and their relationships
2. Identify the primary keys and foreign keys for each table
3. Explain the purpose of the `cluster_metadata` table and how it relates to `segmentation_results`
4. Analyze the database connection configuration in `db.php` - what are the security implications?
5. Suggest THREE improvements to the database schema design

**Files to examine:** `db.php:1-14`, `sql/create_cluster_metadata.sql:1-27`, `index.php:31-52`

**Reference Tables:**
- `customers` (customer_id, age, gender, income, purchase_amount, region)
- `segmentation_results` (customer_id, cluster_label)
- `cluster_metadata` (cluster_id, cluster_name, description, statistics...)

---

### Question 1.3: Request-Response Cycle 

Map the complete request-response cycle for a segmentation query.

**Tasks:**
1. Document step-by-step what happens when a user selects "By Age Group" and clicks "Show Results"
2. Identify which HTTP method is used and why
3. Explain how the segmentation type is sanitized and processed
4. Describe how the results are transformed from database rows to visual charts
5. What happens if the SQL query fails? Trace the error handling mechanism.

**Files to examine:** `index.php:11-68`, `index.php:160-321`

---

## Part 2: SQL Query Analysis

### Question 2.1: Understanding Segmentation Queries 

Analyze the SQL queries used for different segmentation types.

**Given SQL (Age Group Segmentation):**
```sql
SELECT
    CASE
        WHEN age BETWEEN 18 AND 25 THEN '18-25'
        WHEN age BETWEEN 26 AND 40 THEN '26-40'
        WHEN age BETWEEN 41 AND 60 THEN '41-60'
        ELSE '61+'
    END AS age_group,
    COUNT(*) AS total_customers,
    ROUND(AVG(income), 2) AS avg_income,
    ROUND(AVG(purchase_amount), 2) AS avg_purchase_amount
FROM customers
GROUP BY age_group
ORDER BY age_group
```

**Tasks:**
1. Explain the purpose of the CASE statement in this query
2. What would happen if a customer has age = NULL? How is this handled?
3. Rewrite this query to include age groups: 0-17, 18-25, 26-35, 36-50, 51-65, 66+
4. Modify the query to also show the minimum and maximum purchase amounts per age group
5. Why is `ROUND(AVG(income), 2)` used instead of just `AVG(income)`?

**File reference:** `index.php:23-25`

---

### Question 2.2: Complex JOIN Operations 

Examine the cluster segmentation query that uses JOINs.

**Given SQL:**
```sql
SELECT
    sr.cluster_label,
    COUNT(*) AS total_customers,
    ROUND(AVG(c.income), 2) AS avg_income,
    ROUND(AVG(c.purchase_amount), 2) AS avg_purchase_amount,
    MIN(c.age) AS min_age,
    MAX(c.age) AS max_age
FROM segmentation_results sr
JOIN customers c ON sr.customer_id = c.customer_id
GROUP BY sr.cluster_label
ORDER BY sr.cluster_label
```

**Tasks:**
1. Explain what type of JOIN is being used and why
2. What would happen if there are customers in `customers` table but not in `segmentation_results`?
3. Draw a Venn diagram showing which records would be returned
4. Modify this query to also include the dominant gender for each cluster
5. Write a query that shows customers who are NOT assigned to any cluster

**File reference:** `index.php:31-33`

---

### Question 2.3: Query Optimization 

Analyze query performance and optimization opportunities.

**Tasks:**
1. Identify which queries would benefit from database indexes
2. Propose specific indexes to create (table name, column name, index type)
3. The cluster query runs three separate SQL statements (lines 36-46). Could these be combined? How?
4. What is the Big-O time complexity of the income bracket query?
5. Suggest a caching strategy to avoid running the same query multiple times

**File reference:** `index.php:14-68`

---

## Part 3: Security Assessment

### Question 3.1: Input Validation and Sanitization 

Evaluate the application's defense against common web vulnerabilities.

**Code snippet:**
```php
$segmentationType = filter_input(INPUT_POST, 'segmentation_type', FILTER_SANITIZE_STRING);
```

**Tasks:**
1. Explain what `filter_input()` with `FILTER_SANITIZE_STRING` does
2. Is this sufficient protection against SQL injection? Why or why not?
3. Identify ALL user input points in the application (forms, URL parameters, etc.)
4. For each input point, assess if it's properly validated/sanitized
5. Demonstrate with code how an attacker might exploit any vulnerabilities you find

**Files to examine:** `index.php:12`, `login.php:9-10`, `run_clustering.php:512-516`

---

### Question 3.2: XSS Prevention 

Analyze Cross-Site Scripting (XSS) vulnerabilities.

**Code snippet:**
```php
<td><?= htmlspecialchars($value) ?></td>
```

**Tasks:**
1. Explain why `htmlspecialchars()` is used in the output
2. Find at least TWO places in the code where user/database data is output WITHOUT escaping
3. Write an example XSS payload that could exploit these vulnerabilities
4. Propose fixes for each vulnerability
5. Should cluster names from the database be escaped? Why or why not?

**File reference:** `index.php:137`, `index.php:340-346`

---

### Question 3.3: Session Security 

Assess the session management implementation.

**Tasks:**
1. What session security measures are currently implemented?
2. List FIVE session-related vulnerabilities in this application
3. Propose specific code changes to implement:
   - Session fixation prevention
   - Session timeout
   - CSRF token protection
   - Secure session cookie flags
4. Write pseudocode for a session timeout mechanism (logout after 30 minutes of inactivity)

**Files to examine:** `login.php:2`, `index.php:2-6`, `logout.php`

---

## Part 4: K-Means Clustering Algorithm

### Question 4.1: Algorithm Understanding

Demonstrate your understanding of the k-means implementation.

**Tasks:**
1. Explain in your own words how the k-means algorithm works
2. Why is data normalization (z-score) necessary? What would happen without it?
3. Trace the execution of the algorithm for 3 data points and 2 clusters:
   - Point A: age=25, income=30000, purchase=1000
   - Point B: age=50, income=80000, purchase=4000
   - Point C: age=30, income=35000, purchase=1200
4. Explain the purpose of the k-means++ initialization method (lines 95-131)
5. What is the convergence threshold and why is it needed?

**File reference:** `run_clustering.php:33-241`

---

### Question 4.2: Algorithmic Complexity 

Analyze the computational complexity of the clustering implementation.

**Tasks:**
1. Calculate the Big-O time complexity of:
   - `normalizeData()` function
   - `euclideanDistance()` function
   - `assignClusters()` function
   - Entire `fit()` method
2. What is the space complexity of the algorithm?
3. If you have 10,000 customers and 5 clusters, approximately how many distance calculations occur per iteration?
4. Identify the most computationally expensive operation in the algorithm
5. Suggest TWO optimizations to improve performance for large datasets

**File reference:** `run_clustering.php:50-240`

---

### Question 4.3: Business Logic Implementation 

Examine how clusters are interpreted and named.

**Code snippet (lines 268-272):**
```php
function generateClusterName($avgAge, $avgIncome, $avgPurchase) {
    return getIncomeCategory($avgIncome) . " " .
           getAgeCategory($avgAge) . " " .
           getSpendingCategory($avgPurchase);
}
```

**Tasks:**
1. For a cluster with avg_age=35, avg_income=55000, avg_purchase=2800, what name would be generated?
2. Explain the business logic behind the recommendation rules (lines 288-346)
3. Critique this naming system - what are its strengths and weaknesses?
4. Design an alternative cluster naming system that considers gender and region
5. Write pseudocode for a function that generates email marketing templates based on cluster characteristics

**File reference:** `run_clustering.php:247-346`

---

## Part 5: Frontend and Data Visualization

### Question 5.1: Chart.js Implementation

Analyze the data visualization implementation.

**Tasks:**
1. Explain why line charts are used for age_group and income_bracket, but bar charts for others (line 246)
2. Trace how PHP data is converted to JavaScript arrays for Chart.js (lines 162-164)
3. The pie chart uses a predefined color array. What happens if there are 7+ segments?
4. Modify the code to use different chart types:
   - Horizontal bar chart for region segmentation
   - Doughnut chart instead of pie chart
5. Design a new visualization type (your choice) for the purchase tier segmentation

**File reference:** `index.php:160-321`

---

### Question 5.2: Dynamic Insights Generation

Examine the JavaScript-based insights engine.

**Code snippet (lines 170-240):**
```javascript
switch(segmentationType) {
    case 'gender':
        insights = `<ul>
            <li>Total customers analyzed: ${totalCustomers.toLocaleString()}</li>
            <li>Gender distribution shows ${labels.length} categories</li>
            ...
        </ul>`;
        break;
    // ... more cases
}
```

**Tasks:**
1. Explain how the insights are customized for each segmentation type
2. What mathematical operations are performed to calculate insights?
3. Find and fix the potential division-by-zero error in the insights generation
4. Add a new insight for gender segmentation: "Income gap between genders: $X"
5. Design three new insights for the cluster segmentation type

**File reference:** `index.php:166-242`

---

### Question 5.3: Advanced Cluster Visualizations

Study the enhanced visualizations for cluster analysis.

**Tasks:**
1. Explain what a radar chart shows and why it's useful for cluster comparison (lines 464-519)
2. The radar chart uses normalization (lines 479-481). Why is this necessary?
3. Describe the dual y-axis implementation in the grouped bar chart (lines 558-580)
4. What does the scatter plot reveal about cluster quality? (lines 584-644)
5. Propose a new visualization type that would help marketers understand cluster differences better

**File reference:** `index.php:449-645`

---

## Part 6: Code Quality and Best Practices

### Question 6.1: Code Review 

Perform a comprehensive code review of the application.

**Tasks:**
1. Identify FIVE violations of the DRY (Don't Repeat Yourself) principle
2. Find THREE examples of "magic numbers" or "magic strings" that should be constants
3. List functions/code blocks that exceed 50 lines - should they be refactored?
4. Assess the consistency of naming conventions (variables, functions, files)
5. Rate the code documentation quality (1-10) and suggest improvements

**Files to examine:** All PHP files

---

### Question 6.2: Error Handling

Evaluate error handling mechanisms throughout the application.

**Tasks:**
1. List all error handling mechanisms currently in use (try-catch, die(), etc.)
2. What happens when:
   - Database connection fails?
   - A required table doesn't exist?
   - Clustering script times out?
   - User submits form without selecting a segmentation type?
3. Design a comprehensive error handling strategy with user-friendly error messages
4. Implement proper logging for debugging production issues

**Files to examine:** `db.php`, `run_clustering.php`, `index.php`

---

### Question 6.3: Scalability Analysis 

Assess the application's ability to handle growth.

**Tasks:**
1. What would happen with 1 million customer records? Identify bottlenecks.
2. The clustering script has `set_time_limit(0)` - is this good practice? Explain.
3. All results are loaded into memory at once. Propose a pagination strategy.
4. Design a caching layer for frequently-requested segmentations
5. Suggest architectural changes needed to:
   - Support multiple concurrent users
   - Enable real-time updates
   - Distribute processing across multiple servers

**File reference:** `run_clustering.php:18-19`, `index.php:64`

---

## Part 7: Feature Enhancement

### Question 7.1: Export Functionality 

Design and implement a feature to export segmentation results.

**Requirements:**
- Support CSV, PDF, and Excel formats
- Include charts as images in PDF/Excel exports
- Allow filtering of columns to export
- Add export history tracking

**Tasks:**
1. Design the database schema changes needed (if any)
2. Write the SQL queries to retrieve export data
3. Create a UI mockup showing where the export button would appear
4. Write pseudocode for the CSV export function
5. List the PHP libraries you'd need for PDF/Excel generation

---

### Question 7.2: Advanced Segmentation 

Propose and design a new segmentation type: "Customer Lifetime Value (CLV) Tiers"

**Business Rule:** CLV = (Average Purchase Amount × Purchase Frequency × Customer Lifespan)

**Tasks:**
1. What additional database columns would be needed?
2. Design the SQL query to calculate CLV tiers (Bronze, Silver, Gold, Platinum)
3. Write the PHP case statement to handle this new segmentation type
4. Create the JavaScript insights for CLV segmentation
5. What chart type would best visualize CLV distribution? Justify your choice.

---

### Question 7.3: API Development 

Design a RESTful API to expose segmentation data to external applications.

**Tasks:**
1. Design at least 5 API endpoints with HTTP methods (GET, POST, etc.)
2. Define the JSON response format for the `/api/segments/cluster` endpoint
3. Implement authentication for the API (propose a method)
4. Write pseudocode for rate limiting (max 100 requests per hour per user)
5. Document one complete API endpoint using OpenAPI/Swagger format

**Example endpoints:**
- GET /api/segments/{type}
- GET /api/clusters
- POST /api/clusters/run
- GET /api/customers/{id}/segment
- GET /api/insights/{type}

---

## Part 8: Testing and Quality Assurance

### Question 8.1: Unit Testing Strategy 

Design a unit testing strategy for the k-means clustering algorithm.

**Tasks:**
1. Identify 5 critical functions that need unit tests
2. Write test cases for `normalizeData()` function:
   - Test with normal data
   - Test with zero standard deviation
   - Test with negative values
   - Test with empty array
3. Write test cases for `euclideanDistance()` function
4. How would you test the randomness in k-means++ initialization?
5. Propose a framework (PHPUnit, etc.) and justify your choice

**File reference:** `run_clustering.php`

---

### Question 8.2: Integration Testing 

Design integration tests for the segmentation workflow.

**Tasks:**
1. Write test scenarios for the complete login → segment → logout flow
2. Create test data requirements (how many customers, what distributions)
3. Design tests for the cluster segmentation with metadata visualization
4. How would you test that charts are rendering correctly?
5. Propose automated testing tools for this PHP application

---

### Question 8.3: User Acceptance Testing 

Create a UAT plan for business users.

**Tasks:**
1. Define 5 user personas who would use this dashboard
2. Create test scenarios for each persona
3. Design a feedback collection mechanism
4. What metrics would you track to measure success?
5. Create a UAT checklist covering all features

---

## Part 9: Performance Optimization

### Question 9.1: Database Optimization 

**Scenario:** The dashboard is slow with 500,000+ customer records.

**Tasks:**
1. Run EXPLAIN on all segmentation queries - which ones need optimization?
2. Design optimal indexes for the `customers` table
3. Propose a partitioning strategy for the `customers` table
4. Would database views help? Design one for the most common query.
5. Compare MySQL vs PostgreSQL for this use case - which is better and why?

---

### Question 9.2: Frontend Performance 

Optimize the client-side performance.

**Tasks:**
1. The dashboard loads Chart.js from CDN. What are pros and cons?
2. How many HTTP requests are made to load the page? How can this be reduced?
3. Propose lazy loading for charts (only render when scrolled into view)
4. Suggest browser caching strategies for static assets
5. How would you implement Progressive Web App (PWA) features?

---

### Question 9.3: Code Profiling 

**Tasks:**
1. Which PHP function would you use to measure execution time?
2. Profile the clustering script - which function takes the most time?
3. How would you identify memory leaks in long-running PHP scripts?
4. Propose monitoring tools to track application performance in production
5. Design a performance dashboard showing key metrics

---

## Part 10: Business Intelligence and Strategy

### Question 10.1: Marketing Campaign Design 

Using the cluster analysis results, design targeted marketing campaigns.

**Scenario:** The clustering identified these 5 segments:
1. High-Income Young Premium (500 customers, avg income $75k, avg purchase $4k)
2. Budget Young Conservative (1200 customers, avg income $28k, avg purchase $800)
3. Mid-Tier Middle-Aged Moderate (2000 customers, avg income $52k, avg purchase $2.2k)
4. Affluent Mature Active (800 customers, avg income $68k, avg purchase $3.5k)
5. Budget Senior Conservative (400 customers, avg income $35k, avg purchase $1k)

**Tasks:**
1. For each segment, design a specific marketing message and channel
2. Allocate a $100,000 marketing budget across the 5 segments - justify your allocation
3. What products would you promote to each segment?
4. Design an email template for Segment #3
5. Propose success metrics (KPIs) to measure campaign effectiveness

---

### Question 10.2: Dashboard Enhancement for Executives 

**Scenario:** The CEO wants a high-level executive summary view.

**Tasks:**
1. Design a new dashboard page showing only the most critical 5 metrics
2. Propose visualizations for:
   - Revenue by segment over time
   - Customer acquisition cost by segment
   - Segment migration (customers moving between segments)
3. Add predictive analytics - what would you forecast?
4. Design alert notifications for anomalies (e.g., sudden drop in high-value segment)
5. Create a mockup/wireframe of the executive dashboard

---

### Question 10.3: Competitive Analysis 

Compare this application to commercial customer segmentation tools.

**Tasks:**
1. Research 3 commercial tools (e.g., Salesforce, HubSpot, Segment)
2. Create a feature comparison matrix
3. What features do commercial tools have that this app lacks?
4. What are the advantages of this custom-built solution?
5. Estimate the ROI: custom solution vs buying commercial software

---

## Submission Guidelines

### Deliverables

Students should submit:

1. **Written Report** (PDF format)
   - Answer all questions with clear explanations
   - Include code snippets, SQL queries, and diagrams where requested
   - 

2. **Code Implementations** 
   - Any code you write for enhancement questions (Part 7)
   - Unit tests (Part 8.1)
   - Modified/improved versions of existing files

3. **Diagrams and Visualizations**
   - ERD diagram (Question 1.2)
   - Architecture diagrams (Questions 1.3, 6.3)
   - UI mockups (Questions 7.1, 10.2)
   - Venn diagrams, flowcharts as requested

4. **Presentation** 
   - 10-15 slide deck summarizing key findings
   - Focus on security vulnerabilities found and business insights
  

### Recommended Reading

- **PHP Security**: OWASP Top 10 Web Application Security Risks
- **SQL**: MySQL Performance Optimization Guide
- **Algorithms**: "Introduction to Algorithms" - K-Means chapter
- **Data Viz**: Chart.js official documentation
- **Business**: "Competing on Analytics" by Davenport & Harris

### Tools to Install

- XAMPP (provided)
- MySQL Workbench (for ERD design)
- Postman (for API testing in Part 7)
- PHPUnit (for unit testing in Part 8)
- Git (for version control)

### Sample Data

Students should use the existing customer data in the database. If you need to generate additional test data:

```sql
-- Generate 1000 random customers for scalability testing
INSERT INTO customers (age, gender, income, purchase_amount, region)
SELECT
    FLOOR(18 + RAND() * 65) AS age,
    IF(RAND() > 0.5, 'Male', 'Female') AS gender,
    FLOOR(20000 + RAND() * 100000) AS income,
    FLOOR(500 + RAND() * 5000) AS purchase_amount,
    ELT(FLOOR(1 + RAND() * 5), 'North', 'South', 'East', 'West', 'Central') AS region
FROM
    (SELECT 1 UNION SELECT 2 UNION SELECT 3 UNION SELECT 4 UNION SELECT 5) t1,
    (SELECT 1 UNION SELECT 2 UNION SELECT 3 UNION SELECT 4 UNION SELECT 5) t2,
    (SELECT 1 UNION SELECT 2 UNION SELECT 3 UNION SELECT 4 UNION SELECT 5) t3,
    (SELECT 1 UNION SELECT 2 UNION SELECT 3 UNION SELECT 4 UNION SELECT 5) t4;
```

