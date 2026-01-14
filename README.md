
# Customer Segmentation Dashboard - Case Study

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

**Good luck, and happy coding!**
