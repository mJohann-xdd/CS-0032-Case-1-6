<?php
// Database credentials
$host = 'localhost';
$dbname = 'customer_segmentation_ph';
$username = 'root'; // Replace with your MySQL username
$password = '';     // Replace with your MySQL password

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname;charset=utf8", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Database connection failed: " . $e->getMessage());
}
?>