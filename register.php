<?php
session_start();
require_once 'db.php';

$success_message = '';
$error_message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username']);
    $email = trim($_POST['email']);
    $password = $_POST['password'];
    $confirm_password = $_POST['confirm_password'];
    
    // Validation
    if (empty($username) || empty($email) || empty($password)) {
        $error_message = "All fields are required.";
    } else if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error_message = "Invalid email format.";
    } else if (strlen($password) < 8) {
        $error_message = "Password must be at least 8 characters long.";
    } else if ($password !== $confirm_password) {
        $error_message = "Passwords do not match.";
    } else {
        try {
            // Check if username already exists
            $stmt = $pdo->prepare("SELECT user_id FROM users WHERE username = :username");
            $stmt->execute(['username' => $username]);
            if ($stmt->fetch()) {
                $error_message = "Username already exists.";
            } else {
                // Check if email already exists
                $stmt = $pdo->prepare("SELECT user_id FROM users WHERE email = :email");
                $stmt->execute(['email' => $email]);
                if ($stmt->fetch()) {
                    $error_message = "Email already exists.";
                } else {
                    // Hash password and insert user
                    $password_hash = password_hash($password, PASSWORD_DEFAULT);
                    
                    $stmt = $pdo->prepare("INSERT INTO users (username, password_hash, email, role) VALUES (:username, :password_hash, :email, 'user')");
                    $stmt->execute([
                        'username' => $username,
                        'password_hash' => $password_hash,
                        'email' => $email
                    ]);
                    
                    $success_message = "Registration successful! You can now <a href='login.php'>login</a>.";
                    
                    // Clear form
                    $_POST = [];
                }
            }
        } catch (PDOException $e) {
            $error_message = "Registration error. Please try again later.";
            error_log("Registration error: " . $e->getMessage());
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1 class="text-center mb-4">Register</h1>
        
        <?php if ($error_message): ?>
            <div class="alert alert-danger"><?= htmlspecialchars($error_message) ?></div>
        <?php endif; ?>
        
        <?php if ($success_message): ?>
            <div class="alert alert-success"><?= $success_message ?></div>
        <?php endif; ?>
        
        <form method="POST" class="w-50 mx-auto">
            <div class="mb-3">
                <label for="username" class="form-label">Username</label>
                <input type="text" class="form-control" id="username" name="username" 
                       value="<?= htmlspecialchars($_POST['username'] ?? '') ?>" required>
            </div>
            <div class="mb-3">
                <label for="email" class="form-label">Email</label>
                <input type="email" class="form-control" id="email" name="email" 
                       value="<?= htmlspecialchars($_POST['email'] ?? '') ?>" required>
            </div>
            <div class="mb-3">
                <label for="password" class="form-label">Password</label>
                <input type="password" class="form-control" id="password" name="password" required>
                <small class="form-text text-muted">At least 8 characters</small>
            </div>
            <div class="mb-3">
                <label for="confirm_password" class="form-label">Confirm Password</label>
                <input type="password" class="form-control" id="confirm_password" name="confirm_password" required>
            </div>
            <button type="submit" class="btn btn-primary w-100">Register</button>
        </form>
        
        <p class="text-center mt-3">
            Already have an account? <a href="login.php">Login here</a>
        </p>
    </div>
</body>
</html>
