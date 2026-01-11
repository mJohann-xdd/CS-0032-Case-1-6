<?php
session_start();
require_once 'db.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username']);
    $password = $_POST['password'];
    
    try {
        // Fetch user from database
        $stmt = $pdo->prepare("SELECT user_id, username, password_hash, role, failed_attempts, lockout_until FROM users WHERE username = :username");
        $stmt->execute(['username' => $username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($user) {
            // Check if account is locked
            if ($user['lockout_until'] && strtotime($user['lockout_until']) > time()) {
                $lockout_time = date('Y-m-d H:i:s', strtotime($user['lockout_until']));
                $error_message = "Account is locked due to multiple failed attempts. Try again after $lockout_time.";
            } 
            // Verify password
            else if (password_verify($password, $user['password_hash'])) {
                // Reset failed attempts on successful login
                $stmt = $pdo->prepare("UPDATE users SET failed_attempts = 0, lockout_until = NULL, last_login = NOW() WHERE user_id = :user_id");
                $stmt->execute(['user_id' => $user['user_id']]);
                
                // Set session variables
                $_SESSION['logged_in'] = true;
                $_SESSION['user_id'] = $user['user_id'];
                $_SESSION['username'] = $user['username'];
                $_SESSION['role'] = $user['role'];
                
                header('Location: index.php');
                exit;
            } else {
                // Increment failed attempts
                $failed_attempts = $user['failed_attempts'] + 1;
                $lockout_until = null;
                
                // Lock account after 5 failed attempts for 15 minutes
                if ($failed_attempts >= 5) {
                    $lockout_until = date('Y-m-d H:i:s', strtotime('+15 minutes'));
                    $error_message = "Too many failed attempts. Account locked for 15 minutes.";
                } else {
                    $error_message = "Invalid username or password. Attempt $failed_attempts of 5.";
                }
                
                $stmt = $pdo->prepare("UPDATE users SET failed_attempts = :failed_attempts, lockout_until = :lockout_until WHERE user_id = :user_id");
                $stmt->execute([
                    'failed_attempts' => $failed_attempts,
                    'lockout_until' => $lockout_until,
                    'user_id' => $user['user_id']
                ]);
            }
        } else {
            $error_message = "Invalid username or password.";
        }
    } catch (PDOException $e) {
        $error_message = "Login error. Please try again later.";
        error_log("Login error: " . $e->getMessage());
    }
}

if (!isset($_SESSION['logged_in'])) {
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1 class="text-center mb-4">Login</h1>
        <?php if (isset($error_message)): ?>
            <div class="alert alert-danger"><?= htmlspecialchars($error_message) ?></div>
        <?php endif; ?>
        <form method="POST" class="w-50 mx-auto">
            <div class="mb-3">
                <label for="username" class="form-label">Username</label>
                <input type="text" class="form-control" id="username" name="username" required>
            </div>
            <div class="mb-3">
                <label for="password" class="form-label">Password</label>
                <input type="password" class="form-control" id="password" name="password" required>
            </div>
            <button type="submit" class="btn btn-primary w-100">Login</button>
        </form>
        <p class="text-center mt-3">
            Don't have an account? <a href="register.php">Register here</a>
        </p>
    </div>
</body>
</html>
<?php
} else {
    header('Location: index.php');
    exit;
}


?>

