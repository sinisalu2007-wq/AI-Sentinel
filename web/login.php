<?php
session_start();
// Set your admin credentials here
$admin_user = "admin";
$admin_pass = "Sentinel2026"; 

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    if ($_POST['username'] == $admin_user && $_POST['password'] == $admin_pass) {
        $_SESSION['loggedin'] = true;
        header("Location: index.php");
        exit;
    } else {
        $error = "Invalid Credentials!";
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>AI-Sentinel Login</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
</head>
<body class="bg-dark text-white d-flex align-items-center vh-100">
    <div class="container col-md-4">
        <div class="card bg-secondary p-4 shadow">
            <h2 class="text-center">🛡️ Admin Login</h2>
            <form method="POST">
                <input type="text" name="username" class="form-control mb-3" placeholder="Username" required>
                <input type="password" name="password" class="form-control mb-3" placeholder="Password" required>
                <button type="submit" class="btn btn-primary w-100">Access Dashboard</button>
                <?php if(isset($error)) echo "<p class='text-danger mt-2'>$error</p>"; ?>
            </form>
        </div>
    </div>
</body>
</html>