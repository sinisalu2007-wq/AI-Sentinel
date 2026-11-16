<?php
session_start();
if (!isset($_SESSION['loggedin'])) exit("Unauthorized");

if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['ip_to_block'])) {
    $ip = $_POST['ip_to_block'];
    
    // Security check: validate it's an IP address
    if (filter_var($ip, FILTER_VALIDATE_IP)) {
        $safe_ip = escapeshellarg($ip);
        
        // Execute the python blocking script
        // We use sudo because iptables requires root permissions
        shell_exec("sudo python3 ../src/block_ip.py $safe_ip");
        
        // Redirect back with a success flag
        header("Location: index.php?blocked=" . urlencode($ip));
        exit;
    }
}
header("Location: index.php");