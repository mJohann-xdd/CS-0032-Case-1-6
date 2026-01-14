<?php
// Secure session configuration
function configure_secure_session() {
    $is_https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
                || $_SERVER['SERVER_PORT'] == 443;
    
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
session_destroy();
echo json_encode(['success' => true]);
?>