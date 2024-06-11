<?php
// require __DIR__ . '/vendor/autoload.php'; // Include Composer's autoloader
require_once './vendor/autoload.php';
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

function createToken($payload)
{
    $key = 'Dabo2100@IPACO';
    $token = JWT::encode($payload, $key, 'HS256');
    return $token;
}

function checkToken($token)
{
    $key = 'Dabo2100@IPACO';
    try {
        $decoded = JWT::decode($token, new Key($key, 'HS256'));
        return json_encode((array) $decoded);
    } catch (Exception $e) {
        return false;
    }
}

