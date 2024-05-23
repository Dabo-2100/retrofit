<?php

$endpoints = [
    '/api/auth/check' => 'check_auth',
    '/api/auth/login' => 'auth_login',
    '/api/auth/activate' => 'user_activate',
    '/api/auth/resendcode' => 'resend_code',
    '/api/users/authority' => 'get_apps',
    '/api/users' => 'users_read',
    '/api/users/store' => 'users_store',
    '/api/update' => 'update_data',
    '/api/insert' => 'insert_data',
    '/api/sbs' => 'index_sbs',
    '/api/sbs/\d+' => 'sb_details',
    '/api/sb_parts' => 'index_sb_parts',
    '/api/sb_parts/\d+' => 'sb_parts_details',
    '/api/aircrafts' => 'index_aircrafts',
    '/api/aircrafts/\d+' => 'aircrafts_details',
    '/api/aircrafts/\d+/forms' => 'aircraft_forms',
    '/api/forms/\d+/logs' => 'form_logs',
    '/api/forms/\d+' => 'index_forms',
    '/api/applicability/\d+' => 'applicability_details',
    '/api/warehouse/products' => 'search_products',
    '/api/warehouse/products/store' => 'store_product',
    '/api/warehouse/products/qty/\d+' => 'detailed_qty',
    '/api/warehouse/products/store' => 'store_product',
    '/api/warehouse/units/\d+' => 'index_units',
    '/api/connectors/search' => 'search_connectors',
    '/upload/files/items' => 'upload_items',
];

$match = 0;
foreach ($endpoints as $pattern => $function) {
    $regex = preg_replace('~\{(\w+)\}~', '(?P<$1>[^/]+)', $pattern);
    $regex = str_replace('/', '\/', $regex);
    $regex = "/^$regex$/";
    if (preg_match($regex, $requestUri, $matches)) {
        if (function_exists($function)) {
            $match = 1;
            $function($matches);
        }
    }
}

if ($match == 0) {
    echo "Error : 404 | Not Found";
    http_response_code(404);
    exit();
}
