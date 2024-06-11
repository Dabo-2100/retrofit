<?php
// $endpoints = [
//     // Auth
//     '/api/auth/check' => 'check_auth',
//     '/api/auth/login' => 'auth_login',
//     '/api/auth/activate' => 'user_activate',
//     '/api/auth/resendcode' => 'resend_code',
//     // Users
//     '/api/users/authority' => 'get_apps',
//     '/api/users' => 'users_read',
//     '/api/users/store' => 'users_store',
//     // Retrofit
//     '/api/sbs' => 'index_sbs',
//     '/api/sbs/\d+' => 'sb_details',
//     '/api/sb_parts' => 'index_sb_parts',
//     '/api/sb_parts/\d+' => 'sb_parts_details',
//     '/api/applicability/\d+' => 'applicability_details',
//     // Aircrafts
//     '/api/aircrafts' => 'index_aircrafts',
//     '/api/aircrafts/\d+' => 'aircrafts_details',
//     // Projects
//     '/api/projects' => 'index_projects',
//     '/api/projects/\d+' => 'project_details',
//     '/api/projects/store' => 'store_project',
//     '/api/projects/delete' => 'delete_project',
//     // Forms
//     '/api/forms/\d+/logs' => 'form_logs',
//     '/api/forms/\d+' => 'index_forms',
//     '/api/aircrafts/\d+/forms' => 'aircraft_forms',
//     // Warehouse
//     '/api/warehouse/products' => 'search_products',
//     '/api/warehouse/products/store' => 'store_product',
//     '/api/warehouse/products/qty/\d+' => 'detailed_qty',
//     '/api/warehouse/units/\d+' => 'index_units',
//     // Connectors
//     '/api/connectors' => 'index_connectors',
//     '/api/connectors/search' => 'search_connectors',
//     '/api/aircrafts/\d+/connectors' => 'aircraft_connectors',
//     '/api/aircrafts/\d+/connectors/store' => 'store_aircraft_connector',
//     // File Uploader
//     '/upload/files/items' => 'upload_items',
// ];
if (array_key_exists('PATH_INFO', $_SERVER)) {
    $requestUri = $_SERVER['PATH_INFO'];
} else {
    echo "Error : 403 | Forbidden";
    http_response_code(403);
    exit();
}

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
