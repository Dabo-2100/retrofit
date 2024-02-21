<?php
header("Access-Control-Allow-Origin: *"); //To Allow Access From Other Servers
header("Access-Control-Allow-Methods: POST"); //To Allow POST 
header("Access-Control-Allow-Headers: Content-Type, Authorization");
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $Post_object = file_get_contents('php://input');
    $POST_data = json_decode($Post_object, true);
    $api_name = @$POST_data["api_name"];
} else {
    $api_name = @$_GET["api_name"];
}

if ($api_name == "GetData") {
    $Url = "https://www.zohoapis.com/crm/v2/functions/Dabo_Test/actions/execute?auth_type=apikey&zapikey=1003.6f48757796b7b7657ba3026676537e65.ef98a62d5eba8fd19d777611abef025b";
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $Url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
    $response = curl_exec($ch);
    $response = json_decode($response, true);
    $final = $response['details']['userMessage'][0];
    echo "[" . $final . "]";
}

if ($api_name == "GetSBPart_Tasks") {
    $SB_Part_ID = htmlspecialchars(@$POST_data["SB_Part_ID"]);
    $Url = "https://www.zohoapis.com/crm/v2/functions/editsbtasks/actions/execute?auth_type=apikey&zapikey=1003.6f48757796b7b7657ba3026676537e65.ef98a62d5eba8fd19d777611abef025b&requestBody=" . $SB_Part_ID;
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $Url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $Url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
    $response = curl_exec($ch);
    $response = json_decode($response, true);
    $final = $response['details']['userMessage'][0];
    echo "[" . $final . "]";
}

if ($api_name == "GetAllSBsAndParts") {
    $Url = "https://www.zohoapis.com/crm/v2/functions/api_getallsbs/actions/execute?auth_type=apikey&zapikey=1003.6f48757796b7b7657ba3026676537e65.ef98a62d5eba8fd19d777611abef025b";
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $Url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $Url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
    $response = curl_exec($ch);
    $response = json_decode($response, true);
    $final = $response['details']['userMessage'][0];
    echo "[" . $final . "]";
}

// encodeURIComponent js function to encode url