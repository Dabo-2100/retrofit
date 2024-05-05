<?php
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST");
header("Access-Control-Allow-Headers: Content-Type, Authorization");
header("Access-Control-Allow-Credentials: true");
$method = $_SERVER['REQUEST_METHOD'];

if ($method === 'POST') {
    $Post_object = file_get_contents('php://input');
    $POST_data = json_decode($Post_object, true);
    $api_name = @$POST_data["api_name"];
}

if ($api_name == "GetData") {
    $SB_ID = htmlspecialchars(@$POST_data["sb_id"]);
    $Url = "https://www.zohoapis.com/crm/v2/functions/Dabo_Test/actions/execute?auth_type=apikey&zapikey=1003.6f48757796b7b7657ba3026676537e65.ef98a62d5eba8fd19d777611abef025b&SB_ID=" . $SB_ID;
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $Url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
    $response = curl_exec($ch);
    $response = json_decode($response, true);
    print_r($response);
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

if ($api_name == "getAllZoneTasks") {
    $zone_id = htmlspecialchars(@$POST_data["zone_id"]);
    $Url = "https://www.zohoapis.com/crm/v2/functions/api_zone_task/actions/execute?auth_type=apikey&zapikey=1003.6f48757796b7b7657ba3026676537e65.ef98a62d5eba8fd19d777611abef025b&zone_id=" . $zone_id;
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

if ($api_name == "getConnectors") {
    $Url = "https://www.zohoapis.com/crm/v2/functions/connectors_data/actions/execute?auth_type=apikey&zapikey=1003.6f48757796b7b7657ba3026676537e65.ef98a62d5eba8fd19d777611abef025b";
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

if ($api_name == "getConnectorDetails") {
    $connector_id = htmlspecialchars(@$POST_data["connector_id"]);
    $Url = "https://www.zohoapis.com/crm/v2/functions/getconnectordata/actions/execute?auth_type=apikey&zapikey=1003.6f48757796b7b7657ba3026676537e65.ef98a62d5eba8fd19d777611abef025b&connector_id=" . $connector_id;
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

if ($api_name == "getReportData") {
    $report_name = htmlspecialchars(@$POST_data["report_name"]);
    $Url = "https://www.zohoapis.com/crm/v2/functions/getreport/actions/execute?auth_type=apikey&zapikey=1003.6f48757796b7b7657ba3026676537e65.ef98a62d5eba8fd19d777611abef025b&report_name=" . $report_name;
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
    // echo $response;
    $final = $response['details']['userMessage'][0];
    echo "[" . $final . "]";
}

if ($api_name == "getProjectPlan") {
    $aircraft_id = htmlspecialchars(@$POST_data["aircraft_id"]);
    $Url = "https://www.zohoapis.com/crm/v2/functions/makeproject/actions/execute?auth_type=apikey&zapikey=1003.6f48757796b7b7657ba3026676537e65.ef98a62d5eba8fd19d777611abef025b&connector_id=" . $aircraft_id;
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
    // print_r($response);
    $final = $response['details']['output'];
    echo "[" . $final . "]";
}

if ($api_name == "getPartsOnAircraft") {
    $aircraft_id = htmlspecialchars(@$POST_data["aircraft_id"]);
    $step = htmlspecialchars(@$POST_data["step"]);
    $Url = "https://www.zohoapis.com/crm/v2/functions/makeproject2/actions/execute?auth_type=apikey&zapikey=1003.6f48757796b7b7657ba3026676537e65.ef98a62d5eba8fd19d777611abef025b&aircraft_id=$aircraft_id&step=$step&sb_part_id=0";
    echo $Url;
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
    print_r($response);
    $final = $response['details']['output'];
    echo "[" . $final . "]";
}

if ($api_name == "getSbPartData") {
    $sb_part_id = htmlspecialchars(@$POST_data["sb_part_id"]);
    $step = htmlspecialchars(@$POST_data["step"]);
    $Url = "https://www.zohoapis.com/crm/v2/functions/makeproject2/actions/execute?auth_type=apikey&zapikey=1003.6f48757796b7b7657ba3026676537e65.ef98a62d5eba8fd19d777611abef025b&aircraft_id=0&step=$step&sb_part_id=$sb_part_id";
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
    // print_r($response);
    $final = $response['details']['output'];
    echo "[" . $final . "]";
}

if ($api_name == "getPartDetials") {
    $SB_Part_id = htmlspecialchars(@$POST_data["SB_Part_id"]);
    $step = htmlspecialchars(@$POST_data["step"]);
    $aircraft_id = htmlspecialchars(@$POST_data["aircraft_id"]);
    $Url = "https://www.zohoapis.com/crm/v2/functions/plantest/actions/execute?auth_type=apikey&zapikey=1003.6f48757796b7b7657ba3026676537e65.ef98a62d5eba8fd19d777611abef025b&SB_Part_id=$SB_Part_id&step=$step&aircraft_id=$aircraft_id";
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
    $final = $response['details']['output'];
    echo "[" . $final . "]";
}


if ($api_name == "sendData") {
    $task_id = htmlspecialchars(@$POST_data["task_id"]);
    $new_name = htmlspecialchars(@$POST_data["new_name"]);
    $Url = "https://www.zohoapis.com/crm/v2/functions/inserttaskintosb/actions/execute?auth_type=apikey&zapikey=1003.6f48757796b7b7657ba3026676537e65.ef98a62d5eba8fd19d777611abef025b&task_id=$task_id&new_name=$new_name";
    echo $Url;
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
    // print_r($response);
    $final = $response['details']['output'];
    echo "[" . $final . "]";
}

// encodeURIComponent js function to encode url



if ($api_name == "getData") {
    $Url = "https://www.zohoapis.com/crm/v2/functions/get_data/actions/execute?auth_type=apikey&zapikey=1003.6f48757796b7b7657ba3026676537e65.ef98a62d5eba8fd19d777611abef025b";
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $Url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
    $response = curl_exec($ch);
    $response = json_decode($response, true);
    // print_r($response);
    $final = $response['details']['output'];
    echo "[" . $final . "]";
}
