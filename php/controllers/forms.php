<?php
// Routes
$endpoints += [
    '/api/forms/\d+/logs' => 'form_logs',
    '/api/forms/\d+' => 'index_forms',
    '/api/aircrafts/\d+/forms' => 'aircraft_forms',
];

function form_logs($id)
{
    $form_id = explode("/logs", explode("/api/forms/", $id[0])[1])[0];
    global $method;
    global $pdo;
    global $response;
    if ($method === "GET") {
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $headerParts = explode(' ', $_SERVER['HTTP_AUTHORIZATION']);
            if (count($headerParts) == 2 && $headerParts[0] == 'Bearer') {
                $accessToken = $headerParts[1];
                $user_info = json_decode(checkToken($accessToken), true);
                if ($user_info) {
                    try {
                        $sql = "SELECT form_type_id FROM app_forms WHERE form_id = :form_id";
                        $statement = $pdo->prepare($sql);
                        $statement->bindParam(':form_id', $form_id);
                        $statement->execute();
                        $type_id = 0;
                        if ($statement->rowCount() > 0) {
                            while ($SB = $statement->fetch(PDO::FETCH_ASSOC)) {
                                $type_id = $SB['form_type_id'];
                            }
                        }
                        if ($type_id == 1) {
                            $response = get_1001_logs($form_id);
                        } elseif ($type_id == 2) {
                            $response = get_1002_logs($form_id);
                        }
                    } catch (Exception $e) {
                        $response['msg'] = "An error occurred: " . $e->getMessage();
                    }
                } else {
                    $response['msg'] = "Invaild user token !";
                }
                echo json_encode($response, true);
            } else {
                http_response_code(400);
                echo "Error : 400 | Bad Request";
            }
        } else {
            http_response_code(401); // Unauthorized
            echo "Error : 401 | Unauthorized";
        }
    } else {
        echo 'Method Not Allowed';
    }
}

function aircraft_forms($id)
{
    $aircraft_id = explode("/forms", explode("/api/aircrafts/", $id[0])[1])[0];
    global $method;
    global $pdo;
    if ($method === "GET") {
        $response = [
            'err' => true,
            'msg' => null,
            'data' => null,
        ];
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $headerParts = explode(' ', $_SERVER['HTTP_AUTHORIZATION']);
            if (count($headerParts) == 2 && $headerParts[0] == 'Bearer') {
                $accessToken = $headerParts[1];
                $user_info = json_decode(checkToken($accessToken), true);
                if ($user_info) {
                    try {
                        $sql = "SELECT *, (SELECT type_name FROM form_types WHERE type_id = `app_forms`.`form_type_id`) As type_name 
                        FROM app_forms WHERE aircraft_id = :aircraft_id";
                        $statement = $pdo->prepare($sql);
                        $statement->bindParam(':aircraft_id', $aircraft_id);
                        $statement->execute();
                        $data = [];
                        if ($statement->rowCount() > 0) {
                            while ($SB = $statement->fetch(PDO::FETCH_ASSOC)) {
                                $dataObj = [
                                    "form_id" => $SB['form_id'],
                                    "form_order" => $SB['form_order'],
                                    "type_name" => $SB['type_name'],
                                    "form_date" => $SB['form_date'],
                                    "form_parent_id" => $SB['form_parent_id'],
                                    "form_type_id" => $SB['form_type_id'],
                                    // "total_duration" => $SB['total_duration'],
                                ];
                                array_push($data, $dataObj);
                            }
                            $response['err'] = false;
                            $response['msg'] = "All Forms are ready to view !";
                            $response['data'] = $data;
                        } else {
                            $response['msg'] = "There is are Forms exist !";
                        }
                    } catch (Exception $e) {
                        $response['msg'] = "An error occurred: " . $e->getMessage();
                    }
                } else {
                    $response['msg'] = "Invaild user token !";
                }
                echo json_encode($response, true);
            } else {
                http_response_code(400);
                echo "Error : 400 | Bad Request";
            }
        } else {
            http_response_code(401); // Unauthorized
            echo "Error : 401 | Unauthorized";
        }
    } else {
        echo 'Method Not Allowed';
    }
}

function get_1001_logs($form_id)
{
    global $pdo;
    global $response;
    try {
        $table_name = "logs_1";
        $sql = "SELECT 
        *,
        (SELECT form_order FROM app_forms WHERE form_id = $table_name.`1002_id`) AS control_no,
        (SELECT user_name FROM app_users WHERE user_id =  $table_name.`originator_id`) AS originator_name,
        (SELECT user_name FROM app_users WHERE user_id =  $table_name.`supervisor_id`) As supervisor_name
         FROM $table_name WHERE form_id = :form_id";
        $statement = $pdo->prepare($sql);
        $statement->bindParam(':form_id', $form_id);
        $statement->execute();
        $data = [];
        if ($statement->rowCount() > 0) {
            while ($SB = $statement->fetch(PDO::FETCH_ASSOC)) {
                $dataObj = [
                    "control_no" => $SB['control_no'],
                    "log_id" => $SB['log_id'],
                    "log_date" => $SB['log_date'],
                    "work_required" => $SB['work_required'],
                    "action_taken" => $SB['action_taken'],
                    "originator_id" => $SB['originator_id'],
                    "originator_name" => $SB['originator_name'],
                    "supervisor_id" => $SB['supervisor_id'],
                    "supervisor_name" => $SB['supervisor_name'],
                ];
                array_push($data, $dataObj);
                $response['err'] = false;
                $response['msg'] = "All Logs are ready to view !";
                $response['data'] = $data;
            }
        } else {
            $response['msg'] = "There is no Logs into this form !";
        }
    } catch (Exception $e) {
        $response['msg'] = "An error occurred: " . $e->getMessage();
    }
    return $response;
}

function get_1002_logs($form_id)
{
    global $pdo;
    global $response;
    try {
        $table_name = "logs_2";
        $sql = "SELECT 
        *,
        (SELECT COUNT(*) FROM app_forms WHERE form_parent_id = :form_id ) AS cSheets_no,
        (SELECT form_order FROM app_forms WHERE form_id = $table_name.`parent_form_id`) AS control_no,
        (SELECT form_date FROM app_forms WHERE form_id = $table_name.`parent_form_id`) AS date_1001,
        (SELECT user_name FROM app_users WHERE user_id =  $table_name.`inspector_id`) As inspector_name
         FROM $table_name WHERE parent_form_id = :form_id";
        $statement = $pdo->prepare($sql);
        $statement->bindParam(':form_id', $form_id);
        $statement->execute();
        $data = [];
        if ($statement->rowCount() > 0) {
            while ($SB = $statement->fetch(PDO::FETCH_ASSOC)) {
                $dataObj = [
                    "control_no" => $SB['control_no'],
                    "date_1001" => $SB['date_1001'],
                    "log_id" => $SB['log_id'],
                    "parent_form_id" => $SB['parent_form_id'],
                    "log_start_time" => $SB['log_start_time'],
                    "log_start_Date" => $SB['log_start_Date'],
                    "log_reason" => $SB['log_reason'],
                    "item_desc" => $SB['item_desc'],
                    "item_sn" => $SB['item_sn'],
                    "item_pn" => $SB['item_pn'],
                    "replace_item_desc" => $SB['replace_item_desc'],
                    "replace_item_sn" => $SB['replace_item_sn'],
                    "replace_item_pn" => $SB['replace_item_pn'],
                    "log_comments" => $SB['log_comments'],
                    "inspector_id" => $SB['inspector_id'],
                    "inspector_name" => $SB['inspector_name'],
                    "inspector_name" => $SB['inspector_name'],
                    "insection_date" => $SB['insection_date'],
                    "work_required" => $SB['work_required'],
                    "action_taken" => $SB['action_taken'],
                    "cSheets_no" => $SB['cSheets_no'],
                ];
                array_push($data, $dataObj);
                $response['err'] = false;
                $response['msg'] = "All Logs are ready to view !";
                $response['data'] = $data;
            }
        } else {
            $response['msg'] = "There is no Logs into this form !";
        }
    } catch (Exception $e) {
        $response['msg'] = "An error occurred: " . $e->getMessage();
    }
    return $response;
}
