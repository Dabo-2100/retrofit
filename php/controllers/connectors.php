<?php
// Routes
$endpoints += [
    '/api/aircrafts/\d+/connectors' => 'aircraft_connectors',
    '/api/aircrafts/\d+/connectors/store' => 'store_aircraft_connector',
    '/api/connectors' => 'index_connectors',
    '/api/connectors/search' => 'search_connectors',
];

function aircraft_connectors($id)
{
    $aircraft_id = explode("/connectors", explode("/api/aircrafts/", $id[0])[1])[0];
    global $method, $pdo, $response, $POST_data;
    if ($method === "POST") {
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $headerParts = explode(' ', $_SERVER['HTTP_AUTHORIZATION']);
            if (count($headerParts) == 2 && $headerParts[0] == 'Bearer') {
                $accessToken = $headerParts[1];
                $user_info = json_decode(checkToken($accessToken), true);
                if ($user_info) {
                    try {
                        $Filter = '';
                        $is_open_arr = @$POST_data['is_open'];
                        $is_installed_arr = @$POST_data['is_insalled'];

                        if (isset($is_open_arr)) {
                            $f1 = '';
                            foreach ($is_open_arr as $index => $value) {
                                if ($index == 0 && $value != 'not') {
                                    $f1 .= 'aircraft_id = ' . $aircraft_id . ' and is_open = ' . $value . ' ';
                                } else if ($index != 0 && $value != 'not') {
                                    if ($is_open_arr[$index - 1] == 'not') {
                                        $f1 .= 'aircraft_id = ' . $aircraft_id . ' and is_open = ' . $value . ' ';
                                    } else {
                                        $f1 .= 'or aircraft_id = ' . $aircraft_id  . ' and is_open = ' . $value . ' ';
                                    }
                                }
                            }
                            $Filter .= $f1;
                        }

                        if (isset($is_installed_arr)) {
                            $f2 = '';
                            foreach ($is_installed_arr as $index => $value) {
                                if ($value != 'not') {
                                    if ($Filter == "" && $f2 == "") {
                                        $f2 .= 'aircraft_id = ' . $aircraft_id . ' and is_orignal = ' . $value . ' ';
                                    } else {
                                        $f2 .= 'or aircraft_id = ' . $aircraft_id . ' and is_orignal = ' . $value . ' ';
                                    }
                                }
                            }
                            $Filter .= $f2;
                        }

                        if ($Filter == '') {
                            $sql = "SELECT * FROM connectors_vs_aircrafts WHERE aircraft_id = $aircraft_id ";
                        } else {
                            $sql = "SELECT * FROM connectors_vs_aircrafts WHERE $Filter";
                        }

                        $statement = $pdo->prepare($sql);
                        $statement->execute();
                        $data = [];
                        if ($statement->rowCount() > 0) {
                            while ($SB = $statement->fetch(PDO::FETCH_ASSOC)) {
                                $SB['connector_name'] = getOneField("app_connectors", "connector_name", "connector_id = " . $SB['connector_id']);

                                array_push($data, $SB);
                            }
                            $response['err'] = false;
                            // $response['msg'] = "All Connectors are ready to view !";
                            $response['msg'] = $Filter;
                            $response['data'] = $data;
                        } else {
                            $response['msg'] = "There is are Connectors Found !";
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

function store_aircraft_connector($id)
{
    $aircraft_id = explode("/connectors", explode("/api/aircrafts/", $id[0])[1])[0];
    global $method, $pdo, $response, $POST_data;
    if ($method === "POST") {
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $headerParts = explode(' ', $_SERVER['HTTP_AUTHORIZATION']);
            if (count($headerParts) == 2 && $headerParts[0] == 'Bearer') {
                $accessToken = $headerParts[1];
                $user_info = json_decode(checkToken($accessToken), true);
                if ($user_info) {
                    try {
                        $sql = $sql = " INSERT INTO connectors_vs_aircrafts
                            (aircraft_id , connector_id , is_open , is_orignal ) VALUES
                            (:aircraft_id , :connector_id , FALSE , NULL)
                        ";
                        $statement = $pdo->prepare($sql);
                        $statement->bindParam(':aircraft_id', $aircraft_id);
                        $statement->bindParam(':connector_id', $POST_data['connector_id']);
                        $statement->execute();
                        $data = [];
                        $response['err'] = false;
                        $response['msg'] = "Connector Added to aircraft successfuly !";
                        $response['data'] = $data;
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

function index_connectors()
{
    global $method, $pdo, $response;
    if ($method === "GET") {
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $headerParts = explode(' ', $_SERVER['HTTP_AUTHORIZATION']);
            if (count($headerParts) == 2 && $headerParts[0] == 'Bearer') {
                $accessToken = $headerParts[1];
                $user_info = json_decode(checkToken($accessToken), true);
                if ($user_info) {
                    try {
                        $sql = "SELECT * FROM app_connectors";
                        $statement = $pdo->prepare($sql);
                        $statement->execute();
                        $data = [];
                        if ($statement->rowCount() > 0) {
                            while ($SB = $statement->fetch(PDO::FETCH_ASSOC)) {
                                array_push($data, $SB);
                            }
                            $response['err'] = false;
                            $response['msg'] = "All Connectors are ready to view !";
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

function search_connectors()
{
    global $method;
    global $POST_data;
    global $pdo;
    global $response;
    if ($method === "POST") {
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $headerParts = explode(' ', $_SERVER['HTTP_AUTHORIZATION']);
            if (count($headerParts) == 2 && $headerParts[0] == 'Bearer') {
                $accessToken = $headerParts[1];
                $user_info = json_decode(checkToken($accessToken), true);
                if ($user_info) {
                    try {
                        $sql = "SELECT * FROM app_connectors WHERE (connector_name LIKE '%" . $POST_data['connector_name'] . "%')";
                        $statement = $pdo->prepare($sql);
                        $statement->execute();
                        $data = [];
                        if ($statement->rowCount() > 0) {
                            while ($Item = $statement->fetch(PDO::FETCH_ASSOC)) {
                                if (isset($POST_data['aircraft_id'])) {
                                    $Item['is_active'] = getOneField("connectors_vs_aircrafts", "log_id", "connector_id = " . $Item['connector_id']);
                                    if ($Item['is_active']) {
                                        $Item['is_open'] = getOneField("connectors_vs_aircrafts", "is_open", "connector_id = " . $Item['connector_id']);
                                        $Item['is_orignal'] = getOneField("connectors_vs_aircrafts", "is_orignal", "connector_id = " . $Item['connector_id']);
                                    }
                                } else {
                                    $Item['type_name'] = getOneField("connector_types", "type_name", "type_id = " . $Item['type_id']);
                                    $Item['sb_tasks'] = getRows("connectors_vs_tasks", "connector_id = " . $Item['connector_id']);
                                    $sb_tasks  = array_map(function ($task) {
                                        $task['task_name'] = getOneField("sb_tasks", "sb_task_name", "task_id = " . $task['task_id']);
                                        $sb_id = getOneField("sb_tasks", "sb_id", "task_id = " . $task['task_id']);
                                        $sb_part_id = getOneField("sb_tasks", "sb_part_id", "task_id = " . $task['task_id']);
                                        $task_type_id = getOneField("sb_tasks", "task_type_id", "task_id = " . $task['task_id']);
                                        $sb_no = getOneField("sbs", "sb_no", "sb_id = " . $sb_id);
                                        $part_name = getOneField("sb_parts", "part_name", "part_id = " . $sb_part_id);
                                        $task_type_name = getOneField("task_types_zoho", "`Task Type Name`", "task_type_id = " . $task_type_id);
                                        $task['sb_id'] = $sb_id;
                                        $task['sb_no'] = $sb_no;
                                        $task['sb_part_id'] = $sb_part_id;
                                        $task['part_name'] = $part_name;
                                        $task['task_type_name'] = $task_type_name;
                                        return $task;
                                    }, $Item['sb_tasks']);
                                    $Item['sb_tasks'] = $sb_tasks;
                                }
                                array_push($data, $Item);
                            }
                            $response['msg'] = "All Connectors are ready to view";
                            $response['err'] = false;
                            $response['data'] = $data;
                        } else {
                            $response['msg'] = "There is no Connectors with value";
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
