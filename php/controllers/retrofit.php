<?php
// Routes
$endpoints += [
    '/api/sbs' => 'index_sbs',
    '/api/sbs/\d+' => 'sb_details',
    '/api/sb_parts' => 'index_sb_parts',
    '/api/sb_parts/\d+' => 'sb_parts_details',
    '/api/applicability/\d+' => 'applicability_details',
];

function index_sbs()
{
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
                        $sql = "SELECT * FROM sbs";
                        $statement = $pdo->prepare($sql);
                        $statement->execute();
                        $data = [];
                        if ($statement->rowCount() > 0) {
                            while ($SB = $statement->fetch(PDO::FETCH_ASSOC)) {
                                $dataObj = [
                                    "sb_id" => $SB['sb_id'],
                                    "sb_name" => $SB['sb_name'],
                                    "sb_no" => $SB['sb_no'],
                                    "sb_con_req" => $SB['sb_con_req'],
                                    "sb_date" => $SB['sb_date'],
                                ];
                                array_push($data, $dataObj);
                            }
                            $response['err'] = false;
                            $response['msg'] = "All SBs are ready to view !";
                            $response['data'] = $data;
                        } else {
                            $response['msg'] = "There is no SB exist !";
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

function sb_details($id)
{
    $id = explode("/api/sbs/", $id[0])[1];
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
                        $sql = "SELECT * FROM sbs WHERE sb_id =:sb_id";
                        $statement = $pdo->prepare($sql);
                        $statement->bindParam(':sb_id', $id);
                        $statement->execute();
                        $data = [];
                        if ($statement->rowCount() > 0) {
                            while ($SB = $statement->fetch(PDO::FETCH_ASSOC)) {
                                $sb_id = $SB['sb_id'];
                                $dataObj = [
                                    "sb_id" => $SB['sb_id'],
                                    "sb_name" => $SB['sb_name'],
                                    "sb_no" => $SB['sb_no'],
                                    "sb_con_req" => $SB['sb_con_req'],
                                    "sb_date" => $SB['sb_date'],
                                ];
                                $sql2 = "SELECT * FROM sb_parts WHERE sb_id =:sb_id";
                                $statement2 = $pdo->prepare($sql2);
                                $statement2->bindParam(':sb_id', $sb_id);
                                $statement2->execute();
                                $sb_parts = [];
                                if ($statement2->rowCount() > 0) {
                                    while ($SB = $statement2->fetch(PDO::FETCH_ASSOC)) {
                                        $partObj = [
                                            "part_id" => $SB['part_id'],
                                            "part_name" => $SB['part_name'],
                                            "part_desc" => $SB['part_desc'],
                                        ];
                                        array_push($sb_parts, $partObj);
                                    }
                                }
                                $dataObj['sb_parts'] = $sb_parts;
                                array_push($data, $dataObj);
                            }
                            $response['err'] = false;
                            $response['msg'] = "All SBs are ready to view !";
                            $response['data'] = $data;
                        } else {
                            $response['msg'] = "There is no SB exist !";
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

function index_sb_parts()
{
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
                        $sql = "SELECT `sb_parts`.*, sbs.sb_no,
                        (SELECT COUNT(*) FROM sb_tasks WHERE sb_tasks.sb_part_id = sb_parts.part_id) AS task_count
                        FROM `sb_parts` JOIN sbs ON sb_parts.sb_id = sbs.sb_id ORDER BY `sb_parts`.`part_name` ASC";
                        $statement = $pdo->prepare($sql);
                        $statement->execute();
                        $data = [];
                        if ($statement->rowCount() > 0) {
                            while ($SB = $statement->fetch(PDO::FETCH_ASSOC)) {
                                $dataObj = [
                                    "part_id" => $SB['part_name'],
                                    "part_name" => $SB['part_name'],
                                    "part_desc" => $SB['part_desc'],
                                    "sb_id" => $SB['sb_id'],
                                    "sb_no" => $SB['sb_no'],
                                    "task_count" => $SB['task_count']
                                ];
                                array_push($data, $dataObj);
                            }
                            $response['err'] = false;
                            $response['msg'] = "All SB_Parts are ready to view !";
                            $response['data'] = $data;
                        } else {
                            $response['msg'] = "There is no SB Parts exist !";
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

function sb_parts_details()
{
}

function applicability_details($id)
{
    $id = explode("/api/applicability/", $id[0])[1];
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
                        $sql = "SELECT `sb_parts`.*,
                        (SELECT COUNT(*) FROM sb_tasks WHERE `sb_tasks`.`sb_part_id` = `sb_parts_applicability`.sb_part_id) AS task_count,
                        (SELECT SUM(`sb_tasks`.`Total ManPower`) FROM sb_tasks WHERE `sb_tasks`.`sb_part_id` = `sb_parts_applicability`.sb_part_id) AS total_duration
                        FROM sb_parts_applicability
                        JOIN sb_parts ON `sb_parts_applicability`.`sb_part_id` = `sb_parts`.`part_id`
                        WHERE aircraft_id = :aircraft_id
                        ORDER BY `sb_parts`.`part_name` ASC;
                        ";
                        $statement = $pdo->prepare($sql);
                        $statement->bindParam(':aircraft_id', $id);
                        $statement->execute();
                        $data = [];
                        if ($statement->rowCount() > 0) {
                            while ($SB = $statement->fetch(PDO::FETCH_ASSOC)) {
                                $dataObj = [
                                    "part_id" => $SB['part_id'],
                                    "part_name" => $SB['part_name'],
                                    "part_desc" => $SB['part_desc'],
                                    "task_count" => $SB['task_count'],
                                    "total_duration" => $SB['total_duration'],
                                ];
                                array_push($data, $dataObj);
                            }
                            $response['err'] = false;
                            $response['msg'] = "All Parts are ready to view !";
                            $response['data'] = $data;
                        } else {
                            $response['msg'] = "There is no Parts exist !";
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
