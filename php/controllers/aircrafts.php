<?php
// Routes
$endpoints += [
    '/api/aircrafts' => 'index_aircrafts',
    '/api/aircrafts/\d+' => 'aircrafts_details',
];

function index_aircrafts()
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
                        $sql = "SELECT * FROM `aircrafts` ORDER BY aircraft_serial_no";
                        $statement = $pdo->prepare($sql);
                        $statement->execute();
                        $data = [];
                        if ($statement->rowCount() > 0) {
                            while ($SB = $statement->fetch(PDO::FETCH_ASSOC)) {
                                array_push($data, $SB);
                            }
                            $response['err'] = false;
                            $response['msg'] = "All Aircrafts are ready to view !";
                            $response['data'] = $data;
                        } else {
                            $response['msg'] = "There is no Aircrafts exist !";
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

function aircrafts_details($id)
{
    $id = explode("/api/aircrafts/", $id[0])[1];
    global $method, $pdo, $response;
    if ($method === "GET") {
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $headerParts = explode(' ', $_SERVER['HTTP_AUTHORIZATION']);
            if (count($headerParts) == 2 && $headerParts[0] == 'Bearer') {
                $accessToken = $headerParts[1];
                $user_info = json_decode(checkToken($accessToken), true);
                if ($user_info) {
                    try {
                        $sql = "SELECT * , 
                        (SELECT COUNT(*) FROM sb_parts_applicability WHERE aircraft_id =:aircraft_id) AS sb_parts_count 
                        FROM aircrafts WHERE aircraft_id =:aircraft_id";
                        $statement = $pdo->prepare($sql);
                        $statement->bindParam(':aircraft_id', $id);
                        $statement->execute();
                        $data = [];
                        if ($statement->rowCount() > 0) {
                            while ($SB = $statement->fetch(PDO::FETCH_ASSOC)) {
                                $dataObj = [
                                    "aircraft_id" => $SB['aircraft_id'],
                                    "aircraft_serial_no" => $SB['aircraft_serial_no'],
                                    "aircraft_contract_name" => $SB['aircraft_contract_name'],
                                    "sb_parts_count" => $SB['sb_parts_count'],
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
