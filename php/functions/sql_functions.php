<?php

function getOneField($table_name, $required_field, $condition)
{
    global $pdo;
    $sql = "SELECT " . $required_field . " AS Final FROM " . $table_name . " WHERE " . $condition;
    $statement = $pdo->prepare($sql);
    $statement->execute();
    if ($statement->rowCount() > 0) {
        while ($el = $statement->fetch(PDO::FETCH_ASSOC)) {
            return $el['Final'];
        }
    }
}

function getRows($table_name, $condition)
{
    global $pdo;
    $sql = "SELECT * FROM $table_name WHERE " . $condition;
    $statement = $pdo->prepare($sql);
    $statement->execute();
    $final = [];

    if ($statement->rowCount() > 0) {
        while ($el = $statement->fetch(PDO::FETCH_ASSOC)) {
            array_push($final, $el);
        }
    }

    return $final;
}

function update_data()
{
    global $method;
    global $POST_data;
    global $pdo;
    if ($method === "POST") {
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $headerParts = explode(' ', $_SERVER['HTTP_AUTHORIZATION']);
            if (count($headerParts) == 2 && $headerParts[0] == 'Bearer') {
                $accessToken = $headerParts[1];
                $user_info = json_decode(checkToken($accessToken), true);
                if ($user_info) {
                    $response = [
                        'err' => true,
                        'msg' => null,
                        'data' => null,
                    ];
                    $table_name = htmlspecialchars(strtolower(@$POST_data["table_name"]));
                    $condition = htmlspecialchars(strtolower(@$POST_data["condition"]));
                    $updateData = @$POST_data["data"];
                    $sql = "UPDATE $table_name SET ";
                    $updates = array();
                    foreach ($updateData as $column => $value) {
                        if (strpos($column, "password") !== false) {
                            $defalutPass = password_hash($value, PASSWORD_DEFAULT);
                            $updates[] = "$column = '$defalutPass'";
                        } else {
                            $value = htmlspecialchars($value);
                            $updates[] = "$column = '$value'";
                        }
                    }
                    $sql .= implode(", ", $updates);
                    $sql .= " WHERE $condition";
                    $statement = $pdo->prepare($sql);
                    $statement->execute();
                    $response['err'] = false;
                    $response['msg'] = "Data Updated Successfuly !";
                    echo json_encode($response, true);
                } else {
                    // http_response_code(401); // Unauthorized
                    echo "Error : 401 | User role cannot access this module";
                }
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

function insert_data()
{
    global $method, $POST_data, $pdo, $response;
    if ($method == "POST") {
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $headerParts = explode(' ', $_SERVER['HTTP_AUTHORIZATION']);
            if (count($headerParts) == 2 && $headerParts[0] == 'Bearer') {
                $accessToken = $headerParts[1];
                $user_info = json_decode(checkToken($accessToken), true);
                if ($user_info) {
                    $table_name = htmlspecialchars(strtolower(@$POST_data["table_name"]));
                    $Fields = @$POST_data["Fields"];
                    $Values = @$POST_data["Values"];
                    $FieldsStr = "";
                    $ValuesStr = "";
                    foreach ($Fields as $index => $value) {

                        $FieldsStr .= "$value";
                        if (count($Fields) - 1 != $index) {
                            $FieldsStr .= ",";
                        }
                    }
                    foreach ($Values as $index => $value) {
                        $ValuesStr .= "'$value'";
                        if (count($Values) - 1 != $index) {
                            $ValuesStr .= ",";
                        }
                    }
                    $sql = "INSERT INTO $table_name ($FieldsStr) VALUES ($ValuesStr)";
                    try {
                        $statement = $pdo->prepare($sql);
                        $statement->execute();
                        $response['data'] = [
                            'id' => $pdo->lastInsertId()
                        ];
                        $response['err'] = false;
                        $response['msg'] = "Data Inserted Successfuly !";
                    } catch (Exception $e) {
                        // Code to handle the exception
                        echo "An error occurred: " . $e->getMessage();
                    }
                    echo json_encode($response, true);
                } else {
                    // http_response_code(401); // Unauthorized
                    echo "Error : 401 | User role cannot access this module";
                }
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
