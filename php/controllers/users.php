<?php
// Routes
$endpoints += [
    '/api/users' => 'users_read',
    '/api/users/store' => 'users_store',
    '/api/users/authority' => 'get_apps',
];

function user_authority($user_id)
{
    global $pdo;
    $sql = "SELECT app_apps.app_name , app_user_authority.* 
    From app_user_authority INNER JOIN app_apps ON app_apps.app_id = app_user_authority.app_id 
    WHERE app_user_authority.user_id = :user_id and is_active = 1";
    $statement = $pdo->prepare($sql);
    $statement->bindParam(':user_id', $user_id);
    $statement->execute();
    $user_authority = [];
    if ($statement->rowCount() > 0) {
        while ($app = $statement->fetch(PDO::FETCH_ASSOC)) {
            $obj = [
                "log_id" => $app['log_id'],
                "app_id" => $app["app_id"],
                "app_name" => $app["app_name"],
                "role_id" => $app["role_id"],
            ];
            array_push($user_authority, $obj);
        }
    }
    return $user_authority;
}

function users_read()
{
    global $method;
    global $pdo;
    if ($method === "GET") {
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $headerParts = explode(' ', $_SERVER['HTTP_AUTHORIZATION']);
            if (count($headerParts) == 2 && $headerParts[0] == 'Bearer') {
                $accessToken = $headerParts[1];
                $user_info = json_decode(checkToken($accessToken), true);
                $response = [
                    'err' => true,
                    'msg' => null,
                    'data' => null,
                ];
                if (isset($user_info['is_super'])) {
                    if ($user_info['is_super'] == true) {
                        $sql = "SELECT * From app_users WHERE 1=1 ";
                        $statement = $pdo->prepare($sql);
                        $statement->execute();
                        $data = [];
                        if ($statement->rowCount() > 0) {
                            while ($user = $statement->fetch(PDO::FETCH_ASSOC)) {
                                $userObj = [
                                    "user_id" => $user['user_id'],
                                    "user_email" => $user['user_email'],
                                    "user_name" => $user['user_name'],
                                    "user_apps" => user_authority($user['user_id']),
                                ];
                                array_push($data, $userObj);
                            }
                            $response['err'] = false;
                            $response['msg'] = "All Users are ready to view !";
                            $response['data'] = $data;
                        } else {
                            $response['msg'] = "There is no users exist !";
                        }
                    } else {
                        $response['msg'] =  "Error : 401 | User role cannot access this module";
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

function users_store()
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
                if (isset($user_info['is_super'])) {
                    $response = [
                        'err' => true,
                        'msg' => null,
                        'data' => null,
                    ];
                    if ($user_info['is_super'] == true) {
                        $user_email = htmlspecialchars(strtolower(@$POST_data["user_email"]));
                        $user_name = htmlspecialchars(@$POST_data["user_name"]);
                        $is_super = htmlspecialchars(@$POST_data["is_super"]);
                        // Check if user_email is already exist
                        $sql = "SELECT * From app_users WHERE user_email = :user_email ";
                        $statement = $pdo->prepare($sql);
                        $statement->bindParam(':user_email', $user_email);
                        $statement->execute();
                        if ($statement->rowCount() == 0) {
                            // Insert user with default password
                            $defalutPass = password_hash("user", PASSWORD_DEFAULT);
                            $randomCode = rand(1000, 9999);
                            $sql = "INSERT INTO app_users
                                (user_name , user_email , user_password , user_vcode ,user_is_active) VALUES
                                (:user_name , :user_email ,:user_password , :user_vcode , 0 )
                            ";
                            $statement = $pdo->prepare($sql);
                            $statement->bindParam(':user_name', $user_name);
                            $statement->bindParam(':user_email', $user_email);
                            $statement->bindParam(':user_password', $defalutPass);
                            $statement->bindParam(':user_vcode', $randomCode);
                            $statement->execute();
                            $lastInsertId = $pdo->lastInsertId();
                            $payload = [
                                'user_id' => $lastInsertId,
                                'user_email' => $user_email,
                                'is_super' => $is_super,
                            ];

                            $Token = createToken($payload);
                            $sql = "UPDATE app_users SET user_token = :user_token WHERE (user_id = :user_id )";
                            $statement = $pdo->prepare($sql);
                            $statement->bindParam(':user_id', $lastInsertId);
                            $statement->bindParam(':user_token', $Token);
                            $statement->execute();

                            $sql = "INSERT INTO app_user_authority
                                (user_id , app_id , role_id ,is_active) VALUES
                                (:user_id ,8 ,3, 1)
                            ";
                            $statement = $pdo->prepare($sql);
                            $statement->bindParam(':user_id', $lastInsertId);
                            $statement->execute();
                            $response['err'] = false;
                            $response['msg'] = "User added Successfuly Defalut password is : 'user' !";
                        } else {
                            $response['msg'] = "This user is already exist !";
                        }
                    } else {
                        $response['msg'] = "User role cannot access this module!";
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

function get_apps()
{
    global $method, $pdo, $POST_data;
    if ($method === "POST") {
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $headerParts = explode(' ', $_SERVER['HTTP_AUTHORIZATION']);
            if (count($headerParts) == 2 && $headerParts[0] == 'Bearer') {
                $accessToken = $headerParts[1];
                $user_id = htmlspecialchars(@$POST_data["user_id"]);
                $user_info = json_decode(checkToken($accessToken), true);
                $response = [
                    'err' => true,
                    'msg' => null,
                    'data' => null,
                ];
                if (isset($user_info['is_super'])) {
                    if ($user_info['is_super'] == true) {
                        $sql = "SELECT * FROM app_apps WHERE 1=1";
                        $statement = $pdo->prepare($sql);
                        $statement->execute();
                        $data = [];
                        if ($statement->rowCount() > 0) {
                            while ($user = $statement->fetch(PDO::FETCH_ASSOC)) {
                                $userObj = [
                                    "app_id" => $user['app_id'],
                                    "app_name" => $user['app_name'],
                                    "app_is_active" => $user['app_is_active'],
                                ];
                                array_push($data, $userObj);
                            }

                            $response['err'] = false;
                            $response['msg'] = "All Apps are ready to view !";
                            $response['data'] = [
                                'all_apps' => $data,
                                'user_authority' => user_authority($user_id)
                            ];
                        } else {
                            $response['msg'] = "There is no Apps exist !";
                        }
                    } else {
                        $response['msg'] =  "Error : 401 | User role cannot access this module";
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
