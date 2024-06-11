<?php
// Routes
$endpoints += [
    '/api/auth/check' => 'check_auth',
    '/api/auth/login' => 'auth_login',
    '/api/auth/activate' => 'user_activate',
    '/api/auth/resendcode' => 'resend_code',
];

function check_auth()
{
    global $method, $pdo, $response;
    if ($method === "GET") {
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $headerParts = explode(' ', $_SERVER['HTTP_AUTHORIZATION']);
            if (count($headerParts) == 2 && $headerParts[0] == 'Bearer') {
                $accessToken = $headerParts[1];
                $user_info = json_decode(checkToken($accessToken), true);
                $sql = "SELECT * From app_users WHERE user_id=:user_id";
                $statement = $pdo->prepare($sql);
                $statement->bindParam(':user_id', $user_info['user_id']);
                $statement->execute();
                if ($statement->rowCount() > 0) {
                    while ($user = $statement->fetch(PDO::FETCH_ASSOC)) {
                        $userObj = [
                            "user_id" => $user['user_id'],
                            "user_email" => $user['user_email'],
                            "user_name" => $user['user_name'],
                            "user_apps" => user_authority($user['user_id']),
                        ];
                    }
                    $response['err'] = false;
                    $response['msg'] = "Token is valid !";
                    $response['data'] = $userObj;
                } else {
                    $response['msg'] = "User Token is false !";
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

function auth_login()
{
    global $method;
    global $POST_data;
    global $pdo;
    if ($method === "POST") {
        $response = [
            'err' => true,
            'msg' => null,
            'data' => null,
        ];
        $user_email = htmlspecialchars(strtolower(@$POST_data["user_email"]));
        $user_password = htmlspecialchars(@$POST_data["user_password"]);
        $sql = "SELECT * From app_users WHERE (user_email = :user_email)";
        $statement = $pdo->prepare($sql);
        $statement->bindParam(':user_email', $user_email);
        $statement->execute();
        if ($statement->rowCount() > 0) {
            while ($user = $statement->fetch(PDO::FETCH_ASSOC)) {
                if (password_verify($user_password, $user['user_password'])) {
                    $response['err'] = false;
                    if ($user['user_is_active'] == 0) {
                        $response['msg'] = "User is not activated yet";
                        $response['data'] = [
                            "user_is_active" => false,
                            "user_token" => $user['user_token']
                        ];
                    } else {
                        $response['msg'] = "Successfuly logged in";
                        $response['data'] = [
                            "user_is_active" => true,
                            "user_id" => $user['user_id'],
                            "user_email" => $user['user_email'],
                            "user_token" => $user['user_token'],
                            "user_apps" => user_authority($user['user_id']),
                        ];
                    }
                } else {
                    $response['msg'] = "Invalid Password";
                }
            }
        } else {
            $response['msg'] = "Invalid Email";
        }
        echo json_encode($response, true);
    } else {
        echo 'Method Not Allowed';
    }
}

function user_activate()
{
    global $method;
    global $pdo;
    global $POST_data;
    if ($method === "POST") {
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $headerParts = explode(' ', $_SERVER['HTTP_AUTHORIZATION']);
            if (count($headerParts) == 2 && $headerParts[0] == 'Bearer') {
                $accessToken = $headerParts[1];
                $user_vcode = htmlspecialchars(strtolower(@$POST_data["v_code"]));
                $user_info = json_decode(checkToken($accessToken), true);
                $response = [
                    'err' => true,
                    'msg' => null,
                    'data' => null,
                ];
                try {
                    $sql = "SELECT * FROM app_users WHERE user_id=:user_id and user_vcode =:user_vcode";
                    $statement = $pdo->prepare($sql);
                    $statement->bindParam(':user_id', $user_info['user_id']);
                    $statement->bindParam(':user_vcode', $user_vcode);
                    $statement->execute();
                    if ($statement->rowCount() > 0) {
                        while ($user = $statement->fetch(PDO::FETCH_ASSOC)) {
                            $userObj = [
                                "user_id" => $user['user_id'],
                                "user_email" => $user['user_email'],
                                "user_name" => $user['user_name'],
                                "user_apps" => user_authority($user['user_id']),
                            ];
                        }
                        try {
                            $sql = "UPDATE app_users SET user_is_active = 1 WHERE user_id=:user_id and user_vcode =:user_vcode";
                            $statement = $pdo->prepare($sql);
                            $statement->bindParam(':user_id', $user_info['user_id']);
                            $statement->bindParam(':user_vcode', $user_vcode);
                            $statement->execute();
                            $response['err'] = false;
                            $response['msg'] = "Account Activated Succssefuly";
                            $response['data'] = $userObj;
                        } catch (Exception $e) {
                            $response['msg'] = "An error occurred: " . $e->getMessage();
                        }
                    } else {
                        $response['msg'] = "Wrong user code!";
                    }
                } catch (Exception $e) {
                    $response['msg'] = "An error occurred: " . $e->getMessage();
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

function resend_code()
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
                try {
                    $sql = "SELECT * FROM app_users WHERE user_id=:user_id";
                    $statement = $pdo->prepare($sql);
                    $statement->bindParam(':user_id', $user_info['user_id']);
                    $statement->execute();
                    if ($statement->rowCount() > 0) {
                        while ($user = $statement->fetch(PDO::FETCH_ASSOC)) {
                            $userObj = [
                                "user_email" => $user['user_email'],
                                "user_name" => $user['user_name'],
                                "user_vcode" => $user['user_vcode'],
                            ];
                        }
                        $msg = "Welcome " . $userObj['user_name'] . "<br> You Code is : " . $userObj['user_vcode'];
                        try {
                            sendMail($userObj['user_email'], "IPACO Verfication Code", $msg);
                            $response['err'] = false;
                            $response['msg'] = "Code Sent !";
                        } catch (Exception $e) {
                            $response['msg'] = $e;
                        }
                    } else {
                        $response['msg'] = "Wrong user code!";
                    }
                } catch (Exception $e) {
                    $response['msg'] = "An error occurred: " . $e->getMessage();
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
