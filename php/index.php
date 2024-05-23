<?php
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST");
header("Access-Control-Allow-Headers: Content-Type, Authorization");
header("Access-Control-Allow-Credentials: true");
// ini_set('mysqlnd_ms_config.max_packet_size', '64M');
// SET GLOBAL max_allowed_packet = 1073741824;
// Include Composer autoloader
require 'vendor/autoload.php';

use PHPMailer\PHPMailer\Exception;
use PHPMailer\PHPMailer\PHPMailer;

// Use PhpSpreadsheet classes
use PhpOffice\PhpSpreadsheet\IOFactory;

require './vendor/phpmailer/phpmailer/src/Exception.php';
require './vendor/phpmailer/phpmailer/src/PHPMailer.php';
require './vendor/phpmailer/phpmailer/src/SMTP.php';

require_once './token_creator.php';
require_once './db_creator.php';
$pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_OBJ);

$response = [
    'err' => true,
    'msg' => null,
    'data' => null,
];

$method = $_SERVER['REQUEST_METHOD'];
if ($method === 'POST') {
    $Post_object = file_get_contents('php://input');
    $POST_data = json_decode($Post_object, true);
    $api_name = @$POST_data["api_name"];
}

if (array_key_exists('PATH_INFO', $_SERVER)) {
    $requestUri = $_SERVER['PATH_INFO'];
} else {
    echo "Error : 403 | Forbidden";
    http_response_code(403);
    exit();
}

require "./router.php";

// app_users Module
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

function users_read()
{
    global $method;
    global $pdo;
    if ($method === "GET") {
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $headerParts = explode(' ', $_SERVER['HTTP_AUTHORIZATION']);
            if (count($headerParts) == 2 && $headerParts[0] == 'Bearer') {
                $accessToken = $headerParts[1];
                $user_info = json_decode(getToken($accessToken), true);
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
                $user_info = json_decode(getToken($accessToken), true);
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

                            $Token = setToken($payload);
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

function check_auth()
{
    global $method;
    global $pdo;
    if ($method === "GET") {
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $headerParts = explode(' ', $_SERVER['HTTP_AUTHORIZATION']);
            if (count($headerParts) == 2 && $headerParts[0] == 'Bearer') {
                $accessToken = $headerParts[1];
                $user_info = json_decode(getToken($accessToken), true);
                $response = [
                    'err' => true,
                    'msg' => null,
                    'data' => null,
                ];
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
                $user_info = json_decode(getToken($accessToken), true);
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
                $user_info = json_decode(getToken($accessToken), true);
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
                $user_info = json_decode(getToken($accessToken), true);
                if ($user_info['is_super'] == true) {
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
    global $method;
    global $POST_data;
    global $pdo;
    if ($method === "POST") {
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $headerParts = explode(' ', $_SERVER['HTTP_AUTHORIZATION']);
            if (count($headerParts) == 2 && $headerParts[0] == 'Bearer') {
                $accessToken = $headerParts[1];
                $user_info = json_decode(getToken($accessToken), true);
                if ($user_info['is_super'] == true) {
                    $response = [
                        'err' => true,
                        'msg' => null,
                        'data' => null,
                    ];

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
                $user_info = json_decode(getToken($accessToken), true);
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
                $user_info = json_decode(getToken($accessToken), true);
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
                $user_info = json_decode(getToken($accessToken), true);
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

function index_aircrafts()
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
                $user_info = json_decode(getToken($accessToken), true);
                if ($user_info) {
                    try {
                        $sql = "SELECT * FROM `aircrafts`";
                        $statement = $pdo->prepare($sql);
                        $statement->execute();
                        $data = [];
                        if ($statement->rowCount() > 0) {
                            while ($SB = $statement->fetch(PDO::FETCH_ASSOC)) {
                                $dataObj = [
                                    "aircraft_id" => $SB['aircraft_id'],
                                    "aircraft_serial_no" => $SB['aircraft_serial_no'],
                                    "aircraft_contract_name" => $SB['aircraft_contract_name'],
                                ];
                                array_push($data, $dataObj);
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
                $user_info = json_decode(getToken($accessToken), true);
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
                $user_info = json_decode(getToken($accessToken), true);
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

function createTaskList($sb_part_id, $project_id)
{
    global $pdo;
    $response = [
        'err' => true,
        'msg' => null,
        'data' => null,
    ];
    try {
        $sql = "SELECT *,(SELECT part_name FROM sb_parts WHERE part_id = :sb_part_id) AS part_name FROM sb_tasks WHERE (sb_part_id = :sb_part_id) and (department_id != 3)";
        $statement = $pdo->prepare($sql);
        $statement->bindParam(':sb_part_id', $sb_part_id);
        $statement->execute();
        $part_name = null;
        if ($statement->rowCount() > 0) {
            $expected_duration = 0;
            while ($res = $statement->fetch(PDO::FETCH_ASSOC)) {
                $expected_duration += floatval($res['expected_duration_in_hrs']);
                $part_name = $res['part_name'] . ' - Mechanics';
            }
            $sql = "SELECT * FROM project_tasklists WHERE (project_id = :project_id) and (list_name = :part_name)";
            $statement = $pdo->prepare($sql);
            $statement->bindParam(':project_id', $project_id);
            $statement->bindParam(':part_name', $part_name);
            $statement->execute();
            $part_name = null;
            if ($statement->rowCount() > 0) {
                $response['msg'] = "Duplicate Tasklist name !";
                echo $response['msg'];
            } else {
                $sql2 = "INSERT INTO project_tasklists (project_id,list_name,list_total_duration,department_id) VALUES (:project_id,:part_name,:total_duration,2)";
                $statement2 = $pdo->prepare($sql2);
                $statement2->bindParam(':project_id', $project_id);
                $statement2->bindParam(':part_name', $part_name);
                $statement2->bindParam(':total_duration', $expected_duration);
                $statement2->execute();
            }
        }
        // Avionics
        $sql = "SELECT *,(SELECT part_name FROM sb_parts WHERE part_id = :sb_part_id) AS part_name FROM sb_tasks WHERE (sb_part_id = :sb_part_id) and (department_id = 3)";
        $statement = $pdo->prepare($sql);
        $statement->bindParam(':sb_part_id', $sb_part_id);
        $statement->execute();
        $part_name = null;
        if ($statement->rowCount() > 0) {
            while ($res = $statement->fetch(PDO::FETCH_ASSOC)) {
                $part_name = $res['part_name'] . ' - Avionics';
            }
            $sql = "SELECT * FROM project_tasklists WHERE (project_id = :project_id) and (list_name = :part_name)";
            $statement = $pdo->prepare($sql);
            $statement->bindParam(':project_id', $project_id);
            $statement->bindParam(':part_name', $part_name);
            $statement->execute();
            $part_name = null;
            if ($statement->rowCount() > 0) {
                $response['msg'] = "Duplicate Tasklist name !";
                echo $response['msg'];
            } else {
                $sql2 = "INSERT INTO project_tasklists (project_id,list_name,list_total_duration,department_id) VALUES (:project_id,:part_name,:total_duration,3)";
                $statement2 = $pdo->prepare($sql2);
                $statement2->bindParam(':project_id', $project_id);
                $statement2->bindParam(':part_name', $part_name);
                $statement2->bindParam(':total_duration', $expected_duration);
                $statement2->execute();
            }
        }
        $response['err'] = false;
        $response['msg'] = "All Tasklists Created Succesfuly";
    } catch (Exception $e) {
        $response['msg'] = "An error occurred: " . $e->getMessage();
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
                $user_info = json_decode(getToken($accessToken), true);
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
                $user_info = json_decode(getToken($accessToken), true);
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

function get_apps()
{
    global $method;
    global $pdo;
    global $POST_data;
    if ($method === "POST") {
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $headerParts = explode(' ', $_SERVER['HTTP_AUTHORIZATION']);
            if (count($headerParts) == 2 && $headerParts[0] == 'Bearer') {
                $accessToken = $headerParts[1];
                $user_id = htmlspecialchars(@$POST_data["user_id"]);
                $user_info = json_decode(getToken($accessToken), true);
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

function sendMail($sendTo, $subject, $msg)
{
    $mail = new PHPMailer(true);
    try {
        $mail->isSMTP();                                            //Send using SMTP
        $mail->Host       = 'smtp.hostinger.com';                     //Set the SMTP server to send through
        $mail->SMTPAuth   = true;                                   //Enable SMTP authentication
        $mail->Username   = 'info@easetasks.com';                     //SMTP username
        $mail->Password   = '@Soo2taw2eet';                               //SMTP password
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;            //Enable implicit TLS encryption
        $mail->Port       = 465;                                    //TCP port to connect to; use 587 if you have set `SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS`
        //Recipients
        $mail->setFrom('info@easetasks.com', 'IPACO Source Retrofit App');
        $mail->addAddress($sendTo);     //Add a recipient
        //Content
        $mail->isHTML(true);                                  //Set email format to HTML
        $mail->Subject = $subject;
        $mail->Body    = $msg;
        $mail->AltBody = $msg;
        $mail->send();
    } catch (Exception $e) {
        echo $e;
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

function search_products()
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
                $user_info = json_decode(getToken($accessToken), true);
                if ($user_info) {
                    try {
                        $sql = "SELECT * FROM warehouse_products WHERE 
                        (product_pn LIKE '%" . $POST_data['search_value'] . "%' AND warehouse_id = :warehouse_id AND is_active = 1) OR
                        (product_name LIKE '%" . $POST_data['search_value'] . "%' AND warehouse_id = :warehouse_id AND is_active = 1) OR
                        (product_usa_pn LIKE '%" . $POST_data['search_value'] . "%' AND warehouse_id = :warehouse_id AND is_active = 1) ";
                        $statement = $pdo->prepare($sql);
                        // $statement->bindParam(':search_value', $POST_data['search_value']);
                        $statement->bindParam(':warehouse_id', $POST_data['warehouse_id']);
                        $statement->execute();
                        $data = [];
                        if ($statement->rowCount() > 0) {
                            while ($Item = $statement->fetch(PDO::FETCH_ASSOC)) {
                                $itemObj = [
                                    'product_id' => $Item['product_id'],
                                    'product_pn' => $Item['product_pn'],
                                    'product_name' => $Item['product_name'],
                                    'product_usa_pn' => $Item['product_usa_pn'],
                                    'category_id' => $Item['category_id'],
                                    'category_name' => getOneField("warehouse_category", "category_name", "category_id = " . $Item['category_id']),
                                    'qty_id' => getOneField("warehouse_products_qty", "qty_id", "product_id = " . $Item['product_id']),
                                    'total_qty' => getOneField("warehouse_products_qty", "SUM(qty_value)", "product_id = " . $Item['product_id']),
                                ];
                                array_push($data, $itemObj);
                            }
                            $response['msg'] = "All Products are ready to view";
                            $response['err'] = false;
                            $response['data'] = $data;
                        } else {
                            $response['msg'] = "There is no products with value";
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
                $user_info = json_decode(getToken($accessToken), true);
                if ($user_info) {
                    try {
                        $sql = "SELECT * FROM app_connectors WHERE (connector_name LIKE '%" . $POST_data['connector_name'] . "%')";
                        $statement = $pdo->prepare($sql);
                        $statement->execute();
                        $data = [];
                        if ($statement->rowCount() > 0) {
                            while ($Item = $statement->fetch(PDO::FETCH_ASSOC)) {
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



function detailed_qty($id)
{
    $product_id = explode("/logs", explode("/api/warehouse/products/qty/", $id[0])[1])[0];
    global $method;
    global $pdo;
    global $response;
    if ($method === "GET") {
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $headerParts = explode(' ', $_SERVER['HTTP_AUTHORIZATION']);
            if (count($headerParts) == 2 && $headerParts[0] == 'Bearer') {
                $accessToken = $headerParts[1];
                $user_info = json_decode(getToken($accessToken), true);
                if ($user_info) {
                    try {
                        $sql = "SELECT *,
                        (SELECT location_name FROM warehouse_locations WHERE location_id = `warehouse_products_qty`.`location_id`) AS location_name,
                        (SELECT aircraft_serial_no FROM aircrafts WHERE aircraft_id = `warehouse_products_qty`.`aircraft_id`) AS aircraft_serial_no,
                        (SELECT unit_name FROM warehouse_units WHERE unit_id = `warehouse_products_qty`.`unit_id`) AS unit_name
                        FROM warehouse_products_qty WHERE product_id = :product_id";
                        $statement = $pdo->prepare($sql);
                        $statement->bindParam(':product_id', $product_id);
                        $statement->execute();
                        $data = [];
                        if ($statement->rowCount() > 0) {
                            while ($qty = $statement->fetch(PDO::FETCH_ASSOC)) {
                                array_push($data, $qty);
                            }
                            $response['err'] = false;
                            $response['msg'] = "All Qtys are ready to view";
                            $response['data'] = $data;
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

function index_units($id)
{
    $warehouse_id = explode("/logs", explode("/api/warehouse/units/", $id[0])[1])[0];
    global $method;
    global $pdo;
    global $response;
    if ($method === "GET") {
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $headerParts = explode(' ', $_SERVER['HTTP_AUTHORIZATION']);
            if (count($headerParts) == 2 && $headerParts[0] == 'Bearer') {
                $accessToken = $headerParts[1];
                $user_info = json_decode(getToken($accessToken), true);
                if ($user_info) {
                    try {
                        $sql = "SELECT * FROM warehouse_units WHERE warehouse_id = :warehouse_id";
                        $statement = $pdo->prepare($sql);
                        $statement->bindParam(':warehouse_id', $warehouse_id);
                        $statement->execute();
                        $warehouse_units = [];
                        if ($statement->rowCount() > 0) {
                            while ($qty = $statement->fetch(PDO::FETCH_ASSOC)) {
                                array_push($warehouse_units, $qty);
                            }
                        }

                        $sql = "SELECT * FROM warehouse_category WHERE warehouse_id = :warehouse_id";
                        $statement = $pdo->prepare($sql);
                        $statement->bindParam(':warehouse_id', $warehouse_id);
                        $statement->execute();
                        $warehouse_cats = [];
                        if ($statement->rowCount() > 0) {
                            while ($qty = $statement->fetch(PDO::FETCH_ASSOC)) {
                                array_push($warehouse_cats, $qty);
                            }
                        }

                        $response['err'] = false;
                        $response['msg'] = "All Units are ready to view";
                        $response['data'] = [
                            'units' => $warehouse_units,
                            'cats' => $warehouse_cats,
                        ];
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

function store_product()
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
                $user_info = json_decode(getToken($accessToken), true);
                if ($user_info) {
                    try {
                        $sql = "INSERT INTO warehouse_products 
                        (product_pn,product_name,product_usa_pn,category_id,warehouse_id) VALUES
                        (:product_pn,:product_name,:product_usa_pn,:category_id,:warehouse_id) 
                        ";
                        $statement = $pdo->prepare($sql);
                        $statement->bindParam(':product_pn', $POST_data['product_pn']);
                        $statement->bindParam(':product_name', $POST_data['product_name']);
                        $statement->bindParam(':product_usa_pn', $POST_data['product_usa_pn']);
                        $statement->bindParam(':category_id', $POST_data['category_id']);
                        $statement->bindParam(':warehouse_id', $POST_data['warehouse_id']);
                        $statement->execute();
                        $data = [];
                        $response['msg'] = "New item added to warehouse Successfuly !";
                        $response['err'] = false;
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

function upload_items()
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
                $user_info = json_decode(getToken($accessToken), true);
                if ($user_info) {
                    // print_r($_FILES['file']);
                    if (isset($_FILES["file"])) {
                        $tmpFilePath = $_FILES['file']['tmp_name'];
                        // Load the Excel file
                        $objPHPExcel = IOFactory::load($tmpFilePath);
                        // Get the active sheet
                        $sheet = $objPHPExcel->getActiveSheet();
                        // Get the highest row number
                        $highestRow = $sheet->getHighestRow();
                        $acceptedRows = [];
                        $refusedRows = [];
                        // Loop through each row
                        for ($row = 1; $row <= $highestRow; $row++) {
                            // Get cell value for each column in the current row
                            $product_pn = $sheet->getCellByColumnAndRow(1, $row)->getValue();
                            $product_usa_pn = $sheet->getCellByColumnAndRow(3, $row)->getValue();
                            $excelRow = [
                                'cell_1' => $sheet->getCellByColumnAndRow(1, $row)->getValue(),
                                'cell_2' => $sheet->getCellByColumnAndRow(2, $row)->getValue(),
                                'cell_3' => $sheet->getCellByColumnAndRow(3, $row)->getValue(),
                                'cell_4' => $sheet->getCellByColumnAndRow(4, $row)->getValue()
                            ];
                            // Do something with the cell values
                            try {
                                $sql = "
                                    SELECT * FROM warehouse_products WHERE 
                                    (product_pn = :product_pn AND warehouse_id = :warehouse_id AND is_active = 1) OR
                                    (product_usa_pn = :product_usa_pn AND warehouse_id = :warehouse_id AND is_active = 1) 
                                ";
                                $statement = $pdo->prepare($sql);
                                $statement->bindParam(':product_pn', $product_pn);
                                $statement->bindParam(':product_usa_pn', $product_usa_pn);
                                $statement->bindParam(':warehouse_id', $_POST['warehouse_id']);
                                $statement->execute();
                                if ($statement->rowCount() > 0) {
                                    array_push($refusedRows, $excelRow);
                                } else {
                                    array_push($acceptedRows, $excelRow);
                                }
                                $response['data'] = [
                                    'accepted_rows' => $acceptedRows,
                                    'refused_rows' => $refusedRows
                                ];
                                $response['err'] = false;
                                $response['msg'] = 'All Sheet rows has been tested';
                            } catch (Exception $e) {
                                $response['msg'] = "An error occurred: " . $e->getMessage();
                            }
                        }
                    } else {
                        $response['msg'] = "No File Uploaded";
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
