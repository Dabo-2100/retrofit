<?php

header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST");
header("Access-Control-Allow-Headers: Content-Type, Authorization");
header("Access-Control-Allow-Credentials: true");
// ini_set('mysqlnd_ms_config.max_packet_size', '64M');
// SET GLOBAL max_allowed_packet = 1073741824;
// Include Composer autoloader
require 'vendor/autoload.php';

// Use PhpMailer
use PHPMailer\PHPMailer\Exception;
use PHPMailer\PHPMailer\PHPMailer;

require './vendor/phpmailer/phpmailer/src/Exception.php';
require './vendor/phpmailer/phpmailer/src/PHPMailer.php';
require './vendor/phpmailer/phpmailer/src/SMTP.php';

// Use PhpSpreadsheet classes
use PhpOffice\PhpSpreadsheet\IOFactory;
use PhpOffice\PhpSpreadsheet\Calculation\DateTimeExcel\Date;

// Create Database Connection
require './database/db_creator.php';
$pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_OBJ);
require "./functions/sql_functions.php";

// Use JWT Token
require './functions/token_functions.php';

// Use Server Method
$method = $_SERVER['REQUEST_METHOD'];

if ($method === 'POST') {
    $Post_object = file_get_contents('php://input');
    $POST_data = json_decode($Post_object, true);
    $api_name = @$POST_data["api_name"];
}

// Make Global Response
$response = [
    'err' => true,
    'msg' => null,
    'data' => null,
];

$endpoints = [
    '/api/insert' => 'insert_data',
    '/api/update' => 'update_data',
];

// Use Controllers
require "./controllers/auth.php";
require "./controllers/aircrafts.php";
require "./controllers/connectors.php";
require "./controllers/projects.php";
require "./controllers/retrofit.php";
require "./controllers/users.php";
require "./controllers/warehouse.php";
require "./controllers/forms.php";

// Use Router
require "./assets/router.php";

// function sendMail($sendTo, $subject, $msg)
// {
//     $mail = new PHPMailer(true);
//     try {
//         $mail->isSMTP();                                            //Send using SMTP
//         $mail->Host       = 'smtp.hostinger.com';                     //Set the SMTP server to send through
//         $mail->SMTPAuth   = true;                                   //Enable SMTP authentication
//         $mail->Username   = 'info@easetasks.com';                     //SMTP username
//         $mail->Password   = '@Soo2taw2eet';                               //SMTP password
//         $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;            //Enable implicit TLS encryption
//         $mail->Port       = 465;                                    //TCP port to connect to; use 587 if you have set `SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS`
//         //Recipients
//         $mail->setFrom('info@easetasks.com', 'IPACO Source Retrofit App');
//         $mail->addAddress($sendTo);     //Add a recipient
//         //Content
//         $mail->isHTML(true);                                  //Set email format to HTML
//         $mail->Subject = $subject;
//         $mail->Body    = $msg;
//         $mail->AltBody = $msg;
//         $mail->send();
//     } catch (Exception $e) {
//         echo $e;
//     }
// }

// function upload_items()
// {
//     global $method;
//     global $POST_data;
//     global $pdo;
//     global $response;

//     if ($method === "POST") {
//         if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
//             $headerParts = explode(' ', $_SERVER['HTTP_AUTHORIZATION']);
//             if (count($headerParts) == 2 && $headerParts[0] == 'Bearer') {
//                 $accessToken = $headerParts[1];
//                 $user_info = json_decode(checkToken($accessToken), true);
//                 if ($user_info) {
//                     // print_r($_FILES['file']);
//                     if (isset($_FILES["file"])) {
//                         $tmpFilePath = $_FILES['file']['tmp_name'];
//                         // Load the Excel file
//                         $objPHPExcel = IOFactory::load($tmpFilePath);
//                         // Get the active sheet
//                         $sheet = $objPHPExcel->getActiveSheet();
//                         // Get the highest row number
//                         $highestRow = $sheet->getHighestRow();
//                         $acceptedRows = [];
//                         $refusedRows = [];
//                         // Loop through each row
//                         for ($row = 1; $row <= $highestRow; $row++) {
//                             // Get cell value for each column in the current row
//                             $product_pn = $sheet->getCellByColumnAndRow(1, $row)->getValue();
//                             $product_usa_pn = $sheet->getCellByColumnAndRow(3, $row)->getValue();
//                             $excelRow = [
//                                 'cell_1' => $sheet->getCellByColumnAndRow(1, $row)->getValue(),
//                                 'cell_2' => $sheet->getCellByColumnAndRow(2, $row)->getValue(),
//                                 'cell_3' => $sheet->getCellByColumnAndRow(3, $row)->getValue(),
//                                 'cell_4' => $sheet->getCellByColumnAndRow(4, $row)->getValue()
//                             ];
//                             // Do something with the cell values
//                             try {
//                                 $sql = "
//                                     SELECT * FROM warehouse_products WHERE 
//                                     (product_pn = :product_pn AND warehouse_id = :warehouse_id AND is_active = 1) OR
//                                     (product_usa_pn = :product_usa_pn AND warehouse_id = :warehouse_id AND is_active = 1) 
//                                 ";
//                                 $statement = $pdo->prepare($sql);
//                                 $statement->bindParam(':product_pn', $product_pn);
//                                 $statement->bindParam(':product_usa_pn', $product_usa_pn);
//                                 $statement->bindParam(':warehouse_id', $_POST['warehouse_id']);
//                                 $statement->execute();
//                                 if ($statement->rowCount() > 0) {
//                                     array_push($refusedRows, $excelRow);
//                                 } else {
//                                     array_push($acceptedRows, $excelRow);
//                                 }
//                                 $response['data'] = [
//                                     'accepted_rows' => $acceptedRows,
//                                     'refused_rows' => $refusedRows
//                                 ];
//                                 $response['err'] = false;
//                                 $response['msg'] = 'All Sheet rows has been tested';
//                             } catch (Exception $e) {
//                                 $response['msg'] = "An error occurred: " . $e->getMessage();
//                             }
//                         }
//                     } else {
//                         $response['msg'] = "No File Uploaded";
//                     }
//                 } else {
//                     $response['msg'] = "Invaild user token !";
//                 }
//                 echo json_encode($response, true);
//             } else {
//                 http_response_code(400);
//                 echo "Error : 400 | Bad Request";
//             }
//         } else {
//             http_response_code(401); // Unauthorized
//             echo "Error : 401 | Unauthorized";
//         }
//     } else {
//         echo 'Method Not Allowed';
//     }
// }
