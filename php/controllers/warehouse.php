<?php
// Routes
$endpoints += [
    '/api/warehouse/products' => 'search_products',
    '/api/warehouse/products/store' => 'store_product',
    '/api/warehouse/products/qty/\d+' => 'detailed_qty',
    '/api/warehouse/units/\d+' => 'index_units',
];

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
                $user_info = json_decode(checkToken($accessToken), true);
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
                $user_info = json_decode(checkToken($accessToken), true);
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
                $user_info = json_decode(checkToken($accessToken), true);
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
                $user_info = json_decode(checkToken($accessToken), true);
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
