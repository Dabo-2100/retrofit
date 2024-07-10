<?php
// Routes
$endpoints += [
    '/api/projects' => 'index_projects',
    '/api/projects/\d+' => 'project_details',
    '/api/projects/store' => 'store_project',
    '/api/projects/delete' => 'delete_project',
    '/api/projects/status' => 'index_status',
    '/api/projects/teams' => 'index_teams',
    '/api/projects/\d+/tasklists' => 'index_tasklists',
    '/api/projects/\d+/tasklists/\d+/tasks' => 'index_tasks',
    '/api/tasklists/\d+/tasks' => 'index_tasks',
    '/api/tasklists/istemplate' => 'index_templates',
    '/api/tasks/store' => 'store_task',
    '/api/tasks/\d+/switch' => 'switch_task',
    '/api/sb_tasks' => 'index_sbtasks',
    '/api/tasks/\d+/comments' => 'index_comments',
    '/api/tasks/\d+/redescr' => 'update_desc',
];

function index_status()
{
    global $pdo, $response, $method;
    if ($method === "GET") {
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $headerParts = explode(' ', $_SERVER['HTTP_AUTHORIZATION']);
            if (count($headerParts) == 2 && $headerParts[0] == 'Bearer') {
                $accessToken = $headerParts[1];
                $user_info = json_decode(checkToken($accessToken), true);
                if ($user_info) {
                    try {
                        $sql = "SELECT * FROM project_status";
                        $statement = $pdo->prepare($sql);
                        // $statement->bindParam(':form_id', $form_id);
                        $statement->execute();
                        $data = [];
                        if ($statement->rowCount() > 0) {
                            while ($el = $statement->fetch(PDO::FETCH_ASSOC)) {
                                array_push($data, $el);
                            }
                            $response['err'] = false;
                            $response['msg'] = "All Status are ready to view !";
                            $response['data'] = $data;
                        } else {
                            $response['msg'] = "There are no Status found !";
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

function index_projects()
{
    global $pdo, $response, $method;
    if ($method === "GET") {
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $headerParts = explode(' ', $_SERVER['HTTP_AUTHORIZATION']);
            if (count($headerParts) == 2 && $headerParts[0] == 'Bearer') {
                $accessToken = $headerParts[1];
                $user_info = json_decode(checkToken($accessToken), true);
                if ($user_info) {
                    try {
                        $sql = "SELECT * FROM app_projects";
                        $statement = $pdo->prepare($sql);
                        // $statement->bindParam(':form_id', $form_id);
                        $statement->execute();
                        $data = [];
                        if ($statement->rowCount() > 0) {
                            while ($el = $statement->fetch(PDO::FETCH_ASSOC)) {
                                $el['project_progress'] = getProjectProgress($el['project_id']);
                                $el['project_status_name'] = getOneField("project_status", "status_name", "status_id = " . $el['project_status_id']);
                                array_push($data, $el);
                            }
                            $response['err'] = false;
                            $response['msg'] = "All Projects are ready to view !";
                            $response['data'] = $data;
                        } else {
                            $response['msg'] = "There are no Projects found !";
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

function store_project()
{
    insert_data();
}

function store_task()
{
    insert_data();
}

function delete_project()
{
}

function index_tasklists($id)
{
    $project_id = explode("/tasklists", explode("/api/projects/", $id[0])[1])[0];
    global $pdo, $response, $method, $POST_data;
    if ($method === "GET") {
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $headerParts = explode(' ', $_SERVER['HTTP_AUTHORIZATION']);
            if (count($headerParts) == 2 && $headerParts[0] == 'Bearer') {
                $accessToken = $headerParts[1];
                $user_info = json_decode(checkToken($accessToken), true);
                if ($user_info) {
                    try {
                        $sql = "SELECT * FROM project_tasklists WHERE project_id =:project_id ORDER BY tasklist_start_date";
                        $statement = $pdo->prepare($sql);
                        $statement->bindParam(':project_id', $project_id);
                        $statement->execute();
                        $data = [];
                        if ($statement->rowCount() > 0) {
                            while ($el = $statement->fetch(PDO::FETCH_ASSOC)) {
                                $el['tasklist_status_name'] = getOneField("project_status", "status_name", "status_id = " . $el['tasklist_status_id']);
                                $el['tasklist_progress'] = getTaskListProgress($el['tasklist_id']);
                                array_push($data, $el);
                            }
                            $response['err'] = false;
                            $response['msg'] = "All Tasklists are ready to view !";
                            $response['data'] = $data;
                        } else {
                            $response['msg'] = "There are no Tasklists found !";
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
    } elseif ($method === "POST") {
        try {
            $sql = "
            SELECT * FROM project_tasklists 
            WHERE project_id = :project_id 
            AND tasklist_name LIKE :tasklist_name 
            ORDER BY tasklist_start_date";
            $tasklist_name = '%' . $POST_data['contains'] . '%';
            $statement = $pdo->prepare($sql);
            $statement->bindParam(':project_id', $project_id, PDO::PARAM_INT);
            $statement->bindParam(':tasklist_name', $tasklist_name, PDO::PARAM_STR);
            $statement->execute();
            $data = [];
            if ($statement->rowCount() > 0) {
                while ($el = $statement->fetch(PDO::FETCH_ASSOC)) {
                    $el['tasklist_status_name'] = getOneField("project_status", "status_name", "status_id = " . $el['tasklist_status_id']);
                    $el['tasklist_progress'] = getTaskListProgress($el['tasklist_id']);
                    array_push($data, $el);
                }
                $response['err'] = false;
                $response['msg'] = "All Tasklists are ready to view !";
                $response['data'] = $data;
            } else {
                $response['msg'] = "There are no Tasklists found !";
            }
            echo json_encode($response, true);
        } catch (Exception $e) {
            $response['msg'] = "An error occurred: " . $e->getMessage();
        }
    } else {
        echo 'Method Not Allowed';
    }
}

function index_tasks($id)
{
    // $project_id = explode("/tasklists", explode("/api/projects/", $id[0])[1])[0];
    $tasklist_id = explode("/tasks", explode("tasklists/", $id[0])[1])[0];
    global $pdo, $response, $method, $POST_data;
    if ($method === "GET") {
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $headerParts = explode(' ', $_SERVER['HTTP_AUTHORIZATION']);
            if (count($headerParts) == 2 && $headerParts[0] == 'Bearer') {
                $accessToken = $headerParts[1];
                $user_info = json_decode(checkToken($accessToken), true);
                if ($user_info) {
                    try {
                        $sql = "
                        SELECT *,
                        (SELECT COUNT(*) FROM task_comments WHERE task_id = `project_tasks`.`task_id`) AS comment_count 
                        FROM project_tasks 
                        WHERE tasklist_id =:tasklist_id
                        ORDER BY task_order
                        ";
                        $statement = $pdo->prepare($sql);
                        $statement->bindParam(':tasklist_id', $tasklist_id);
                        $statement->execute();
                        $data = [];
                        if ($statement->rowCount() > 0) {
                            while ($el = $statement->fetch(PDO::FETCH_ASSOC)) {
                                $el['tasklist_status_name'] = getOneField("project_status", "status_name", "status_id = " . $el['task_status_id']);
                                $el['tasklist_status_color'] = getOneField("project_status", "status_color_code", "status_id = " . $el['task_status_id']);
                                array_push($data, $el);
                            }
                            $response['err'] = false;
                            $response['msg'] = "All Tasks are ready to view !";
                            $response['data'] = $data;
                        } else {
                            $response['msg'] = "There are no Tasks found !";
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
    } elseif ($method === "POST") {
        try {
            $sql = "SELECT *,(SELECT COUNT(*) FROM task_comments WHERE task_id = `project_tasks`.`task_id`) AS comment_count FROM project_tasks WHERE tasklist_id =:tasklist_id and  task_status_id=:task_status_id";
            $statement = $pdo->prepare($sql);
            $statement->bindParam(':tasklist_id', $tasklist_id);
            $statement->bindParam(':task_status_id', $POST_data['task_status_id']);
            $statement->execute();
            $data = [];
            if ($statement->rowCount() > 0) {
                while ($el = $statement->fetch(PDO::FETCH_ASSOC)) {
                    $el['tasklist_status_name'] = getOneField("project_status", "status_name", "status_id = " . $el['task_status_id']);
                    $el['tasklist_status_color'] = getOneField("project_status", "status_color_code", "status_id = " . $el['task_status_id']);
                    array_push($data, $el);
                }
                $response['err'] = false;
                $response['msg'] = "All Tasks are ready to view !";
                $response['data'] = $data;
            } else {
                $response['msg'] = "There are no Tasks found !";
            }
            echo json_encode($response, true);
        } catch (Exception $e) {
            $response['msg'] = "An error occurred: " . $e->getMessage();
        }
    } else {
        echo 'Method Not Allowed';
    }
}

function index_teams()
{
    global $pdo, $response, $method;
    if ($method === "GET") {
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $headerParts = explode(' ', $_SERVER['HTTP_AUTHORIZATION']);
            if (count($headerParts) == 2 && $headerParts[0] == 'Bearer') {
                $accessToken = $headerParts[1];
                $user_info = json_decode(checkToken($accessToken), true);
                if ($user_info) {
                    try {
                        $sql = "SELECT * FROM app_teams";
                        $statement = $pdo->prepare($sql);
                        // $statement->bindParam(':form_id', $form_id);
                        $statement->execute();
                        $data = [];
                        if ($statement->rowCount() > 0) {
                            while ($el = $statement->fetch(PDO::FETCH_ASSOC)) {
                                array_push($data, $el);
                            }
                            $response['err'] = false;
                            $response['msg'] = "All Teams are ready to view !";
                            $response['data'] = $data;
                        } else {
                            $response['msg'] = "There are no Teams found !";
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

function getTaskListProgress($tasklist_id)
{
    global $pdo;
    try {
        $sql = "SELECT *,(SELECT tasklist_duration FROM project_tasklists WHERE tasklist_id=:tasklist_id) As list_Duration FROM project_tasks WHERE tasklist_id =:tasklist_id";
        $statement = $pdo->prepare($sql);
        $statement->bindParam(':tasklist_id', $tasklist_id);
        $statement->execute();
        $tasklistProgress = 0;
        $totalDoneHrs = 0;
        if ($statement->rowCount() > 0) {
            $listDuration = 0;
            while ($el = $statement->fetch(PDO::FETCH_ASSOC)) {
                $taskDoneHrs = ($el['task_progress'] / 100) * $el['task_duration'];
                $totalDoneHrs += $taskDoneHrs;
                $listDuration = $el['list_Duration'];
            }
            if ($listDuration > 0) {
                $tasklistProgress = ($totalDoneHrs / $listDuration) * 100;
            }
        }
        return $tasklistProgress;
    } catch (Exception $e) {
        echo $e->getMessage();
    }
}

function getTaskListActualDuration($tasklist_id)
{
    global $pdo;
    try {
        $sql = "
            SELECT * , (SELECT tasklist_duration FROM project_tasklists WHERE tasklist_id = $tasklist_id) FROM project_tasks WHERE tasklist_id = $tasklist_id;
        ";
        $statement = $pdo->prepare($sql);
        // $statement->bindParam(':tasklist_id', $tasklist_id);
        $statement->execute();
        $tasklist_actual_duration = 0;
        if ($statement->rowCount() > 0) {
            while ($el = $statement->fetch(PDO::FETCH_ASSOC)) {
                if ($el['actual_duration'] != 0) {
                    $tasklist_actual_duration += $el['actual_duration'];
                } else {
                    if ($el['task_status_id'] == 4) {
                        $tasklist_actual_duration += $el['task_duration'];
                    }
                }
            }
        }
        return $tasklist_actual_duration;
    } catch (Exception $e) {
        echo $e->getMessage();
    }
}

function index_sbtasks()
{
    global $pdo, $response, $method;
    if ($method === "GET") {
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $headerParts = explode(' ', $_SERVER['HTTP_AUTHORIZATION']);
            if (count($headerParts) == 2 && $headerParts[0] == 'Bearer') {
                $accessToken = $headerParts[1];
                $user_info = json_decode(checkToken($accessToken), true);
                if ($user_info) {
                    try {
                        $sql = "SELECT * FROM `sb_tasks` ORDER BY sb_id , sb_part_id , task_level_1 , task_level_2 , task_level_3 , task_level_4";
                        $statement = $pdo->prepare($sql);
                        // $statement->bindParam(':form_id', $form_id);
                        $statement->execute();
                        $data = [];
                        if ($statement->rowCount() > 0) {
                            while ($el = $statement->fetch(PDO::FETCH_ASSOC)) {
                                $el['sb_name'] = getOneField("sbs", "sb_no", "sb_id = " . $el['sb_id']);
                                $el['sb_part_name'] = getOneField("sb_parts", "part_name", "part_id = " . $el['sb_part_id']);
                                $el['task_type_name'] = getOneField("task_types_zoho", "`Task Type Name`", "task_type_id = " . $el['task_type_id']);
                                array_push($data, $el);
                            }
                            $response['err'] = false;
                            $response['msg'] = "All sb_tasks are ready to view !";
                            $response['data'] = $data;
                        } else {
                            $response['msg'] = "There are sb_tasks found !";
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

function getProjectProgress($project_id)
{
    global $pdo;
    try {
        $sql = "SELECT * FROM project_tasklists WHERE project_id =:project_id";
        $statement = $pdo->prepare($sql);
        $statement->bindParam(':project_id', $project_id);
        $statement->execute();
        $projectProgress = 0;
        $projectDuration = 0;
        if ($statement->rowCount() > 0) {
            $projectDoneHrs = 0;
            while ($el = $statement->fetch(PDO::FETCH_ASSOC)) {
                $tasklistDuration = $el['tasklist_duration'];
                $projectDuration += $tasklistDuration;
                $tasklistProgress = getTaskListProgress($el['tasklist_id']) / 100;
                $doneHrs = $tasklistProgress * $tasklistDuration;
                $projectDoneHrs += $doneHrs;
            }
            $projectProgress = ($projectDoneHrs / $projectDuration) * 100;
        }
        return $projectProgress;
    } catch (Exception $e) {
        echo $e->getMessage();
    }
}

function index_templates()
{
    global $pdo, $response, $method;
    if ($method === "GET") {
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $headerParts = explode(' ', $_SERVER['HTTP_AUTHORIZATION']);
            if (count($headerParts) == 2 && $headerParts[0] == 'Bearer') {
                $accessToken = $headerParts[1];
                $user_info = json_decode(checkToken($accessToken), true);
                if ($user_info) {
                    try {
                        $sql = "SELECT * FROM project_tasklists WHERE is_template = 1 ORDER BY tasklist_name";
                        $statement = $pdo->prepare($sql);
                        $statement->execute();
                        $data = [];

                        if ($statement->rowCount() > 0) {
                            while ($el = $statement->fetch(PDO::FETCH_ASSOC)) {
                                array_push($data, $el);
                            }
                            $response['err'] = false;
                            $response['msg'] = "All Tasklists are ready to view !";
                            $response['data'] = $data;
                        } else {
                            $response['msg'] = "There are no Tasklists found !";
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

function index_comments($id)
{
    $task_id = explode("/comments", explode("api/tasks/", $id[0])[1])[0];
    global $pdo, $response, $method, $POST_data;
    if ($method === "GET") {
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $headerParts = explode(' ', $_SERVER['HTTP_AUTHORIZATION']);
            if (count($headerParts) == 2 && $headerParts[0] == 'Bearer') {
                $accessToken = $headerParts[1];
                $user_info = json_decode(checkToken($accessToken), true);
                if ($user_info) {
                    try {
                        $sql = "SELECT * FROM task_comments WHERE task_id =:task_id ORDER BY created_at";
                        $statement = $pdo->prepare($sql);
                        $statement->bindParam(':task_id', $task_id);
                        $statement->execute();
                        $data = [];
                        if ($statement->rowCount() > 0) {
                            while ($el = $statement->fetch(PDO::FETCH_ASSOC)) {
                                array_push($data, $el);
                            }
                            $response['err'] = false;
                            $response['msg'] = "All Comments are ready to view !";
                            $response['data'] = $data;
                        } else {
                            $response['msg'] = "There are no Comments found !";
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
    } elseif ($method === "POST") {
        try {
            $sql = "
            SELECT * FROM project_tasklists 
            WHERE project_id = :project_id 
            AND tasklist_name LIKE :tasklist_name 
            ORDER BY tasklist_start_date";
            $tasklist_name = '%' . $POST_data['contains'] . '%';
            $statement = $pdo->prepare($sql);
            $statement->bindParam(':project_id', $project_id, PDO::PARAM_INT);
            $statement->bindParam(':tasklist_name', $tasklist_name, PDO::PARAM_STR);
            $statement->execute();
            $data = [];
            if ($statement->rowCount() > 0) {
                while ($el = $statement->fetch(PDO::FETCH_ASSOC)) {
                    $el['tasklist_status_name'] = getOneField("project_status", "status_name", "status_id = " . $el['tasklist_status_id']);
                    $el['tasklist_progress'] = getTaskListProgress($el['tasklist_id']);
                    array_push($data, $el);
                }
                $response['err'] = false;
                $response['msg'] = "All Tasklists are ready to view !";
                $response['data'] = $data;
            } else {
                $response['msg'] = "There are no Tasklists found !";
            }
            echo json_encode($response, true);
        } catch (Exception $e) {
            $response['msg'] = "An error occurred: " . $e->getMessage();
        }
    } else {
        echo 'Method Not Allowed';
    }
}



function switch_task($id)
{
    global $pdo, $response, $method;
    $task_id = explode("/switch", explode("tasks/", $id[0])[1])[0];
    if ($method === "POST") {
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $headerParts = explode(' ', $_SERVER['HTTP_AUTHORIZATION']);
            if (count($headerParts) == 2 && $headerParts[0] == 'Bearer') {
                $accessToken = $headerParts[1];
                $user_info = json_decode(checkToken($accessToken), true);
                if ($user_info) {
                    $task_name      = getOneField("project_tasks", "task_name", "task_id = $task_id");
                    $task_desc      = getOneField("project_tasks", "task_desc", "task_id = $task_id");
                    $task_duration  = getOneField("project_tasks", "task_duration", "task_id = $task_id");
                    $tasklist_id    = getOneField("project_tasks", "tasklist_id", "task_id = $task_id");
                    $tasklist_name  = getOneField("project_tasklists", "tasklist_name", "tasklist_id = $tasklist_id");
                    $template_tasklist_id = getOneField("project_tasklists", "tasklist_id", "tasklist_name = '$tasklist_name' and is_template = true");
                    $new_tasklist_name  = null;
                    if (strpos($tasklist_name, "Structure")) {
                        $new_tasklist_name = str_replace("Structure", "Avionics", $tasklist_name);
                    } else {
                        $new_tasklist_name = str_replace("Avionics", "Structure", $tasklist_name);
                    }
                    $project_id = getOneField("project_tasklists", "project_id", "tasklist_id = $tasklist_id");
                    $new_tasklist_id = getOneField("project_tasklists", "tasklist_id", "tasklist_name = '$new_tasklist_name' and project_id = $project_id");
                    $new_template_id = getOneField("project_tasklists", "tasklist_id", "tasklist_name = '$new_tasklist_name' and is_template = true");
                    try {
                        if (is_null($new_tasklist_id) != 1) {
                            $sql = "INSERT INTO project_tasks (task_name,task_desc,task_duration,tasklist_id,task_status_id) 
                                VALUES ('$task_name', '$task_desc', $task_duration ,$new_tasklist_id, 1)";
                            $statement = $pdo->prepare($sql);
                            $statement->execute();

                            $sql2 = "UPDATE project_tasks SET
                                level_1 = IF(LENGTH(task_name) - LENGTH(REPLACE(task_name, '.', '')) >= 0, CAST(SUBSTRING_INDEX(task_name, '.', 1) AS UNSIGNED), NULL),
                                level_2 = IF(LENGTH(task_name) - LENGTH(REPLACE(task_name, '.', '')) >= 1, CAST(SUBSTRING_INDEX(SUBSTRING_INDEX(task_name, '.', 2), '.', -1) AS UNSIGNED), NULL),
                                level_3 = IF(LENGTH(task_name) - LENGTH(REPLACE(task_name, '.', '')) >= 2, CAST(SUBSTRING_INDEX(task_name, '.', -1) AS UNSIGNED), NULL)
                                WHERE tasklist_id = '$new_tasklist_id'    
                            ";
                            $statement2 = $pdo->prepare($sql2);
                            $statement2->execute();
                        }

                        if (is_null($new_template_id) != 1) {
                            $sql = "INSERT INTO project_tasks (task_name,task_desc,task_duration,tasklist_id,task_status_id) 
                                VALUES ('$task_name', '$task_desc', $task_duration ,$new_template_id, 1)";
                            $statement = $pdo->prepare($sql);
                            $statement->execute();
                            $sql2 = "UPDATE project_tasks SET
                                level_1 = IF(LENGTH(task_name) - LENGTH(REPLACE(task_name, '.', '')) >= 0, CAST(SUBSTRING_INDEX(task_name, '.', 1) AS UNSIGNED), NULL),
                                level_2 = IF(LENGTH(task_name) - LENGTH(REPLACE(task_name, '.', '')) >= 1, CAST(SUBSTRING_INDEX(SUBSTRING_INDEX(task_name, '.', 2), '.', -1) AS UNSIGNED), NULL),
                                level_3 = IF(LENGTH(task_name) - LENGTH(REPLACE(task_name, '.', '')) >= 2, CAST(SUBSTRING_INDEX(task_name, '.', -1) AS UNSIGNED), NULL)
                                WHERE tasklist_id = '$new_template_id'
                                ";
                            $statement2 = $pdo->prepare($sql2);
                            $statement2->execute();
                        }

                        $sql2 = "DELETE FROM project_tasks WHERE task_id = :task_id";
                        $statement2 = $pdo->prepare($sql2);
                        $statement2->bindParam(':task_id', $task_id);
                        $statement2->execute();

                        $sql2 = "DELETE FROM project_tasks WHERE tasklist_id = :template_tasklist_id AND task_name = :task_name";
                        $statement2 = $pdo->prepare($sql2);
                        $statement2->bindParam(':template_tasklist_id', $template_tasklist_id);
                        $statement2->bindParam(':task_name', $task_name);
                        $statement2->execute();

                        reOrderFromTasklist($tasklist_id);
                        reOrderFromTasklist($new_tasklist_id);
                        reOrderFromTasklist($template_tasklist_id);
                        reOrderFromTasklist($new_template_id);

                        $response['err'] = false;
                        $response['msg'] = "Task Change Department Succesfuly !";
                    } catch (Exception $e) {
                        // echo "Error Happend";
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
};



function reOrderFromTasklist($tasklist_id)
{
    global $pdo;
    if (is_null($tasklist_id) != 1) {
        $sql = "SELECT task_id,task_name FROM project_tasks WHERE tasklist_id = $tasklist_id ORDER BY level_1,level_2,level_3";
        $statement0 = $pdo->prepare($sql);
        $statement0->execute();
        if ($statement0->rowCount() > 0) {
            $index = 0;
            while ($el = $statement0->fetch(PDO::FETCH_ASSOC)) {
                $new = $index + 1;
                $task_name = $el['task_name'];
                $sql3 = "UPDATE project_tasks SET task_order = $new 
                WHERE task_name = '$task_name' AND tasklist_id = $tasklist_id";
                $statement3 = $pdo->prepare($sql3);
                $statement3->execute();
                $index = $new;
                echo $index;
            }
        }
    }
}


function update_desc($id)
{
    global $pdo, $response, $POST_data, $method;
    $task_id = explode("/redesc", explode("tasks/", $id[0])[1])[0];
    $field = 'task_desc';
    $new_desc = $POST_data['task_desc'];
    if (is_null($new_desc) == 1) {
        $new_desc = $POST_data['task_name'];
        $field  = 'task_name';
    }
    if ($method === "POST") {
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $headerParts = explode(' ', $_SERVER['HTTP_AUTHORIZATION']);
            if (count($headerParts) == 2 && $headerParts[0] == 'Bearer') {
                $accessToken = $headerParts[1];
                $user_info = json_decode(checkToken($accessToken), true);
                if ($user_info) {
                    $task_name      = getOneField("project_tasks", "task_name", "task_id = $task_id");
                    $tasklist_id    = getOneField("project_tasks", "tasklist_id", "task_id = $task_id");
                    $tasklist_name  = getOneField("project_tasklists", "tasklist_name", "tasklist_id = $tasklist_id");
                    $template_tasklist_id = getOneField("project_tasklists", "tasklist_id", "tasklist_name = '$tasklist_name' and is_template = true");
                    try {
                        $sql = "UPDATE project_tasks SET $field = '$new_desc' WHERE task_id = '$task_id'";
                        $statement = $pdo->prepare($sql);
                        $statement->execute();

                        $sql2 = "UPDATE project_tasks SET $field = '$new_desc' WHERE tasklist_id = '$template_tasklist_id' AND task_name = '$task_name'";
                        $statement2 = $pdo->prepare($sql2);
                        $statement2->execute();

                        if ($field == "task_name") {
                            $sql2 = "UPDATE project_tasks SET
                                level_1 = IF(LENGTH(task_name) - LENGTH(REPLACE(task_name, '.', '')) >= 0, CAST(SUBSTRING_INDEX(task_name, '.', 1) AS UNSIGNED), NULL),
                                level_2 = IF(LENGTH(task_name) - LENGTH(REPLACE(task_name, '.', '')) >= 1, CAST(SUBSTRING_INDEX(SUBSTRING_INDEX(task_name, '.', 2), '.', -1) AS UNSIGNED), NULL),
                                level_3 = IF(LENGTH(task_name) - LENGTH(REPLACE(task_name, '.', '')) >= 2, CAST(SUBSTRING_INDEX(task_name, '.', -1) AS UNSIGNED), NULL)
                                WHERE tasklist_id = '$tasklist_id'";
                            $statement2 = $pdo->prepare($sql2);
                            $statement2->execute();

                            $sql2 = "UPDATE project_tasks SET
                                level_1 = IF(LENGTH(task_name) - LENGTH(REPLACE(task_name, '.', '')) >= 0, CAST(SUBSTRING_INDEX(task_name, '.', 1) AS UNSIGNED), NULL),
                                level_2 = IF(LENGTH(task_name) - LENGTH(REPLACE(task_name, '.', '')) >= 1, CAST(SUBSTRING_INDEX(SUBSTRING_INDEX(task_name, '.', 2), '.', -1) AS UNSIGNED), NULL),
                                level_3 = IF(LENGTH(task_name) - LENGTH(REPLACE(task_name, '.', '')) >= 2, CAST(SUBSTRING_INDEX(task_name, '.', -1) AS UNSIGNED), NULL)
                                WHERE tasklist_id = '$template_tasklist_id'";
                            $statement2 = $pdo->prepare($sql2);
                            $statement2->execute();

                            reOrderFromTasklist($tasklist_id);
                            reOrderFromTasklist($template_tasklist_id);
                        }

                        $response['err'] = false;
                        $response['msg'] = "Task desc updated Succesfuly !";
                    } catch (Exception $e) {
                        // echo "Error Happend";
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
