<?php
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST");
header("Access-Control-Allow-Headers: Content-Type, Authorization");
header("Access-Control-Allow-Credentials: true");

if (isset($_FILES["files"])) {
    // Loop through each file
    $response = [
        'error' => true,
        'msg' => null,
        'data' => null,
    ];
    $files_url = [];
    $msgs = [];

    $fileCount = count($_FILES["files"]["name"]);
    for ($i = 0; $i < $fileCount; $i++) {
        $fileName = $_FILES["files"]["name"][$i];
        $fileTmpName = $_FILES["files"]["tmp_name"][$i];
        $fileSize = $_FILES["files"]["size"][$i];
        $fileError = $_FILES["files"]["error"][$i];
        $fileType = $_FILES["files"]["type"][$i];
        $imageFileType = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));
        $accepted_size = 20 * 1024 * 1024;
        $uploadOk = 1;
        $check = getimagesize($fileTmpName);
        if ($check === false) {
            array_push($msgs, "This is not img file : $fileName");
            $uploadOk = 0;
        }

        if ($fileSize > $accepted_size) {
            array_push($msgs, "Sorry, your file : $fileName is too large.");
            $uploadOk = 0;
        }

        if (
            $imageFileType != "jpg" && $imageFileType != "png" && $imageFileType != "jpeg"
            && $imageFileType != "gif"
        ) {
            array_push($msgs, "Sorry : $fileName , only JPG, JPEG, PNG & GIF files are allowed.");
            $uploadOk = 0;
        }

        // Check if file uploaded without errors
        if ($fileError === 0 && $uploadOk === 1) {
            // Specify upload directory
            $uploadDir = "./media/" . $_POST['media_url'] . "/";
            if (!is_dir("./media/" . $_POST['media_url'])) {
                mkdir($uploadDir, 0777, true);
            }
            // Generate unique filename to prevent overwriting existing files
            $unique_name = uniqid() . '_' . $fileName;
            $fileDestination = $uploadDir . $unique_name;
            // Move uploaded file from temporary location to specified destination
            if (move_uploaded_file($fileTmpName, $fileDestination)) {
                $response['error'] = false;
                $name = "media/" . $_POST['media_url'] . "/" . $unique_name;
                array_push($files_url, $name);
            } else {
                $response['error'] = true;
                array_push($msgs, "Error uploading file '$fileName'.<br>");
            }
        } else {
            array_push($msgs, "Error uploading file '$fileName': " . $_FILES["files"]["error"][$i] . "<br>");
        }
    }
    $response['msg'] = $msgs;
    $response['data'] = $files_url;
    echo json_encode($response);
} else {
    echo "No files uploaded.";
}
