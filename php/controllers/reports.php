<?php
$endpoints += [
    '/api/reports/1/\d+' => 'report_1',
    '/api/reports/2/\d+' => 'report_2',
];

function report_1($id)
{
    $project_id = explode("/api/reports/1/", $id[0])[1];
    $aircraft_id = getOneField("app_projects", "aircraft_id", "project_id = $project_id");
    $aircraft_SN = getOneField("aircrafts", "aircraft_serial_no", "aircraft_id = $aircraft_id");
    global $pdo, $response;
    try {
        $sql = "SELECT sb_part_id FROM sb_parts_applicability WHERE aircraft_id = :aircraft_id ";
        $statement = $pdo->prepare($sql);
        $statement->bindParam(':aircraft_id', $aircraft_id);
        $statement->execute();
        $data = [];
        if ($statement->rowCount() > 0) {
            while ($el = $statement->fetch(PDO::FETCH_ASSOC)) {
                $part_id = $el['sb_part_id'];
                $part_name = getOneField("sb_parts", "part_name", "part_id = $part_id");
                $sb_name = explode(" | ", $part_name)[0];
                $sb_desc = getOneField("sbs", "sb_name", "sb_no = '$sb_name'");
                $issued_duration = getOneField("sb_parts", "issued_duration", "part_id = $part_id");
                // echo $sb_desc;
                // echo explode(" | ", $part_name)[0]."<br>";
                $template_s_id = getOneField("project_tasklists", "tasklist_id", "is_template = 1 AND tasklist_name = '$part_name [ Structure ]'");
                $template_a_id = getOneField("project_tasklists", "tasklist_id", "is_template = 1 AND tasklist_name = '$part_name [ Avionics ]'");
                $structure_duration = $avionics_duration = 0;

                if ($template_s_id != null) {
                    $structure_duration = getOneField("project_tasklists", "tasklist_duration", "tasklist_id = $template_s_id");
                }
                if ($template_a_id != null) {
                    $avionics_duration = getOneField("project_tasklists", "tasklist_duration", "tasklist_id = $template_a_id");
                }

                $recorded_s_id = getOneField("project_tasklists", "tasklist_id", "project_id = $project_id AND tasklist_name = '$part_name [ Structure ]'");
                $recorded_a_id = getOneField("project_tasklists", "tasklist_id", "project_id = $project_id AND tasklist_name = '$part_name [ Avionics ]'");

                $recorded_s_duration = $recorded_a_duration = 0;

                if ($recorded_s_id != null) {
                    $recorded_s_duration = (getTaskListProgress($recorded_s_id) / 100) * $structure_duration;
                }
                if ($recorded_a_id != null) {
                    $recorded_a_duration = (getTaskListProgress($recorded_a_id) / 100) * $avionics_duration;
                }

                $Row = [
                    'aircraft_sn' => $aircraft_SN,
                    'template_s_id' => $template_s_id,
                    'template_a_id' => $template_a_id,
                    'sb_no' => explode("|", $part_name)[0],
                    'sb_desc' => $sb_desc,
                    'issued_duration' => $issued_duration,
                    'sb_part_name' => $part_name,
                    'structure_duration' => $structure_duration,
                    'avionics_duration' => $avionics_duration,
                    'total_duration' => $structure_duration + $avionics_duration,
                    'done_duration_s' => $recorded_s_duration,
                    'done_duration_a' => $recorded_a_duration,
                ];
                array_push($data, $Row);
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
    echo json_encode($response, true);
}
