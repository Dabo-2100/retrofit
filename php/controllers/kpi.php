<?php
$endpoints += [
    '/api/kpi/\d+' => 'kpi',
];

function kpi($id)
{
    $sn_includes = htmlspecialchars(explode("/api/kpi/", $id[0])[1]);
    $aircraft_id = getOneField("aircrafts", "aircraft_id", "aircraft_serial_no Like '%$sn_includes%'");
    $project_id = getOneField("app_projects", "project_id", "aircraft_id = $aircraft_id");
    global $pdo, $response;
    try {
        $sql = "SELECT sb_part_id FROM sb_parts_applicability WHERE aircraft_id = :aircraft_id ";
        $statement = $pdo->prepare($sql);
        $statement->bindParam(':aircraft_id', $aircraft_id);
        $statement->execute();
        $data_report1 = $data = $data_report2 = [];
        if ($statement->rowCount() > 0) {
            while ($el = $statement->fetch(PDO::FETCH_ASSOC)) {

                $structure_duration = $avionics_duration = $structure_progress = $avionics_progress   = $avionics_actual_duration = $structure_actual_duration = $project_s_id
                    = $project_a_id = null;
                $part_id = $el['sb_part_id'];
                $part_name = getOneField("sb_parts", "part_name", "part_id = $part_id");
                $el['part_name'] = $part_name;
                $el['sb_no'] = explode(" | ", $part_name)[0];
                // Calculate Leonardo Issued Time
                $issued_duration = getOneField("sb_parts", "issued_duration", "part_id = $part_id");
                $el['issued_duration'] = $issued_duration;
                // Calculate The IPACO Estimated Time
                $template_s_id = getOneField("project_tasklists", "tasklist_id", "is_template = 1 AND tasklist_name = '$part_name [ Structure ]'");
                $template_a_id = getOneField("project_tasklists", "tasklist_id", "is_template = 1 AND tasklist_name = '$part_name [ Avionics ]'");
                if ($project_id != null) {
                    $project_s_id = getOneField("project_tasklists", "tasklist_id", "project_id = $project_id  AND tasklist_name = '$part_name [ Structure ]'");
                    $project_a_id = getOneField("project_tasklists", "tasklist_id", "project_id = $project_id  AND tasklist_name = '$part_name [ Avionics ]'");
                }


                if ($template_s_id != null) {
                    $structure_duration = getOneField("project_tasklists", "tasklist_duration", "tasklist_id = $template_s_id");
                    $structure_actual_duration = getTaskListActualDuration($template_s_id);
                }
                if ($template_a_id != null) {
                    $avionics_duration = getOneField("project_tasklists", "tasklist_duration", "tasklist_id = $template_a_id");
                }

                if ($project_s_id != null) {
                    $structure_actual_duration = getTaskListActualDuration($project_s_id);
                    $structure_progress = getTaskListProgress($project_s_id);
                }
                if ($project_a_id != null) {
                    $avionics_actual_duration = getTaskListActualDuration($project_a_id);
                    $avionics_progress  = getTaskListProgress($project_a_id);
                }
                $estimated_duration = $structure_duration + $avionics_duration;

                $actual_duration = $structure_actual_duration + $avionics_actual_duration;
                $el['estimated_duration'] = round($estimated_duration);
                $el['estimated_s_duration'] = round($structure_duration);
                $el['estimated_a_duration'] = round($avionics_duration);

                $el['actual_duration'] = round($actual_duration);
                $el['structure_actual_duration'] = round($structure_actual_duration);
                $el['avionics_actual_duration'] = round($avionics_actual_duration);

                $el['structure_progress'] = round($structure_progress);
                $el['avionics_progress'] = round($avionics_progress);

                $el['estimated_done_duration'] =
                    round(($structure_progress / 100 * $structure_duration) + ($avionics_progress / 100 * $avionics_duration));

                array_push($data_report1, $el);
            }
            $data['report_1'] = $data_report1;
            $data['report_2'] = $data_report2;
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
