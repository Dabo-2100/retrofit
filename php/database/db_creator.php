<?php
// connect to the database
require_once './database/db_config.php';

$options = [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::MYSQL_ATTR_INIT_COMMAND => 'SET NAMES utf8',
];

try {
    $pdo = new PDO("mysql:host=$host;dbname=$db;charset=UTF8", $user, $password, $options);
} catch (PDOException $e) {
    die($e->getMessage());
    exit();
}

$statements = [
    'CREATE TABLE IF NOT EXISTS app_roles( 
        role_id           INT(20) AUTO_INCREMENT PRIMARY KEY,
        role_name         VARCHAR(255) NOT NULL,
        created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_update       TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )',
    'INSERT IGNORE INTO app_roles (role_id,role_name) VALUES (1,"super"),(2,"admin"),(3,"user")',

    'CREATE TABLE IF NOT EXISTS app_apps( 
        app_id            INT(20) AUTO_INCREMENT PRIMARY KEY,
        app_name          VARCHAR(255) NOT NULL,
        app_logo_name     VARCHAR(255) NOT NULL,
        app_is_active     BOOLEAN DEFAULT FALSE,
        created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_update       TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )',
    'INSERT IGNORE INTO app_apps 
        (app_id,app_name,app_is_active) VALUES 
        (1,"Warehouse",1),
        (2,"Avionics",1),
        (3,"Aircraft_forms",1),
        (4,"Retrofit_Data",1),
        (5,"Projects",1),
        (6,"User Authority",1)
    ',

    'CREATE TABLE IF NOT EXISTS app_departments( 
        department_id      INT(20) AUTO_INCREMENT PRIMARY KEY,
        department_name    VARCHAR(255) NOT NULL,
        zoho_id            VARCHAR(255) NOT NULL,
        department_power   INT(20),
        created_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_update        TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )',
    'INSERT IGNORE INTO app_departments 
        (department_id,department_name,zoho_id,department_power) VALUES 
        (1,"Airframe","zcrm_6133467000000483533",5),
        (2,"Structure","zcrm_6133467000000483538",5),
        (3,"Avionics","zcrm_6133467000000483543",5),
        (4,"General","zcrm_6133467000000526005",5)
    ',

    'CREATE TABLE IF NOT EXISTS app_teams( 
        team_id           INT(20) AUTO_INCREMENT PRIMARY KEY,
        team_name         VARCHAR(255) NOT NULL,
        department_id     INT,
        FOREIGN KEY (department_id) REFERENCES app_departments(department_id),
        team_is_active    BOOLEAN DEFAULT TRUE,
        created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_update       TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )',
    'INSERT IGNORE INTO app_teams 
        (team_id,team_name,department_id,team_is_active) VALUES 
        (1,"Planning",4,1),
        (2,"Structure Team 1",2,1),
        (3,"Structure Team 2",2,1),
        (4,"Avionics Team 1",3,1),
        (5,"Avionics Team 2",3,1)
    ',

    'CREATE TABLE IF NOT EXISTS app_users( 
        user_id           INT(20) AUTO_INCREMENT PRIMARY KEY,
        user_email        VARCHAR(255) NOT NULL,
        user_name         VARCHAR(255) NOT NULL,
        user_password     VARCHAR(255) NOT NULL,
        user_token        VARCHAR(255) NOT NULL,
        user_vcode        VARCHAR(255) NOT NULL,
        team_id           INT,
        FOREIGN KEY (team_id) REFERENCES app_teams(team_id),
        user_is_active    BOOLEAN DEFAULT FALSE,
        created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_update       TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )',
    'INSERT IGNORE INTO app_users 
        (user_id,user_email,user_name,user_password,user_token,user_vcode,team_id,user_is_active) VALUES 
        (1,"a_fattah_m@icloud.com","Dabo","$2y$10$7dY18c5TR8j.MTfH2fMWTe3d/1botvUYTVnyu2.Hn3PtpSzD/WzGy","eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiMSIsInVzZXJfaXNfYWN0aXZlIjp0cnVlLCJpc19zdXBlciI6dHJ1ZX0.JPPhF9O49X0G8Jc-KhUN_42FcOHMkTN_ArBFk9VMBe4","1234",1,1)
    ',

    'CREATE TABLE IF NOT EXISTS app_user_authority( 
        log_id            INT(20) AUTO_INCREMENT PRIMARY KEY,
        user_id           INT,
        FOREIGN KEY (user_id) REFERENCES app_users(user_id),
        app_id            INT,
        FOREIGN KEY (app_id) REFERENCES app_apps(app_id),
        role_id           INT,
        FOREIGN KEY (role_id) REFERENCES app_roles(role_id),
        is_active         BOOLEAN DEFAULT FALSE,
        created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_update       TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )',
    'INSERT IGNORE INTO app_user_authority 
        (log_id,user_id,app_id,role_id,is_active) VALUES 
        (1,1,1,1,1),
        (2,1,2,1,1),
        (3,1,3,1,1),
        (4,1,4,1,1),
        (5,1,5,1,1),
        (6,1,6,1,1)
    ',

    'CREATE TABLE IF NOT EXISTS form_types( 
        type_id           INT(20) AUTO_INCREMENT PRIMARY KEY,
        type_name         VARCHAR(255) NOT NULL,
        is_active         BOOLEAN DEFAULT TRUE,
        created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_update       TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )',
    'INSERT IGNORE INTO form_types 
        (type_id,type_name,is_active) VALUES 
        (1,"Form 1001",1),
        (2,"Form 1002",1),
        (3,"Form 1003",1),
        (4,"Form 1004",1),
        (5,"Form 1003_B",1)
    ',

    'CREATE TABLE IF NOT EXISTS aircrafts( 
        aircraft_id             INT(20) AUTO_INCREMENT PRIMARY KEY,
        aircraft_serial_no      VARCHAR(255) NOT NULL,
        aircraft_contract_name  VARCHAR(255) NOT NULL,
        zoho_id                 VARCHAR(255) NOT NULL,
        created_at              TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_update             TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )',

    'CREATE TABLE IF NOT EXISTS app_forms( 
        form_id           INT(20) AUTO_INCREMENT PRIMARY KEY,
        form_order        INT(20),
        form_parent_id    INT,
        FOREIGN KEY (form_parent_id) REFERENCES app_forms(form_id),
        aircraft_id       INT,
        FOREIGN KEY (aircraft_id) REFERENCES aircrafts(aircraft_id),
        form_type_id      INT,
        FOREIGN KEY (form_type_id) REFERENCES form_types(type_id),
        form_date         DATE NOT NULL ,
        is_active         BOOLEAN DEFAULT TRUE,
        created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_update       TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE (aircraft_id, form_order,form_type_id)
    )',

    'CREATE TABLE IF NOT EXISTS logs_1( 
        log_id          INT(20) AUTO_INCREMENT PRIMARY KEY,
        form_id         INT,
        FOREIGN KEY (form_id) REFERENCES app_forms(form_id),
        1002_id         INT,
        FOREIGN KEY (1002_id) REFERENCES app_forms(form_id),
        log_date        DATE NOT NULL,
        originator_id   INT,
        FOREIGN KEY (originator_id) REFERENCES app_users(user_id),
        supervisor_id   INT,
        FOREIGN KEY (supervisor_id) REFERENCES app_users(user_id),
        work_required   VARCHAR(255) NOT NULL,
        action_taken    VARCHAR(255) NOT NULL,
        is_active       BOOLEAN DEFAULT TRUE,
        created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_update     TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE (form_id, 1002_id)
    )',

    'CREATE TABLE IF NOT EXISTS logs_2( 
        log_id              INT(20) AUTO_INCREMENT PRIMARY KEY,
        parent_form_id      INT,
        FOREIGN KEY (parent_form_id) REFERENCES app_forms(form_id),
        log_start_time      VARCHAR(255),
        log_start_Date      DATE,
        log_reason          VARCHAR(255),
        item_desc           VARCHAR(255),
        replace_item_desc   VARCHAR(255),
        item_sn             VARCHAR(255),
        item_pn             VARCHAR(255),
        replace_item_sn     VARCHAR(255),
        replace_item_pn     VARCHAR(255),
        log_comments        VARCHAR(255),
        inspector_id        INT,
        FOREIGN KEY (inspector_id) REFERENCES app_users(user_id),
        insection_date      DATE,
        work_required       VARCHAR(255) NOT NULL,
        action_taken        VARCHAR(255) NOT NULL,
        is_active           BOOLEAN DEFAULT TRUE,
        created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_update         TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE (parent_form_id)
    )',

    'CREATE TABLE IF NOT EXISTS app_warehouses( 
        warehouse_id        INT(20) AUTO_INCREMENT PRIMARY KEY,
        warehouse_name      VARCHAR(255),
        is_active           BOOLEAN DEFAULT TRUE,
        created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_update         TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE (warehouse_name)
    )',

    'CREATE TABLE IF NOT EXISTS warehouse_category( 
        category_id         INT(20) AUTO_INCREMENT PRIMARY KEY,
        category_name       VARCHAR(255),
        warehouse_id        INT,
        FOREIGN KEY (warehouse_id) REFERENCES app_warehouses(warehouse_id),
        is_active           BOOLEAN DEFAULT TRUE,
        created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_update         TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE (category_name)
    )',

    'CREATE TABLE IF NOT EXISTS warehouse_units( 
        unit_id             INT(20) AUTO_INCREMENT PRIMARY KEY,
        unit_name           VARCHAR(255),
        parent_unit_id      INT,
        FOREIGN KEY (parent_unit_id) REFERENCES warehouse_units(unit_id),
        warehouse_id      INT,
        FOREIGN KEY (warehouse_id) REFERENCES app_warehouses(warehouse_id),
        qty_in_parent_unit  INT,
        is_active           BOOLEAN DEFAULT TRUE,
        created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_update         TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE (unit_name)
    )',

    'CREATE TABLE IF NOT EXISTS warehouse_locations( 
        location_id         INT(20) AUTO_INCREMENT PRIMARY KEY,
        location_name       VARCHAR(255),
        warehouse_id        INT,
        FOREIGN KEY (warehouse_id) REFERENCES app_warehouses(warehouse_id),
        is_active           BOOLEAN DEFAULT TRUE,
        created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_update         TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE (location_name,warehouse_id)
    )',

    'CREATE TABLE IF NOT EXISTS warehouse_products( 
        product_id        INT(20) AUTO_INCREMENT PRIMARY KEY,
        product_pn        VARCHAR(255),
        product_name      VARCHAR(255),
        product_usa_pn    VARCHAR(255),
        category_id       INT,
        FOREIGN KEY (category_id) REFERENCES warehouse_category(category_id),
        warehouse_id       INT,
        FOREIGN KEY (warehouse_id) REFERENCES app_warehouses(warehouse_id),
        is_active         BOOLEAN DEFAULT TRUE,
        created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_update       TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE (product_pn)
    )',

    'CREATE TABLE IF NOT EXISTS warehouse_products_qty( 
        qty_id              INT(20) AUTO_INCREMENT PRIMARY KEY,
        product_id          INT,
        FOREIGN KEY (product_id) REFERENCES warehouse_products(product_id),
        unit_id             INT,
        FOREIGN KEY (unit_id) REFERENCES warehouse_units(unit_id),
        location_id         INT,
        FOREIGN KEY (location_id) REFERENCES warehouse_locations(location_id),
        aircraft_id         INT,
        FOREIGN KEY (aircraft_id) REFERENCES aircrafts(aircraft_id),
        qty_value           FLOAT,
        is_active           BOOLEAN DEFAULT TRUE,
        created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_update         TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )',

    'CREATE TABLE IF NOT EXISTS warehouse_qty_logs( 
        log_id              INT(20) AUTO_INCREMENT PRIMARY KEY,
        qty_id              INT,
        FOREIGN KEY (qty_id) REFERENCES warehouse_products_qty(qty_id),
        user_id             INT,
        FOREIGN KEY (user_id) REFERENCES app_users(user_id),
        log_value           FLOAT,
        log_type            VARCHAR(255),
        log_reason          VARCHAR(255),
        packing_list        VARCHAR(255),
        log_date            DATE NOT NULL,
        is_active           BOOLEAN DEFAULT TRUE,
        created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_update         TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )',

    'CREATE TABLE IF NOT EXISTS connector_types( 
        type_id             INT(20) AUTO_INCREMENT PRIMARY KEY,
        type_name           VARCHAR(255),
        created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_update         TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE (type_name)
    )',
    'INSERT IGNORE INTO connector_types 
        (type_id,type_name) VALUES 
        (1,"Cable Assembly"),
        (2,"Bus Terminator"),
        (3,"CB"),
        (4,"Connector"),
        (5,"Data Bus"),
        (6,"Diode"),
        (7,"Ground Stud"),
        (8,"Junction"),
        (9,"Plugin"),
        (10,"Relay Socket"),
        (11,"Splice"),
        (12,"Switch"),
        (13,"Terminal Board"),
        (14,"Wire")
    ',

    'CREATE TABLE IF NOT EXISTS app_connectors( 
        connector_id        INT(20) AUTO_INCREMENT PRIMARY KEY,
        connector_name      VARCHAR(255),
        type_id             INT,
        FOREIGN KEY (type_id) REFERENCES connector_types(type_id),
        created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_update         TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE (connector_name)
    )',

    'CREATE TABLE IF NOT EXISTS connectors_vs_tasks( 
        log_id              INT(20) AUTO_INCREMENT PRIMARY KEY,
        connector_id        INT,
        FOREIGN KEY (connector_id) REFERENCES app_connectors(connector_id),
        task_id             INT,
        FOREIGN KEY (task_id) REFERENCES sb_tasks(task_id),
        created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_update         TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )',

    'CREATE TABLE IF NOT EXISTS connectors_vs_aircrafts( 
        log_id              INT(20) AUTO_INCREMENT PRIMARY KEY,
        connector_id        INT,
        FOREIGN KEY (connector_id) REFERENCES app_connectors(connector_id),
        aircraft_id         INT,
        FOREIGN KEY (aircraft_id) REFERENCES aircrafts(aircraft_id),
        is_open             BOOLEAN DEFAULT FALSE,
        is_orignal          BOOLEAN DEFAULT TRUE,
        created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_update         TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )',

    // Projects App

    'CREATE TABLE IF NOT EXISTS project_status( 
        status_id               INT(20) AUTO_INCREMENT PRIMARY KEY,
        status_name             VARCHAR(255),
        status_color_code       VARCHAR(255),
        created_at              TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_update             TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE (status_name)
    )',

    'INSERT IGNORE INTO project_status 
        (status_id,status_name,status_color_code) VALUES 
        (1,"On Going","#528d64"),
        (2,"On Hold","#fbc11e"),
        (3,"Delayed","#e73434"),
        (4,"Done","#2cc8ba"),
        (5,"Waiting For SB","#fbc11e"),
        (6,"Waiting For Spare parts","#fbc11e"),
        (7,"Waiting For Installation","#fbc11e"),
        (8,"Waiting For Manpower","#fbc11e"),
        (9,"Waiting For Findings","#fbc11e")
    ',

    'CREATE TABLE IF NOT EXISTS app_projects( 
        project_id              INT(20) AUTO_INCREMENT PRIMARY KEY,
        project_name            VARCHAR(255),
        project_status_id       INT,
        FOREIGN KEY (project_status_id) REFERENCES project_status(status_id),
        project_start_date      DATE,
        project_end_date        DATE,
        project_completion_date DATE,
        project_duration        FLOAT DEFAULT 0,
        aircraft_id             INT,
        FOREIGN KEY (aircraft_id) REFERENCES aircrafts(aircraft_id),
        created_at              TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_update             TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )',

    'CREATE TABLE IF NOT EXISTS project_tasklists( 
        tasklist_id             INT(20) AUTO_INCREMENT PRIMARY KEY,
        tasklist_name           VARCHAR(255),
        project_id              INT,
        FOREIGN KEY (project_id) REFERENCES app_projects(project_id),
        tasklist_duration       FLOAT,
        is_template             BOOLEAN DEFAULT FALSE,
        tasklist_start_date     DATE,
        tasklist_end_date       DATE,
        tasklist_status_id      INT,
        FOREIGN KEY (tasklist_status_id) REFERENCES project_status(status_id),
        created_at              TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_update             TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )',

    'CREATE TABLE IF NOT EXISTS project_tasks( 
        task_id                 INT(20) AUTO_INCREMENT PRIMARY KEY,
        task_name               VARCHAR(255),
        task_desc               VARCHAR(255),
        task_team_id            INT,
        FOREIGN KEY (task_team_id) REFERENCES app_teams(team_id),
        task_order              INT(20),
        tasklist_id             INT,
        FOREIGN KEY (tasklist_id) REFERENCES project_tasklists(tasklist_id),
        task_progress           FLOAT,
        task_status_id          INT,
        FOREIGN KEY (task_status_id) REFERENCES project_status(status_id),
        task_duration           FLOAT,
        actual_duration         FLOAT,
        task_start_date         TIMESTAMP NULL,
        task_end_date           TIMESTAMP NULL,
        created_at              TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_update             TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE (tasklist_id,task_order)
    )',

    'CREATE TABLE IF NOT EXISTS task_comments( 
        comment_id              INT(20) AUTO_INCREMENT PRIMARY KEY,
        comment_name            VARCHAR(255),
        author_id               INT,
        FOREIGN KEY (author_id) REFERENCES app_users(user_id),
        task_id                 INT,
        FOREIGN KEY (task_id) REFERENCES project_tasks(task_id),
        created_at              TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_update             TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )',
];

// execute SQL statements
foreach ($statements as $statement) {
    $pdo->exec($statement);
}
