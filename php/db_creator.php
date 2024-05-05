<?php
// connect to the database
require_once('./db_config.php');

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
        (2,"SB_Updater",1),
        (3,"Connector_Check",1),
        (4,"Zone_Check",1),
        (5,"Users_Authority",1),
        (6,"Retrofit_Data",1),
        (7,"Projects",1),
        (8,"Daily_Attendance",1)
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
        (6,1,6,1,1),
        (7,1,7,1,1),
        (8,1,8,1,1)
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
        work_required   VARCHAR(255) NOT NULL,
        action_taken    VARCHAR(255) NOT NULL,
        is_active       BOOLEAN DEFAULT TRUE,
        created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_update     TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE (parent_form_id)
    )',

    // 'CREATE TABLE IF NOT EXISTS logs_3( 
    //     log_id              INT(20) AUTO_INCREMENT PRIMARY KEY,
    //     parent_form_id      INT,
    //     FOREIGN KEY (parent_form_id) REFERENCES app_forms(form_id),
    //     work_required       VARCHAR(255) NOT NULL,
    //     operator_code       VARCHAR(255) NOT NULL,
    //     work_hrs            VARCHAR(255) NOT NULL,
    //     has_operator        BOOLEAN DEFAULT TRUE,
    //     work_done           VARCHAR(255) NOT NULL,
    //     log_start_time      VARCHAR(255),
    //     log_start_Date      DATE,
    //     log_reason          VARCHAR(255),
    //     item_desc           VARCHAR(255),
    //     replace_item_desc   VARCHAR(255),
    //     item_sn             VARCHAR(255),
    //     item_pn             VARCHAR(255),
    //     replace_item_sn     VARCHAR(255),
    //     replace_item_pn     VARCHAR(255),
    //     log_comments        VARCHAR(255),
    //     inspector_id        INT,
    //     FOREIGN KEY (inspector_id) REFERENCES app_users(user_id),
    //     insection_date      DATE,
    //     action_taken        VARCHAR(255) NOT NULL,
    //     is_active           BOOLEAN DEFAULT TRUE,
    //     created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    //     last_update         TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    //     UNIQUE (parent_form_id)
    // )',
];
// execute SQL statements
foreach ($statements as $statement) {
    $pdo->exec($statement);
}
