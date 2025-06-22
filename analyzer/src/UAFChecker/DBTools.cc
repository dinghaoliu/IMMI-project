#include "UAFChecker.h"


void UAFCheckerPass::update_database(GlobalContext *Ctx,
    string bug_func_name, string cai_info, string func_code_info){

    const char *server = "localhost";
    const char *user = "pulutong";
    const char *pwd = "";
    const char *database = "bug_data";

    string table_name_bug = "bug_table_internal_inconsistent";

    string drop_table_bug = "drop table if exists " + table_name_bug;
    
    string create_table_bug = "create table " + table_name_bug;
    create_table_bug += "(id int auto_increment, ";
    create_table_bug += "bug_func_name varchar(70), ";
    create_table_bug += "cai_info varchar(200), ";
    create_table_bug += "func_info TEXT, ";
    create_table_bug += "GPT_result varchar(100), ";
    create_table_bug += "primary key(id));";

    MYSQL mysql;
    MYSQL *conn = mysql_init(&mysql);

    if(!mysql_real_connect(conn, server, user, pwd, database, 0, NULL, 0)){
        OP<<"WARNING: MYSQL connect failed!\n";
        OP<<mysql_error(conn);
        OP<<"\n";
        return;
    }

    //First clean the old table data
    if(mysql_query(conn, drop_table_bug.c_str())) {
        OP<<"Drop bug table failed\n";
        OP<<mysql_error(conn);
        OP<<"\n";
        return;
    }

    //Create a new table to record our data
    if(mysql_query(conn, create_table_bug.c_str())) {
        OP<<"Create bug table failed\n";
        OP<<mysql_error(conn);
        OP<<"\n";
        return;
    }

    //Insert new bug result
    string cmd = insert_internal_bug_table(Ctx, bug_func_name, cai_info, func_code_info);
    if(mysql_query(conn, cmd.c_str())) {
        OP<<"Insert bug_table_internal_inconsistent table failed\n";
        OP<<"cmd: "<<cmd<<"\n";
    }

    mysql_close(&mysql);
}

//Used to speed up database insert
string UAFCheckerPass::insert_internal_bug_table(GlobalContext *Ctx, 
    string bug_func_name, string cai_info, string func_code_info){
    
    stringstream insertss;
    insertss << "insert into bug_table_internal_inconsistent ";
    insertss << "(bug_func_name, cai_info, func_info, GPT_result) values ";

    insertss << "(";
    insertss << "\"" << bug_func_name <<"\",";
    insertss << "\"" << cai_info <<"\",";

    //Handle " here
    string func_code_info_converted = "";
    for(int i = 0; i < func_code_info.length(); i++){
        if(func_code_info[i] == '\"'){
            func_code_info_converted += "\\";
            func_code_info_converted += func_code_info[i];
        }
        else{
            func_code_info_converted += func_code_info[i];
        }
    }

    insertss << "\"" << func_code_info_converted <<"\",";
    insertss << "\"" << "None" <<"\"";
    insertss << ")";

    return insertss.str();

}

int UAFCheckerPass::init_database(DBInfo *db_info, MYSQL *mysql){
    
    const char *server = db_info->server.c_str();
    const char *user = db_info->user.c_str();
    const char *pwd = db_info->pw.c_str();
    const char *database = db_info->database.c_str();

    string table_name_bug = "bug_table_external_inconsistent";
    string table_name_func_info = "func_info_table";

    string drop_table_bug = "drop table if exists " + table_name_bug;
    string drop_table_func_info = "drop table if exists " + table_name_func_info;
    
    string create_table_bug = "create table " + table_name_bug;
    create_table_bug += "(id int auto_increment, ";
    create_table_bug += "caller_responsibility varchar(50), ";
    create_table_bug += "bug_func_name varchar(70), ";
    create_table_bug += "free_duty varchar(1000), ";
    create_table_bug += "call_chain varchar(100), ";
    create_table_bug += "BB_chain varchar(500), ";
    create_table_bug += "primary key(id));";

    string create_table_func_info = "create table " + table_name_func_info;
    create_table_func_info += "(id int auto_increment, ";
    create_table_func_info += "func_name varchar(70) UNIQUE, ";
    create_table_func_info += "func_info TEXT, ";
    create_table_func_info += "primary key(id));";

    MYSQL *conn = mysql_init(mysql);

    if(!mysql_real_connect(conn, server, user, pwd, database, 0, NULL, 0)){
        OP<<"WARNING: MYSQL connect failed!\n";
        OP<<mysql_error(conn);
        OP<<"\n";
        return -1;
    }

    //First clean the old table data
    if(mysql_query(conn, drop_table_bug.c_str())) {
        OP<<"Drop bug table 1 failed\n";
        OP<<mysql_error(conn);
        OP<<"\n";
        return -1;
    }

    //Create a new table to record our data
    if(mysql_query(conn, create_table_bug.c_str())) {
        OP<<"Create bug table 1 failed\n";
        OP<<mysql_error(conn);
        OP<<"\n";
        return -1;
    }

    if(mysql_query(conn, drop_table_func_info.c_str())) {
        OP<<"Drop bug table 2 failed\n";
        OP<<mysql_error(conn);
        OP<<"\n";
        return -1;
    }

    if(mysql_query(conn, create_table_func_info.c_str())) {
        OP<<"Create bug table 2 failed\n";
        OP<<mysql_error(conn);
        OP<<"\n";
        return -1;
    }

    OP<<"init database success\n";
    mysql_close(mysql);
    return 0;

}

int UAFCheckerPass::insert_func_info_table(DBInfo *db_info, 
    string bug_func_name, string func_code_info){

    const char *server = db_info->server.c_str();
    const char *user = db_info->user.c_str();
    const char *pwd = db_info->pw.c_str();
    const char *database = db_info->database.c_str();

    MYSQL mysql;
    MYSQL *conn = mysql_init(&mysql);

    if(!mysql_real_connect(conn, server, user, pwd, database, 0, NULL, 0)){
        OP<<"WARNING: MYSQL connect failed!\n";
        OP<<mysql_error(conn);
        OP<<"\n";
        return -1;
    }

    string cmd = "insert into func_info_table ";
    cmd += "(func_name, func_info) values ";
    cmd += "(";
    cmd += "\"";
    cmd += bug_func_name;
    cmd += "\",";

    //Handle " here
    string func_code_info_converted = "";
    for(int i = 0; i < func_code_info.length(); i++){
        if(func_code_info[i] == '\"'){
            func_code_info_converted += "\\";
            func_code_info_converted += func_code_info[i];
        }
        else{
            func_code_info_converted += func_code_info[i];
        }
    }

    cmd += "\"";
    cmd += func_code_info_converted;
    cmd += "\");";

    if(mysql_query(conn, cmd.c_str())) {
        OP<<"Insert func_info_table table failed\n";
        OP<<"cmd: "<<cmd<<"\n";
        OP<<mysql_error(conn);
        OP<<"\n";
    }

    mysql_close(&mysql);
    return 0;
}


int UAFCheckerPass::insert_bug_table(DBInfo *db_info,
    string caller_responsibility, string bug_func_name, 
    string cai_info, string call_chain, string bb_chain){
    
    const char *server = db_info->server.c_str();
    const char *user = db_info->user.c_str();
    const char *pwd = db_info->pw.c_str();
    const char *database = db_info->database.c_str();

    MYSQL mysql;
    MYSQL *conn = mysql_init(&mysql);

    if(!mysql_real_connect(conn, server, user, pwd, database, 0, NULL, 0)){
        OP<<"WARNING: MYSQL connect failed!\n";
        OP<<mysql_error(conn);
        OP<<"\n";
        return -1;
    }

    string cmd = "insert into bug_table_external_inconsistent ";
    cmd += "(caller_responsibility, bug_func_name, free_duty, call_chain, BB_chain) values ";
    cmd += "(";
    cmd += "\"";
    cmd += caller_responsibility;
    cmd += "\",";

    cmd += "\"";
    cmd += bug_func_name;
    cmd += "\",";

    cmd += "\"";
    cmd += cai_info;
    cmd += "\",";

    cmd += "\"";
    cmd += call_chain;
    cmd += "\",";

    cmd += "\"";
    cmd += bb_chain;
    cmd += "\");";


    if(mysql_query(conn, cmd.c_str())) {
        OP<<"Insert bug_table_external_inconsistent table failed\n";
        OP<<"cmd: "<<cmd<<"\n";
        OP<<mysql_error(conn);
        OP<<"\n";
    }

    mysql_close(&mysql);

    return 0;
}


int UAFCheckerPass::init_release_db(DBInfo *db_info){
    
    const char *server = db_info->server.c_str();
    const char *user = db_info->user.c_str();
    const char *pwd = db_info->pw.c_str();
    const char *database = db_info->database.c_str();

    string table_name_release = "release_summary_table";

    string drop_table_release = "drop table if exists " + table_name_release;
    
    string create_table_release = "create table " + table_name_release;
    create_table_release += "(id int auto_increment, ";
    create_table_release += "func_name varchar(70), ";
    create_table_release += "arg_id varchar(20), ";
    create_table_release += "release_summary varchar(8000), ";
    create_table_release += "primary key(id));";

    MYSQL mysql;
    MYSQL *conn = mysql_init(&mysql);

    if(!mysql_real_connect(conn, server, user, pwd, database, 0, NULL, 0)){
        OP<<"WARNING: MYSQL connect failed!\n";
        OP<<mysql_error(conn);
        OP<<"\n";
        return -1;
    }

    //First clean the old table data
    if(mysql_query(conn, drop_table_release.c_str())) {
        OP<<"Drop bug table 1 failed\n";
        OP<<mysql_error(conn);
        OP<<"\n";
        return -1;
    }

    //Create a new table to record our data
    if(mysql_query(conn, create_table_release.c_str())) {
        OP<<"Create bug table 1 failed\n";
        OP<<mysql_error(conn);
        OP<<"\n";
        return -1;
    }

    for(auto i : GlobalReleaseSummaryMap){

        string fname = i.first;

        for(auto j : i.second){
            int arg_id = j.first;

            string total_hash = "";
            for(auto hash : j.second){
                total_hash += hash;
                total_hash += "\n";
            }

            string cmd = "insert into release_summary_table ";
            cmd += "(func_name, arg_id, release_summary) values ";
            cmd += "(";
            cmd += "\"";
            cmd += fname;
            cmd += "\",";

            cmd += "\"";
            cmd += to_string(arg_id);
            cmd += "\",";

            cmd += "\"";
            cmd += total_hash;
            cmd += "\");";

            if(mysql_query(conn, cmd.c_str())) {
                OP<<"Insert release_summary_table table failed\n";
                OP<<"cmd: "<<cmd<<"\n";
                OP<<mysql_error(conn);
                OP<<"\n";
            }
        }
    }

    mysql_close(&mysql);
    return 0;

}