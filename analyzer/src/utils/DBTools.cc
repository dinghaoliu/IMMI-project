#include "DBTools.h"
#include "format.hh"

namespace mysql {

MYSQL* mysql_connect(string ip_address, string user_name, string password, string db_name, string port, string charset) {
    MYSQL* mysql = new MYSQL();
    mysql_init(mysql);
    mysql_set_character_set(mysql, charset.c_str());
    if (!mysql_real_connect(
        mysql, 
        ip_address.c_str(), 
        user_name.c_str(), 
        password.c_str(), 
        db_name.c_str(), 
        (unsigned int)stoi(port), 
        NULL, 
        0)) {
        ELOG->error("Connecting to Mysql {0}:{1} error: {2}", ip_address, port, mysql_error(mysql));
        return nullptr;
    }
    return mysql;
}

MYSQL* mysql_connect(string config_file) {
    ifstream config_f(config_file);
    nlohmann::json j_config;
    if (!config_f.good()) { return nullptr; }
    config_f >> j_config;
    return mysql_connect(
        j_config["ip_address"],
        j_config["user_name"],
        j_config["password"],
        j_config["db_name"],
        j_config["port"]
    );
}

MYSQL* mysql_connect(config::DatabaseCredential credential) {
    return mysql_connect(credential.host, credential.username, credential.password, credential.dbname, credential.port);
}

bool mysql_raw_query(MYSQL* mysql, const string& raw_query) {
    if (mysql_query(mysql, raw_query.c_str())) {
        ELOG->error("Mysql query error: {0} | {1}", raw_query, mysql_error(mysql));
        return false;
    }
    return true;
}

/*
{} => ""
{"1","2","3"} => "(1, 2, 3)" / "1, 2, 3"
*/
string __mysql_expend_columns(const vector<string>& vec, bool with_brackets=true) {
    if (vec.empty()) return "";
    string res = with_brackets ? "(" : "";
    for (string s : vec) res += (s + ", ");
    res.erase(res.end() - 2, res.end());
    res += with_brackets ? ")" : "";
    return res;
}

/*
{} => ""
{"1","2","3"} => "('1', '2', '3')"
*/
string __mysql_expend_values(const vector<string>& vec) {
    if (vec.empty()) return "";
    string res = "(";
    for (string s : vec) res += ("\'" + s + "\'" + ", ");
    res.erase(res.end() - 2, res.end());
    res += ")";
    return res;
}

bool mysql_create_table(MYSQL* mysql, string table_name, vector<string>& columns, vector<string>& pks, string tail) {
    vector<string> t_info(columns);
    t_info.insert(t_info.end(), pks.begin(), pks.end());
    string query = util::Format("CREATE TABLE {0} {1} {2};", table_name, __mysql_expend_columns(t_info), tail);
    return mysql_raw_query(mysql, query);
}

bool mysql_drop_table(MYSQL* mysql, string table_name) {
    string query = util::Format("DROP TABLE IF EXISTS {0};", table_name);
    return mysql_raw_query(mysql, query);
}

bool mysql_insert(MYSQL* mysql, string table, vector<string>& values) {
    string query = util::Format("INSERT INTO {0} VALUES {1};", 
        table, __mysql_expend_values(values));
    return mysql_raw_query(mysql, query);
}

bool mysql_insert(MYSQL* mysql, string table, vector<string>& columns, vector<string>& values) {
    string query = util::Format("INSERT INTO {0} {1} VALUES {2};", 
        table, __mysql_expend_columns(columns), __mysql_expend_values(values));
    return mysql_raw_query(mysql, query);
}

bool mysql_insert_batch(MYSQL* mysql, string table, vector<vector<string>>& values_vec) {
    vector<string> lines(values_vec.size());
    for (int i = 0; i < values_vec.size(); i++) {
        lines[i] = __mysql_expend_values(values_vec[i]);
    }
    string query = util::Format("INSERT INTO {0} VALUES {1};", 
        table, __mysql_expend_columns(lines, false));
    return mysql_raw_query(mysql, query);
}

/* the raw_res will be freed after success. */
MysqlResult* __raw_res_to_mysql_res(MYSQL* mysql, MYSQL_RES* raw_res, string table, bool map_result) {
    assert(raw_res == nullptr && "raw_res with nullptr");
    MysqlResult* res = new MysqlResult();
    if (map_result) {
        res->is_map_result = true;
        while (MYSQL_FIELD* field = mysql_fetch_fields(raw_res)) {
            res->headers.push_back(string(field->name));
        }

        int row_count = 0;
        while (MYSQL_ROW row = mysql_fetch_row(raw_res)) {
            map<string, string> *temp_map = new map<string, string>();
            for (int i = 0; i < res->headers.size(); i++) {
                (*temp_map)[res->headers[i]] = row[i];
            }
            res->data.push_back(*temp_map);
            row_count++;
        }    
    } else {
        res->is_row_result = true;
        int row_count = 0;
        unsigned int num_fields = mysql_num_fields(raw_res);
        while (MYSQL_ROW row = mysql_fetch_row(raw_res)) {
            vector<string>* r = new vector<string>();
            for (size_t i = 0; i < num_fields; i++) {
                r->push_back(row[i]);
            }
            res->rows.push_back(*r);
            row_count++;
        }        
    }
    mysql_free_result(raw_res);
    return res;
}

MysqlResult* mysql_select(MYSQL* mysql, string table, string limitation, bool map_result) {
    MysqlResult* res = new MysqlResult();
    string query = util::Format("SELECT * FROM {0} {1};", table, limitation); 
    if (!mysql_raw_query(mysql, query)) {
        return nullptr;
    }
    MYSQL_RES* raw_res = mysql_store_result(mysql);
    return __raw_res_to_mysql_res(mysql, raw_res, table, map_result);        
}

MysqlResult* mysql_select(MYSQL* mysql, string table, vector<string>& columns, string limitation, bool map_result) {
    MysqlResult* res = new MysqlResult();
    string selected_columns = __mysql_expend_columns(columns, false);
    string query = util::Format("SELECT {0} FROM {1} {2};", selected_columns, table, limitation); 
    if (!mysql_raw_query(mysql, query)) {
        return nullptr;
    }
    MYSQL_RES* raw_res = mysql_store_result(mysql);
    return __raw_res_to_mysql_res(mysql, raw_res, table, map_result);
}

void mysql_finish(MYSQL* mysql) {
    mysql_commit(mysql);
    mysql_close(mysql);
}

}
