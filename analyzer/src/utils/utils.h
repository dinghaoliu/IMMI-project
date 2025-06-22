#ifndef UTILS_H
#define UTILS_H

#include "include_llvm.h"
#include <iostream>
#include <set>
#include <mysql/mysql.h>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <filesystem>
#include "toml.hpp"
#include "typedef.h"
#include "utils_macro.h"
#include <omp.h>

#define SOUND_MODE 1

using namespace std;


namespace common {

    template<typename Tmap> 
    void printMap(Tmap map, int num=0) {
        for (auto p : map){
            cout << p.first << ":" << p.second << endl;
        }
    }// TODO: this is a very very very bad practice, try some delicate way

    template<typename Tstl> 
    void printSTL(Tstl stl, int num=0) {
        copy(stl.begin(), num ? next(stl.begin(), num) : stl.end(), 
            ostream_iterator<typename Tstl::value_type>(cout, " "));
        cout << "\n";
    }

    template<typename Type>
    set<Type> setIntersection(set<Type> set0, set<Type> set1) {
        set<Type> intersection;
        for (auto value : set0)
            if (set1.find(value) != set1.end())
                intersection.insert(value);
        return intersection;
    }

    template<typename LLType>
    string llobj_to_string(LLType* llobj) {
        string buffer;
        raw_string_ostream os(buffer);
        llobj->print(os);
        return os.str();
    }
}

namespace load {
    Module* loadModule(string file_path);
    int loadModules(vector<string>& inputFilenames, ModuleMap &module_map);
    int loadModules(cl::list<string>& inputFilenames, ModuleMap& module_map);
    int loadModules(string bclistFile, ModuleMap& module_map);
}

namespace config {
    using namespace toml;

    #define CONFIG_FILE "analyzer/src/configs/configs.toml"
    parse_result loadConfig(string path=CONFIG_FILE);
    // not supported
    node_view<node> getConfig(vector<string> keys, parse_result config);

    typedef struct {
        string host; string port; string username; string password; string dbname;
    } DatabaseCredential;

    DatabaseCredential get_mysql_credential();

    void setAllocFuncs(set<string> &allocFuncs);
    void setFreeFuncs(set<string> &freeFuncs);
    void setIcallIgnoreList(vector<string> &icallIgnoreFileLoc, vector<string> &icallIgnoreLineNum);
    void setDebugFuncs(set<string> &debugFuncs);
    void setHeapAllocFuncs(set<string> &heapAllocFuncs);


    // Setup functions that copy/move values. // <src, dst, size>
    static void SetCopyFuncs(map<string, tuple<int8_t, int8_t, int8_t>> &CopyFuncs) {
        //CopyFuncs["memcpy"] = make_tuple(1, 0, 2);
        //CopyFuncs["__memcpy"] = make_tuple(1, 0, 2);
        //CopyFuncs["strncpy"] = make_tuple(1, 0, 2);
        CopyFuncs["memmove"] = make_tuple(1, 0, 2);
        CopyFuncs["__memmove"] = make_tuple(1, 0, 2);
        CopyFuncs["llvm.memmove.p0i8.p0i8.i32"] = make_tuple(1, 0, 2);
        CopyFuncs["llvm.memmove.p0i8.p0i8.i64"] = make_tuple(1, 0, 2);
    }


} // namespace config

// mini tool, no exception but crash.
namespace timer {
    extern string boot_time;
    extern map<string, long int> recorder;
    long int now();
    string utcTime();
    void record(string key);
    void record(string key, long int time);
    void add(string key, long int time);
    long int get(string key1);
    long int diff(string key1, string key2);
}

namespace logging {
    using namespace spdlog;
        
    extern string log_prefix;
    extern shared_ptr<logger> global_log;
    extern shared_ptr<logger> exc_log;
    extern shared_ptr<logger> stdout_log;
    extern shared_ptr<logger> stderr_log;

    void setup_logger();
    shared_ptr<logger> register_logger(string name, level::level_enum level=level::info, string log_file="");
}



#endif