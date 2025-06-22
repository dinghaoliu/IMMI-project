#include "utils/Analyzer.h"
#include "utils/utils.h"
#include "utils/Tools.h"
#include <spdlog/common.h>
#include <spdlog/fmt/bundled/color.h>
#include "utils/Errors.h"
#include "utils/Common.h"
#include "CallGraph/CallGraph.h"

#define BC_LIST "bc.list"
#define TEST_BC_LIST "analyzer/testfiles_for_pair/bc.list"

using namespace config;

GlobalContext GlobalCtx;

void IterativeModulePass::run(ModuleMap &modules) {}

Module* module_for_test(string module_path = "test_1.ll") {
    return load::loadModule(module_path);
}

map<string, Module*> modules_for_test(string bc_list = BC_LIST) {
    auto ret = map<string, Module*>();
    load::loadModules(bc_list, ret);
    return ret;
}

template<typename... Args>
void template_test(string format, Args&&... args) {
    string result = format + " ";
    ((result += to_string(args) + " "), ...);
}

void test_main(Module* M) {

}

int main(int argc, char* argv[]) {
    auto modules = modules_for_test();
    for (auto p : modules) {
        test_main(p.second);
    }

    return 0;
}