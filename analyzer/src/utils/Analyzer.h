#ifndef _ANALYZER_GLOBAL_H
#define _ANALYZER_GLOBAL_H

#include "include_llvm.h"
#include "typedef.h"
#include <map>
#include <unordered_map>
#include <set>
#include <string>
#include "utils.h"

using namespace std;

enum TypeAnalyzeResult{
    TypeEscape = 0,
    OneLayer = 1,
    TwoLayer = 2,
    ThreeLayer = 3,
    NoTwoLayerInfo = 4,
    MissingBaseType = 5,
    MixedLayer = 6,
};

enum AliasFailureReasons{
    none = 0,
    F_has_no_global_definition = 1,
    binary_operation = 2,
    llvm_used = 3,
    exceed_max = 4,
    success = 5,
    ignore_analysis = 6,
    inline_asm = 7,
    init_in_asm = 8,
};


struct GlobalContext {
    GlobalContext() {
        Modules.clear();
        LoopFuncs.clear();
    }

    vector<string> LeadKeywords;
    vector<string> FollowerKeywords;
    vector<string> FollowerStructKeywords;
    vector<string> IcallIgnoreFileLoc;
    vector<string> IcallIgnoreLineNum;

    // Map global function name to function defination.
    unordered_map<string, Function*> GlobalFuncs_old; // TODO lzp: save?
      NameFuncMap GlobalFuncs;
    NameFuncMap GlobalAllFuncs;
    map<size_t, Function*> Global_Unique_Func_Map;
    map<size_t, Function*> Global_Unique_All_Func_Map;
    map<size_t, set<GlobalValue*>> Global_Unique_GV_Map;
    set<Function*> Global_AddressTaken_Func_Set; // TODO lzp: save?

    // Functions whose addresses are taken.
    FuncSet AddressTakenFuncs;

    // Map a callsite to all potential callee functions.
    // CalleeMap Type: DenseMap<CallInst *, FuncSet>;
    // Given a call inst, find its definition function (1 is the best)
    CalleeMap Callees;

    // Map a function to all potential caller instructions.
    // CallerMap Type: DenseMap<Function*, CallInstSet>
    // Given a function pointer F, collect all of its call site
    CallerMap Callers;

    //Only record indirect call
    CallerMap ICallers;
    CalleeMap ICallees;

    // Indirect call instructions.
    vector<CallInst *>IndirectCallInsts;

    // Modules.
    ModuleMap Modules;

    // Pinter analysis results.
    FuncAAResultsMap FuncAAResults;

    /******SecurityCheck methods******/

    // Unified functions -- no redundant inline functions inline相关，研究一下 lzp todo
    DenseMap<size_t, Function *> UnifiedFuncMap;

    // Map function signature to functions
    DenseMap<size_t, FuncSet> sigFuncsMap;
    DenseMap<size_t, FuncSet> oneLayerFuncsMap;

    // SecurityChecksPass
    map<string, tuple<int8_t, int8_t, int8_t>> CopyFuncs;
    map<Function*, set<Loop*>> Global_Loop_Map;

    /******Path pair analysis methods******/
    set<Function*> LoopFuncs;
    set<string> HeapAllocFuncs;
    set<string> DebugFuncs;
    set<string> FreeFuncs;
    set<string> AllocFuncs;
    set<string> BinaryOperandInsts;

    /******Type Builder methods******/
    DenseMap<size_t, string> Global_Literal_Struct_Map; //map literal struct ('s hash) and its name
    DenseMap <size_t, FuncSet> Global_EmptyTy_Funcs;
    set<size_t> Global_Union_Set;
    map<Function*, set<size_t>> Global_Arg_Cast_Func_Map;

    /******icall methods******/
    unsigned long long icallTargets = 0;
    unsigned long long icallTargets_OneLayer = 0;
    unsigned long long icallNumber = 0;
    unsigned long long valid_icallNumber = 0;
    unsigned long long valid_icallTargets = 0;

    unsigned long long num_haveLayerStructName = 0;
    unsigned long long num_emptyNameWithDebuginfo = 0;
    unsigned long long num_emptyNameWithoutDebuginfo = 0;
    unsigned long long num_local_info_name = 0;
    unsigned long long num_array_prelayer = 0;
    unsigned long long num_escape_store = 0;

    unsigned long long num_typebuilder_haveStructName = 0;
    unsigned long long num_typebuilder_haveNoStructName = 0;

    /****** ICall Statistic Result ******/
    map <CallInst*, TypeAnalyzeResult> Global_MLTA_Result_Map;

    /****** Alias Statistic Result ******/
    map <AliasFailureReasons, size_t> failure_reasons;

    /****** Bug Detection Statistics ******/
    unsigned long long intro_inconsistency_bugs = 0;
    unsigned long long inter_inconsistency_host_free_bugs = 0;
    unsigned long long inter_inconsistency_missing_free_bugs = 0;
    unsigned long long inter_inconsistency_redundant_free_bugs = 0;

    //Debug info
    map<string, Type*> Global_Literal_Struct_Name_Map;
    map<Function *, map<Value *, Value *>>AliasStructPtrMap;
    unsigned long long Global_missing_type_def_struct_num = 0;
    int Global_pre_anon_icall_num = 0;
};

class IterativeModulePass {
    protected:
        GlobalContext *Ctx;
        const string ID;
        shared_ptr<spdlog::logger> logger;
        Module* current_module; // for debug
    public:
        IterativeModulePass(GlobalContext *Ctx_, const string ID_, shared_ptr<spdlog::logger> logger=nullptr)
            : Ctx(Ctx_), ID(ID_), logger(logger ? logger : logging::register_logger(ID_)) { }

        // Run on each module before iterative pass.
        virtual bool doInitialization(Module *M) { return true; }
        // Iterative pass.
        virtual bool doModulePass(Module *M) { return false; }
        // Run on each module after iterative pass.
        virtual bool doFinalization(Module *M) { return true; }

        virtual void run(ModuleMap &modules);
};

#endif
