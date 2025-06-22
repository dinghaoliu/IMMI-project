#include "UAFChecker.h"

//#define TEST_ONE_CASE ""

using namespace llvm;

map<Function*, set<int>> UAFCheckerPass::GlobalFreeFuncMap;
map<CallInst*, set<int>> UAFCheckerPass::GlobalFreeCallMap;
map<Value*, CallInst*> UAFCheckerPass::GlobalFreedValueMap;
map<Value*, CallInst*> UAFCheckerPass::GlobalFreedValueWrapperMap;
map<Value*, set<Function*>> UAFCheckerPass::GlobalFreeInfluenceMap;

map<Function*,map<Instruction*, BasicBlock*>> UAFCheckerPass::GlobalSimpleIfMap;

set<size_t> UAFCheckerPass::GlobalAnalyzedSet;

map<string, map<Value*, CallInst*>> UAFCheckerPass::GlobalFuncReleaseMap;

map<string, map<int,set<string>>> UAFCheckerPass::GlobalReleaseSummaryMap;
map<string, map<int,set<string>>> UAFCheckerPass::GlobalNullSummaryMap;
map<string, map<CallInst*, set<int>>> UAFCheckerPass::GlobalAnalyzedFuncMap;
map<string, map<int, vector<UAFCheckerPass::ReleaseSummary*>>> UAFCheckerPass::GlobalReleaseTransitMap;

map<Function*, UAFCheckerPass::EdgeErrMap> UAFCheckerPass::GlobalErrEdgeMap;
map<string, UAFCheckerPass::ReleaseDutySummary*> UAFCheckerPass::GlobalDutySummaryMap;

void UAFCheckerPass::identifyReleaseRange(Function *F, unsigned free_id, CallInst* free_cai) {
    //unique checking
    string fname = F->getName().str();
    if (GlobalAnalyzedFuncMap.count(fname) &&
        GlobalAnalyzedFuncMap[fname].count(free_cai) &&
        GlobalAnalyzedFuncMap[fname][free_cai].count(free_id)
    ) { return; }

    GlobalAnalyzedFuncMap[fname][free_cai].insert(free_id);

    vector<int> field_access_arr;
    bool is_nullified = false;
    int arg_pro_id = checkFreedValueComesFromArg(free_cai, field_access_arr, is_nullified, free_id);
    if(arg_pro_id < 0) { return; }

    string access_hash = "";
    for(auto i : field_access_arr){
        access_hash += to_string(i);
    }

    ReleaseSummary *RS = new ReleaseSummary(fname, arg_pro_id, free_cai, free_id, access_hash, is_nullified);
    GlobalReleaseTransitMap[fname][arg_pro_id].push_back(RS);

    //F's free_id-th arg could reach the freed value
    //check callers
    CallInstSet callers = Ctx->Callers[F];
    for(CallInst* caller_inst : callers){
        if (caller_inst->isIndirectCall()) { continue; } //ignore icall currently

        unsigned argNum = caller_inst->arg_size();
        if(F->arg_size() != argNum) { continue; }

        identifyReleaseRange(caller_inst->getFunction(), arg_pro_id, caller_inst);
    }

}

//Start from functions who call kfree, find all the wrappers
void UAFCheckerPass::identifyReleaseFuncs(Function *F){
    if(!F) return;

    for (Instruction& I : instructions(F)) {
        if (CallInst *CI = dyn_cast<CallInst>(&I)) {
            StringRef FName = getCalledFuncName(CI);
            if(!Ctx->FreeFuncs.count(FName.str())) { continue; }
            //Execute alias analysis
            Value* CAI_arg = CI->getArgOperand(0);
            unsigned free_id = 0;
            if(FName == "kmem_cache_free"){ //This function will free the 2rd arg
                CAI_arg = CI->getArgOperand(1);
                free_id = 1;
            }
            identifyReleaseRange(F, free_id, CI);
        }
    }
}


bool UAFCheckerPass::doInitialization(Module *M) {

    timer::record("uaf_init_start");

    //Find function wrappers for each function
    for(Function& F : *M) {
        if (F.empty()) continue;
        
#ifdef TEST_ONE_CASE
        if(F->getName()!= TEST_ONE_CASE){
            continue;
        }
#endif
        identifyReleaseFuncs(&F);

        if (Ctx->LoopFuncs.count(&F)) { continue; }

        //Record the return value of May_Return_Err block
        map<BasicBlock *,Value *> blockAttributeMap;

        //Return value check
        BBErrMap bbErrMap;
        set<BasicBlock *> normalblockSet;
        EdgeErrMap edgeErrMap;

        // Find and record basic blocks that set error returning code
        checkErrReturn(&F, bbErrMap, blockAttributeMap);
        for(auto& p : bbErrMap){
            BasicBlock* bb = p.first;
            int CV = p.second;

            if(CV == Not_Return_Err){
                bbErrMap[bb] = May_Return_Err;
                normalblockSet.insert(bb);
            }
        }

        // Find and record basic blocks that have error handling code
        Type* return_value_type = F.getReturnType();

        markAllEdgesErrFlag(&F, bbErrMap, edgeErrMap);
        
        for (auto& p : blockAttributeMap) {
            markCallCases(&F, p.second, edgeErrMap);
        }

        EdgeErrMap errEdgeMap;
        for (auto& p : edgeErrMap) {
            CFGEdge edge = p.first;
            //Found an error edge
            if(!checkEdgeErr(edge, edgeErrMap)){
                pair<CFGEdge,int> value(edge,1);
                errEdgeMap.insert(value);
            }
        }
        recurMarkErrEdges(errEdgeMap);
        GlobalErrEdgeMap[&F] = errEdgeMap;
    }

    timer::record("uaf_init_end");
    return false;
}


bool UAFCheckerPass::doModulePass(Module *M) {
    timer::record("uaf_dmp_start");

    //Summarize the global release relations
    static int once = 0;
    if(once == 0) {
        once++;
        logger->info("Begin summarize");
        logger->info("GlobalReleaseTransitMap size:{}", GlobalReleaseTransitMap.size());
        for(auto i : GlobalReleaseTransitMap){
            string fname = i.first;
            for(auto j : i.second){
                int f_arg_id = j.first;
                set<string> access_arr;
                set<string> nullification_arr;
                map<CallInst*, set<int>> analyzed_pairs;

                recurGetFieldAccessArr(fname, f_arg_id, "", access_arr, nullification_arr, analyzed_pairs, NULL);
                
                if(!access_arr.empty()){
                    GlobalReleaseSummaryMap[fname][f_arg_id] = access_arr;
                }

                if(!nullification_arr.empty()){
                    GlobalNullSummaryMap[fname][f_arg_id] = nullification_arr;
                }
            }
        }
        logger->info("Summarize success");
    }
    

    timer::record("uaf_dmp_end");

    for(Function& F : *M) {
        if (F.empty()) { continue; }
        
#ifdef TEST_ONE_CASE
        if(F.getName()!= TEST_ONE_CASE){
            continue;
        }
#endif

        if(Ctx->LoopFuncs.count(&F)) { continue; }
        dutyAnalyzer(&F);
    }

    timer::record("duty_analysis_end");
    timer::add("uaf_dmp", timer::diff("uaf_dmp_start", "uaf_dmp_end"));
    timer::add("duty_analysis", timer::diff("uaf_dmp_end", "duty_analysis_end"));

    return false;
}


bool UAFCheckerPass::doFinalization(Module *M) {
    static int once = 0;
    if(once == 0) {
        once++;
        timer::record("uaf_fin_start");
        dutyBugDetector();
        timer::record("uaf_fin_end");
    }
    return false;
}