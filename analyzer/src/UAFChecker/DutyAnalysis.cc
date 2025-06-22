#include "UAFChecker.h"

using namespace llvm;

Instruction* UAFCheckerPass::getArgStoreInst(CallInst *CI, 
    int &Arg_idx, string &field_access_arr) {
    
    if(!CI) { return nullptr; }
    
    Function *F = CI->getFunction();
    AliasContext* LocalAliasCtx = new AliasContext();
    map<int, Value*> arg_map;
    int arg_idx = -1;
    for(Argument& arg : F->args()){
        arg_idx++;
        Type *arg_type = arg.getType();
        if(arg_type->isPointerTy() || arg_type->isStructTy()){
            arg_map[arg_idx] = &arg;
        }
    }

    if (arg_map.empty()) { return nullptr; }

    bool found_tag = false;
    for (Instruction& I : instructions(F)) {
        HandleInst(&I, LocalAliasCtx, Ctx);

        if(&I == CI) { found_tag = true; }
        if(found_tag == false) { continue; }
        
        set<Value*> targetValueSet;
        getPreviousValues(CI, targetValueSet, LocalAliasCtx);
        for(auto p : arg_map){
            if(targetValueSet.count(p.second)){
                Arg_idx = p.first;

                AliasNode *n_arg = getNode(p.second, LocalAliasCtx);
                if(!n_arg) { return nullptr; }

                AliasNode *n_cai = getNode(CI, LocalAliasCtx);
                if(!n_cai) { return nullptr; }

                set<AliasNode*> analyzed_set;
                vector<int> access_arr;
                if(get_field_access_arr(LocalAliasCtx, n_arg, n_cai, access_arr, analyzed_set)){
                    for(auto i : access_arr){
                        field_access_arr += to_string(i);
                    }
                    return &I;
                }
                return nullptr;
            }
        }
    }
    return nullptr;
}

void UAFCheckerPass::getErrPath(EdgeErrMap errEdgeMap, BasicBlock *headBB, 
    vector<BasicBlock*> &path) {

    list<BasicBlock *> EB = {headBB}; //BFS record list
    set<BasicBlock *> PB; //Global value set to avoid loop

    while (!EB.empty()) {
        BasicBlock *TB = EB.front(); //Current checking block
        EB.pop_front();

        if (PB.count(TB))
            continue;
        PB.insert(TB);

        //Found a path
        bool found = false;
        for (auto p : errEdgeMap) {
            CFGEdge edge = p.first;
            Instruction* TI = edge.first;
            BasicBlock *firstBB = TI->getParent();
            BasicBlock *endBB = edge.second;

            if(firstBB == TB){
                found = true;
                path.push_back(TB);
                EB.push_back(endBB);
            }
        }
        if(!found) { path.push_back(TB); }
    }//end while
}

void UAFCheckerPass::getReturnCheckBlocks(CallInst* CI, set<BasicBlock*> &bb_set) {

    Function *F = CI->getFunction();
    AliasContext* LocalAliasCtx = new AliasContext();
    analyzeFunction(F, LocalAliasCtx, Ctx);

    AliasNode *n_cai = getNode(CI, LocalAliasCtx);
    if(!n_cai) { return; }
    
    for(auto v : n_cai->aliasclass)
        for(User *U : v->users())
            if(ICmpInst *ICI = dyn_cast<ICmpInst>(U))
                bb_set.insert(ICI->getParent());
}

void UAFCheckerPass::getFollowingErrPaths(Instruction* begin_I, 
    CallInst* CI, map<BasicBlock*, vector<BasicBlock*>> &err_path_map){

    Function *F = begin_I->getFunction();
    if(!GlobalErrEdgeMap.count(F)) { return; }
    
    EdgeErrMap errEdgeMap = GlobalErrEdgeMap[F];
    if(errEdgeMap.empty()) { return; }

    BasicBlock *returnBB = NULL;
    for (Instruction& I : instructions(F)) {
        if (ReturnInst *RI = dyn_cast<ReturnInst>(&I)) { 
            returnBB = RI->getParent(); 
        }
    }
    if(!returnBB) { return; }
    
    map<BasicBlock*, vector<BasicBlock*>> path_map;
    vector<BasicBlock*> current_path;
    for (auto p : errEdgeMap) {
        CFGEdge edge = p.first;
        Instruction* TI = edge.first;
        BasicBlock *firstBB = TI->getParent();
        BasicBlock *endBB = edge.second;
        
        bool is_lead = true;
        for (auto pp : errEdgeMap) {
            CFGEdge edge2 = pp.first;
            Instruction* TI2 = edge2.first;
            BasicBlock *firstBB2 = TI2->getParent();
            BasicBlock *endBB2 = edge2.second;
            if(endBB2 == firstBB){ // lzp : is that a bug? should be firstBB2?
                is_lead = false;
                break;
            }
        }

        if(is_lead){
            getErrPath(errEdgeMap, firstBB, current_path);
            BasicBlock* endBB = current_path.back();
            if(endBB != returnBB)
                continue;
            path_map[current_path.front()] = current_path;
            current_path.clear();
        }
    }

    BasicBlock* begin_I_bb = begin_I->getParent();
    set<BasicBlock*> bb_set;
    getReturnCheckBlocks(CI, bb_set);

    for(auto p : path_map){
        BasicBlock* headBB = p.first;
        if(bb_set.count(headBB))
            continue;
        if(checkBlockPairConnectivity(begin_I_bb, headBB)){
            err_path_map[headBB] = p.second;
        }
    }
}

void UAFCheckerPass::freeBehaviorAnalyzer(CallInst* CI, 
    map<BasicBlock*, vector<BasicBlock*>> err_path_map,
    int arg_idx, string access_hash){

    Function *F = CI->getFunction();
    
    //No following error paths
    //The caller need not to handle this case on failure
    if(err_path_map.empty()) { return; }

    AliasContext* LocalAliasCtx = new AliasContext();
    for (Instruction& I : instructions(F)) {
        HandleInst(&I, LocalAliasCtx, Ctx);
    }

    if (!getNode(F->getArg(arg_idx), LocalAliasCtx)) { return; }

    //Extract release summaries from the err paths
    map<BasicBlock*, set<string>> path_release_summary_map;
    map<BasicBlock*, set<string>> path_nullification_summary_map;
    for(auto p : err_path_map){
        set<string> path_release_summary_set;
        set<string> path_nullification_summary_set;
        vector<Instruction*> path_insts;
        BasicBlock* path_lead_bb = p.first;
        for(auto path_bb : p.second){
            for(Instruction& I : *path_bb){
                path_insts.push_back(&I);
                if(CallInst* CI = dyn_cast<CallInst>(&I)){
                    StringRef cai_name = getCalledFuncName(CI);
                    if(Ctx->FreeFuncs.count(cai_name.str())){
                        int callee_arg_id = 0;

                        //This API is special
                        if(cai_name == "kmem_cache_free"){
                            callee_arg_id = 1;
                        }

                        Value *freed_v = CI->getArgOperand(0);
                        AliasNode *n_cai = getNode(freed_v, LocalAliasCtx);
                        if(!n_cai) { continue; }

                        vector<int> field_access_arr;
                        bool is_nullified = false;
                        int arg_pro_id = checkFreedValueComesFromArg(CI, field_access_arr, is_nullified, callee_arg_id, LocalAliasCtx);
                        if(arg_pro_id != arg_idx) { continue; }

                        string access_hash = "";
                        for(auto i : field_access_arr){
                            access_hash += to_string(i);
                        }
                        if(access_hash == "") { continue; }
                        
                        path_release_summary_set.insert(access_hash);
                    } else if (GlobalReleaseSummaryMap.count(cai_name.str())) {
                        //OP<<"free CI: "<<*CI<<"\n";
                        map<int,set<string>> callee_free_summary = GlobalReleaseSummaryMap[cai_name.str()];
                        for(auto s : callee_free_summary){
                            int callee_arg_id = s.first;
                            if(callee_arg_id >= CI->arg_size()) { continue; }
                            
                            Value *freed_v = CI->getArgOperand(0);
                            AliasNode *n_cai = getNode(freed_v, LocalAliasCtx);
                            if(!n_cai) { continue; }

                            vector<int> field_access_arr;
                            bool is_nullified = false;
                            int arg_pro_id = checkFreedValueComesFromArg(CI, field_access_arr, is_nullified, callee_arg_id, LocalAliasCtx);
                            if(arg_pro_id != arg_idx) { continue; }

                            string access_hash = "";
                            for(auto i : field_access_arr){
                                access_hash += to_string(i);
                            }
                            if(access_hash == "") { continue; }
                            
                            access_hash.pop_back(); // lzp ??? what's this for
                            for(auto callee_access_hash : s.second){
                                string new_hash = access_hash + callee_access_hash;
                                path_release_summary_set.insert(new_hash);
                            }
                        }
                    }

                    if(GlobalNullSummaryMap.count(cai_name.str())){
                        map<int,set<string>> callee_nullification_summary = GlobalNullSummaryMap[cai_name.str()];
                        for(auto s : callee_nullification_summary){
                            int callee_arg_id = s.first;
                            if(callee_arg_id >= CI->arg_size()) { continue; }
                            
                            vector<int> field_access_arr;
                            bool is_nullified = false;
                            int arg_pro_id = checkFreedValueComesFromArg(CI, field_access_arr, is_nullified, callee_arg_id, LocalAliasCtx);
                            if(arg_pro_id != arg_idx) { continue; }
                            
                            string access_hash = "";
                            for(auto i : field_access_arr){
                                access_hash += to_string(i);
                            }
                            if(access_hash == "") { continue; }
                            
                            access_hash.pop_back();
                            for(auto callee_access_hash : s.second){
                                string new_hash = access_hash + callee_access_hash;
                                path_nullification_summary_set.insert(new_hash);
                            }
                        }
                    }
                }
            }
        }//end single path analysis

        //Then analyze whether the resource is nullified
        set<BasicBlock*> pre_path;
        AliasContext* PathAliasCtx = new AliasContext();
        set<CallInst*> path_calls;

        BasicBlock* entryBB = &F->getEntryBlock();
        if(recur_get_pre_path(path_lead_bb, pre_path, entryBB) != false){
            for(BasicBlock* bb : pre_path){
                for(Instruction& I : *bb){
                    HandleInst(&I, PathAliasCtx, Ctx, false);
                    if(CallInst *cai = dyn_cast<CallInst>(&I)){
                        path_calls.insert(cai);
                    }
                }
            }
        }
        
        for(auto I : path_insts){
            HandleInst(I, PathAliasCtx, Ctx, false);
            if(CallInst *cai = dyn_cast<CallInst>(I)){
                path_calls.insert(cai);
            }
        }

        AliasNode *n_freed_v = getNode(CI, PathAliasCtx);
        set<AliasNode*> previousNodeSet;
        //showGraph(PathAliasCtx);
        bool nulltag = false;
        if(n_freed_v){
            previousNodeSet.insert(n_freed_v);
            getPreviousNodes(n_freed_v, previousNodeSet, PathAliasCtx);
            for(auto n_freed_v : previousNodeSet)
                for(auto v : n_freed_v->aliasclass)
                    if(ConstantPointerNull* CNullPtr = dyn_cast<ConstantPointerNull>(v))
                        nulltag = true;
        }
        if(nulltag){
            path_nullification_summary_set.insert(access_hash);
            //continue;
        }
            
        //Only record resources that are released but not nullified,
        //but this is incorrect for internal inconsistancy analysis
        path_release_summary_map[p.first] = path_release_summary_set;
        path_nullification_summary_map[p.first] = path_nullification_summary_set;
    
    }//end all path analysis

    //Analyze the release behaviors
    bool freed_tag = false;
    bool no_freed_tag = false;
    bool freed_and_not_nullified_tag = false;
    set<BasicBlock*> free_bb_set;
    for(auto p : path_release_summary_map){
        if (p.second.count(access_hash)) {
            //Resource has been freed
            freed_tag = true;
            free_bb_set.insert(p.first);
            if(!path_nullification_summary_map[p.first].count(access_hash)){
                freed_and_not_nullified_tag = true;
            }         
        } else {
            //A simple refcount filter
            bool is_put_device = false;
            for (auto bb : err_path_map[p.first]) {
                for(Instruction& I : *bb){
                    if(CallInst* CI = dyn_cast<CallInst>(&I)){
                        StringRef cai_name = getCalledFuncName(CI);
                        if (cai_name == "put_device") {
                            is_put_device = true;
                        } else if (cai_name == "device_unregister"){
                            is_put_device = true;
                        } else if (cai_name == "kobject_put"){
                            is_put_device = true;
                        }
                    }
                }
            }
            if(is_put_device == false) { no_freed_tag = true; }
        }
    }

    if(freed_and_not_nullified_tag && !no_freed_tag){
        logger->info("all paths have free in: {0}", F->getName().str());
        //In this case, the caller should not free the same resource on failure
        if(GlobalDutySummaryMap.count(F->getName().str())){
            ReleaseDutySummary *RS = GlobalDutySummaryMap[F->getName().str()];
            RS->OnFailureNotReleaseDuty[arg_idx][access_hash] = CI;
            RS->OnSuccessReleaseDuty[arg_idx].insert(access_hash);
        }
        else{
            ReleaseDutySummary *RS = new ReleaseDutySummary();
            RS->callee_name = F->getName().str();
            RS->OnFailureNotReleaseDuty[arg_idx][access_hash] = CI;
            RS->OnSuccessReleaseDuty[arg_idx].insert(access_hash);
            RS->callers = Ctx->Callers[F];
            GlobalDutySummaryMap[F->getName().str()] = RS;
        }
    }

    if(!freed_and_not_nullified_tag && no_freed_tag){
        logger->info("all paths do not have free in: {0}", F->getName().str());
        if(GlobalDutySummaryMap.count(F->getName().str())){
            ReleaseDutySummary *RS = GlobalDutySummaryMap[F->getName().str()];
            RS->OnFailReleaseDuty[arg_idx][access_hash] = CI;
            RS->OnSuccessReleaseDuty[arg_idx].insert(access_hash);
        }
        else{
            ReleaseDutySummary *RS = new ReleaseDutySummary();
            RS->callee_name = F->getName().str();
            RS->OnFailReleaseDuty[arg_idx][access_hash] = CI;
            RS->OnSuccessReleaseDuty[arg_idx].insert(access_hash);
            RS->callers = Ctx->Callers[F];
            GlobalDutySummaryMap[F->getName().str()] = RS;
        }
    }

    if(freed_tag && no_freed_tag){
        //For this case, just report it as a bug: inner inconsistent
        logger->info("Some free but some do not in: {0}", F->getName().str());
        
        // Generate detailed bug report
        ofstream bug_report("analyzer/logs/Bug_Report.txt", ios::app);
        if(bug_report.is_open()){
            // Get current timestamp
            time_t now = time(0);
            char* time_str = ctime(&now);
            string timestamp(time_str);
            timestamp.pop_back(); // remove newline
            
            bug_report << "========================================\n";
            bug_report << "BUG REPORT - Intro-inconsistency\n";
            bug_report << "========================================\n";
            bug_report << "Timestamp: " << timestamp << "\n";
            bug_report << "Bug Type: Intro-Inconsistency\n";
            bug_report << "Function: " << F->getName().str() << "\n";
            bug_report << "Description: Heap memory allocated by instruction is freed in some error handling paths but not in others\n\n";
            
            // Get allocation instruction info
            bug_report << "Allocation Instruction:\n";
            bug_report << "  Location: " << getInstLineNo(CI) << "\n";
            bug_report << "  Instruction: ";
            
            // Convert LLVM instruction to string
            string inst_str;
            raw_string_ostream rso(inst_str);
            CI->print(rso);
            bug_report << inst_str << "\n\n";
            
            // Report paths that free the memory
            bug_report << "Error Handling Paths That FREE the Memory:\n";
            for(BasicBlock* bb : free_bb_set){
                bug_report << "  Path starting at: " << getBlockName(bb) << "\n";
                bug_report << "    Full path: ";
                for(BasicBlock* b : err_path_map[bb]){
                    bug_report << getBlockName(b) << " -> ";
                }
                bug_report << "END\n";
            }
            bug_report << "\n";
            
            // Report paths that do NOT free the memory
            bug_report << "Error Handling Paths That DO NOT FREE the Memory:\n";
            for(auto p : path_release_summary_map){
                if (!p.second.count(access_hash) && err_path_map.count(p.first)) {
                    bug_report << "  Path starting at: " << getBlockName(p.first) << "\n";
                    bug_report << "    Full path: ";
                    for(BasicBlock* b : err_path_map[p.first]){
                        bug_report << getBlockName(b) << " -> ";
                    }
                    bug_report << "END\n";
                }
            }
            
            bug_report << "\nImpact: This inconsistency can lead to memory leaks or UAF/double-free vulnerabilities\n";
            bug_report << "Recommendation: Ensure consistent memory management across all error handling paths\n";
            bug_report << "========================================\n\n";
            
            bug_report.close();
            
            // Increment bug counter
            Ctx->intro_inconsistency_bugs++;
        } else {
            logger->error("Failed to open Bug_Report.txt for writing");
        }
        
        //logger->info("Alloc: {0}", *CI);
        for(BasicBlock* bb : free_bb_set){
            string free_info = "--free at: " + getBlockName(bb);
            for(BasicBlock* b : err_path_map[bb]){
                if(b == bb) { continue; }
                free_info += " " + getBlockName(b);
            }
            logger->info(free_info);
        }
    }
}

void UAFCheckerPass::dutyAnalyzer(Function *F){
    for (Instruction& I : instructions(F)) {
        if(CallInst *CI = dyn_cast<CallInst>(&I)){
            string called_fname = getCalledFuncName(CI).str();

            if(!Ctx->AllocFuncs.count(called_fname) &&
               !Ctx->AllocFuncs.count("__" + called_fname)
            ) { continue; }

            //1. Check when the allocated value is stored to global (e.g., func arg)
            int arg_idx = -1;
            string field_access_arr = "";
            Instruction* begin_I = getArgStoreInst(CI, arg_idx, field_access_arr);
            if(!begin_I || field_access_arr == "" || arg_idx == -1) { continue; }

            //2. Get all err paths after begin_I
            map<BasicBlock*, vector<BasicBlock*>> err_path_map;
            getFollowingErrPaths(begin_I, CI, err_path_map);

            //3. Analyze the free behaviors of err paths
            freeBehaviorAnalyzer(CI, err_path_map, arg_idx, field_access_arr);
        }
    }

}