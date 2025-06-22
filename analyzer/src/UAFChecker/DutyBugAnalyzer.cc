#include "UAFChecker.h"

using namespace llvm;

/*
    The callee does not release the resource on failure
    In this case, the caller should release them on failure
    map<int, set<string>> OnFailReleaseDuty;

    The callee has released the resource on failure
    In this case, the caller should not release them on failure
    map<int, set<string>> OnFailureNotReleaseDuty;

    Record the caller should release which values on success of callee
    map<int, set<string>> OnSuccessReleaseDuty;
*/

void UAFCheckerPass::dutyBugDetector(){


    int num_OnFailReleaseDuty = 0;
    int num_OnFailureNotReleaseDuty = 0;
    int num_OnSuccessReleaseDuty = 0;
    int num_caller = 0;

    for(auto p : GlobalDutySummaryMap){
        string fname = p.first;
        ReleaseDutySummary* RS = p.second;
        auto OnFailReleaseDuty = RS->OnFailReleaseDuty;
        auto OnFailureNotReleaseDuty = RS->OnFailureNotReleaseDuty;
        auto OnSuccessReleaseDuty = RS->OnSuccessReleaseDuty;

        // OP<<"\nfname: "<<fname<<"\n";
        if(!OnFailReleaseDuty.empty()){
            // OP<<"OnFailReleaseDuty: \n";
            handleOnFailReleaseDuty(fname, OnFailReleaseDuty, RS->callers);
            num_OnFailReleaseDuty++;
        }

        if(!OnFailureNotReleaseDuty.empty()){
            // OP<<"OnFailureNotReleaseDuty: \n";
            handleOnFailureNotReleaseDuty(fname, OnFailureNotReleaseDuty, RS->callers);
            num_OnFailureNotReleaseDuty++;
        }

        if(!OnSuccessReleaseDuty.empty()){
            // OP<<"OnSuccessReleaseDuty: \n";
            num_OnSuccessReleaseDuty++;
        }
    }

    logger->info("num_OnFailReleaseDuty: {0}", num_OnFailReleaseDuty);
    logger->info("num_OnFailureNotReleaseDuty: {0}", num_OnFailureNotReleaseDuty);
    logger->info("num_OnSuccessReleaseDuty: {0}", num_OnSuccessReleaseDuty);
    logger->info("num_caller: {0}", num_caller);
    
    // mysql_close(&mysql);
}

bool UAFCheckerPass::getCaiFollowingErrPath(CallInst* CI, 
    vector<BasicBlock*> &err_path){
    
    Function *F = CI->getFunction();
    BasicBlock *CI_BB = CI->getParent();
    
    if(GlobalErrEdgeMap.count(F) == 0){
        //TODO: handle this case
        return true;
    }
    
    EdgeErrMap errEdgeMap = GlobalErrEdgeMap[F];
    if(errEdgeMap.size() == 0)
        return true;
    
    //dumpErrEdges(errEdgeMap);
    getErrPath(errEdgeMap, CI_BB, err_path);

    //If the path contains both paths after CI
    //we regard it as a false positive
    BasicBlock* cai_bb = CI->getParent();
    Instruction *TI = cai_bb->getTerminator();
    int num_succ = TI->getNumSuccessors();

    if(num_succ == 2){
        BasicBlock* succ1 = TI->getSuccessor(0);
        BasicBlock* succ2 = TI->getSuccessor(1);
        bool found1 = false;
        bool found2 = false;
        for(auto bb : err_path){
            if(bb == succ1)
                found1 = true;
            if(bb == succ2)
                found2 = true;
        }
        if(found1 && found2){
            return false;
        }
    }

    return true;
}

bool UAFCheckerPass::getAliasNodeAccessArr(AliasContext*aCtx, AliasNode *start, 
    AliasNode *end, string &access_hash){

    if(start == end){
        access_hash = "0";
        return true;
    }

    set<AliasNode*> previousNodeSet;
    previousNodeSet.clear();
    getPreviousNodes(start, previousNodeSet, aCtx);

    //In this case, end node is the parent node of start node
    if(previousNodeSet.count(end)){
        vector<int> field_access_arr;
        field_access_arr.clear();
        set<AliasNode*> analyzed_set;
        if(get_field_access_arr(aCtx, end, start, field_access_arr, analyzed_set)){
            string node_access_hash = "";
            for(auto i : field_access_arr){
                node_access_hash += to_string(i);
            }

            return true;
        }
        return false;
    }

    previousNodeSet.clear();
    getPreviousNodes(end, previousNodeSet, aCtx);

    //In this case, start node is the parent node of end node
    if(previousNodeSet.count(start)){
        vector<int> field_access_arr;
        field_access_arr.clear();
        set<AliasNode*> analyzed_set;
        if(get_field_access_arr(aCtx, start, end, field_access_arr, analyzed_set)){
            string node_access_hash = "";
            for(auto i : field_access_arr){
                node_access_hash += to_string(i);
            }
            //OP<<"node_access_hash: "<<node_access_hash<<"\n";
            access_hash = node_access_hash;
            return true;
        }
        return false;
    }


    return false;
}


void UAFCheckerPass::analyzePathFreeAction(AliasContext* actx, 
    Value* duty_value, set<string> duty_hash_set, 
    vector<BasicBlock*> path, set<string> &not_handled_hash_set,
    bool &is_host_free) {

    not_handled_hash_set = duty_hash_set;

    if(path.empty()) { return; }
    
    AliasNode *n_cai = getNode(duty_value, actx);
    if(!n_cai) { return; }
    
    set<string> released_hash_set;
    released_hash_set.clear();
    bool is_parent_freed = false;

    for(auto bb : path){
        for(Instruction& I : *bb){
            if(CallInst* CI = dyn_cast<CallInst>(&I)){
                StringRef cai_name = getCalledFuncName(CI);
                //Handle direct free
                if(Ctx->FreeFuncs.count(cai_name.str())){
                    int callee_arg_id = 0;
                    if(cai_name == "kmem_cache_free"){
                        callee_arg_id = 1;
                    }

                    Value *freed_v = CI->getArgOperand(callee_arg_id);
                    AliasNode *n_free = getNode(freed_v, actx);
                    if(!n_free) { continue; }

                    string access_hash = "";
                    if(!getAliasNodeAccessArr(actx, n_cai, n_free, access_hash)){
                        continue;
                    }

                    if(duty_hash_set.count(access_hash)){
                        duty_hash_set.erase(access_hash);
                        // all resources have been freed
                        if(duty_hash_set.empty()){
                            goto end_loop;
                        }
                    }

                    //The parent struct is freed
                    if(access_hash == "0"){
                        for(auto freed_hash : duty_hash_set){
                            if(freed_hash != "0"){
                                // OP<<"BUG: The parent struct is freed\n";
                                is_parent_freed = true;
                                goto end_loop;
                            }
                        }
                    }

                } else if(GlobalReleaseSummaryMap.count(cai_name.str())){
                    map<int, set<string>> callee_free_summary = GlobalReleaseSummaryMap[cai_name.str()];
                    for(auto s : callee_free_summary){
                        int callee_arg_id = s.first;
                        if(callee_arg_id >= CI->arg_size()) { continue; }
                        
                        set<string> callee_free_set = s.second;

                        Value *freed_v = CI->getArgOperand(callee_arg_id);
                        AliasNode *n_free = getNode(freed_v, actx);
                        if(!n_free) { continue; }

                        string access_hash = "";
                        if(getAliasNodeAccessArr(actx, n_cai, n_free, access_hash) == false){
                            continue;
                        }

                        if(access_hash == "0") {
                            for(auto freed_hash : callee_free_set) {
                                if(duty_hash_set.count(freed_hash)) {
                                    duty_hash_set.erase(freed_hash);
                                    // all resources have been freed
                                    if(duty_hash_set.empty()) {
                                        goto end_loop;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

end_loop:
    //loop end
    not_handled_hash_set = duty_hash_set;
    is_host_free = is_parent_freed;

    return;
}

void UAFCheckerPass::checkCaller_should_release(CallInst* caller_cai, int arg_id, 
    set<string> duty_resources, int max_execution_num, 
    vector<string> &call_chain, string cai_source){

    //Currently only handle direct call
    if(caller_cai->isIndirectCall()){
        return;
    }

    if(max_execution_num > 3)
        return;
    
    string duty_summary = "";
    duty_summary += to_string(arg_id);
    duty_summary += "\n";

    Function *cai_F = caller_cai->getFunction();
    //OP<<"\ncaller: "<<cai_F->getName()<<" "<<*caller_cai<<"\n";
    //OP<<"current recur layer: "<<max_execution_num<<"\n";
    //OP<<"arg_id: "<<arg_id<<"\n";

    for(auto s : duty_resources){
        duty_summary += s;
        duty_summary += "\n";
    }

    AliasContext* LocalAliasCtx = new AliasContext();        
    for (Instruction& I : instructions(cai_F)) {
        HandleInst(&I, LocalAliasCtx, Ctx);
    }
    
    Value* cai_arg = caller_cai->getArgOperand(arg_id);
    AliasNode *n_cai = getNode(cai_arg, LocalAliasCtx);
    if(!n_cai) { return; }

    //First check whether the caller's err path contains free
    vector<BasicBlock*> err_path;
    getCaiFollowingErrPath(caller_cai, err_path); //TODO: this implementation is not precise enough
    /*for(auto bb : err_path){
        OP<<getBlockName(bb)<<" ";
    }
    OP <<"\n";*/

    set<string> not_handled_hash_set;
    bool is_host_free = false;
    analyzePathFreeAction(LocalAliasCtx, cai_arg, duty_resources, err_path, not_handled_hash_set, is_host_free);
    if(is_host_free){

        string chain_str = "";
        for(auto s : call_chain){
            chain_str += s;
            chain_str += "\n";
            string func_code = "";
            if(getFuncFromName(s, func_code)){
                // insert_func_info_table(db_info, s, func_code);
                //write_func_info_to_logfile(s, func_code);
            }
        }

        string start_func = call_chain[0];
        // insert_bug_table(db_info, "caller_should_free", start_func,cai_source,chain_str, "host free");
        //write_bug_to_logfile("caller_missing_free", start_func, cai_source, chain_str, "host free");
        
        // Generate detailed bug report for Inter-inconsistency (host free case)
        ofstream bug_report("analyzer/logs/Bug_Report.txt", ios::app);
        if(bug_report.is_open()){
            // Get current timestamp
            time_t now = time(0);
            char* time_str = ctime(&now);
            string timestamp(time_str);
            timestamp.pop_back(); // remove newline
            
            bug_report << "========================================\n";
            bug_report << "BUG REPORT - Inter-inconsistency\n";
            bug_report << "========================================\n";
            bug_report << "Timestamp: " << timestamp << "\n";
            bug_report << "Bug Type: Inter-Inconsistency (Host Free)\n";
            bug_report << "Description: Memory allocated in callee is not released by callee, and caller releases parent structure instead of specific resource\n\n";
            
            // Allocation information
            bug_report << "Allocation Function: " << call_chain[0] << "\n";
            bug_report << "Allocation Source:\n" << cai_source << "\n";
            
            // Call chain information
            bug_report << "Call Chain (from allocation to problematic caller):\n";
            for(int i = 0; i < call_chain.size(); i++){
                bug_report << "  " << i+1 << ". " << call_chain[i];
                if(i == 0) bug_report << " (allocates memory)";
                else if(i == call_chain.size()-1) bug_report << " (frees parent structure)";
                bug_report << "\n";
            }
            bug_report << "\n";
            
            // Resource information
            bug_report << "Unfreed Resources:\n";
            for(auto resource : duty_resources){
                bug_report << "  - Resource hash: " << resource << "\n";
            }
            
            bug_report << "\nProblem: The caller frees the parent structure but not the specific allocated resource\n";
            bug_report << "Impact: This can lead to memory leaks as the specific resource is never freed\n";
            bug_report << "Recommendation: Either the callee should free the resource on failure, or the caller should free the specific resource instead of just the parent structure\n";
            bug_report << "========================================\n\n";
            
            bug_report.close();
            
            // Increment bug counter
            Ctx->inter_inconsistency_host_free_bugs++;
        } else {
            logger->error("Failed to open Bug_Report.txt for writing");
        }

        return;
    }

    if(not_handled_hash_set.empty()){
        // OP<<"caller has freed all resources\n\n";
        return;
    }

    //Now there are some resources have not been freed in the caller
    //Check whether the resources are freed in other paths
    /* OP<<"This caller does not release: \n";
    for(auto s : not_handled_hash_set){
        OP<<"duty: "<<s<<"\n";
        //getchar();
    }*/

    vector<BasicBlock*> all_path;
    if(GlobalErrEdgeMap.count(cai_F) == 0){
        return;
    }

    EdgeErrMap errEdgeMap = GlobalErrEdgeMap[cai_F];
    set<BasicBlock*> all_err_path_bb;
    for(auto p : errEdgeMap){
        CFGEdge edge = p.first;
        BasicBlock* firstbb = edge.first->getParent();
        BasicBlock* secondbb = edge.second;
        all_err_path_bb.insert(firstbb);
        all_err_path_bb.insert(secondbb);
    }

    /*for(Function::iterator b = cai_F->begin(); b != cai_F->end(); b++){
        BasicBlock * bb = &*b;
        all_path.push_back(bb);
    }*/
    for(auto bb : all_err_path_bb){
        all_path.push_back(bb);
    }
    /*OP<<"all err path:\n";
    for(auto bb : all_err_path_bb){
        OP<<getBlockName(bb)<<" ";
    }*/

    set<string> not_handled_hash_set2;
    analyzePathFreeAction(LocalAliasCtx, cai_arg, duty_resources, all_path, not_handled_hash_set2, is_host_free);
    if(not_handled_hash_set2.size() != not_handled_hash_set.size()){
        // OP<<"caller has freed in other path\n";
        for(auto s : not_handled_hash_set2){
            // OP<<"other path freed: "<<s<<"\n";
        }

        string chain_str = "";
        for(auto s : call_chain){
            chain_str += s;
            chain_str += "\n";
            string func_code = "";
            if(getFuncFromName(s, func_code)){
                // insert_func_info_table(db_info, s, func_code);
                // write_func_info_to_logfile(s, func_code);
            }
        }

        string start_func = call_chain[0];
        // insert_bug_table(db_info, "caller_missing_free", start_func,cai_source,chain_str, "");
        // write_bug_to_logfile("caller_should_free", start_func, cai_source, chain_str, "");
        
        // Generate detailed bug report for Inter-inconsistency (missing free case)
        ofstream bug_report("analyzer/logs/Bug_Report.txt", ios::app);
        if(bug_report.is_open()){
            // Get current timestamp
            time_t now = time(0);
            char* time_str = ctime(&now);
            string timestamp(time_str);
            timestamp.pop_back(); // remove newline
            
            bug_report << "========================================\n";
            bug_report << "BUG REPORT - Inter-inconsistency\n";
            bug_report << "========================================\n";
            bug_report << "Timestamp: " << timestamp << "\n";
            bug_report << "Bug Type: Inter-Inconsistency (Missing Free)\n";
            bug_report << "Description: Memory allocated in callee is not released by callee on failure, and caller also fails to release it in error handling paths\n\n";
            
            // Allocation information
            bug_report << "Allocation Function: " << call_chain[0] << "\n";
            bug_report << "Allocation Source:\n" << cai_source << "\n";
            
            // Call chain information
            bug_report << "Call Chain (from allocation to problematic caller):\n";
            for(int i = 0; i < call_chain.size(); i++){
                bug_report << "  " << i+1 << ". " << call_chain[i];
                if(i == 0) bug_report << " (allocates memory)";
                else if(i == call_chain.size()-1) bug_report << " (should free but doesn't)";
                bug_report << "\n";
            }
            bug_report << "\n";
            
            // Resource information
            bug_report << "Unfreed Resources:\n";
            for(auto resource : not_handled_hash_set2){
                bug_report << "  - Resource hash: " << resource << "\n";
            }
            
            // Path analysis
            bug_report << "Analysis:\n";
            bug_report << "  - Caller has freed the resource in some paths but NOT in error handling paths\n";
            bug_report << "  - The resource remains allocated and is never freed in error scenarios\n";
            
            bug_report << "\nProblem: Inconsistent memory management between different execution paths\n";
            bug_report << "Impact: This leads to memory leaks when errors occur during execution\n";
            bug_report << "Recommendation: Ensure the caller consistently frees the resource in ALL error handling paths, or modify the callee to handle cleanup on failure\n";
            bug_report << "========================================\n\n";
            
            bug_report.close();
            
            // Increment bug counter
            Ctx->inter_inconsistency_missing_free_bugs++;
        } else {
            logger->error("Failed to open Bug_Report.txt for writing");
        }
        
        return;
    }
    
    //Check callers
    // OP<<"need caller check\n";
    vector<int> field_access_arr;
    bool is_nullified = false;
    int arg_pro_id = checkFreedValueComesFromArg(caller_cai, field_access_arr, is_nullified, arg_id);
    if(arg_pro_id < 0){
        // OP<<"invalid arg number\n";
        return;
    }

    string access_hash = "";
    for(auto i : field_access_arr){
        access_hash += to_string(i);
    }
    // OP<<"access_hash: "<<access_hash<<"\n";
    access_hash.pop_back();

    set<string> caller_duty_resources;
    for(auto s : duty_resources){
        s = access_hash + s;
        caller_duty_resources.insert(s);
    }

    CallInstSet callset = Ctx->Callers[cai_F];
    for(auto it = callset.begin(); it != callset.end(); it++){
        CallInst* caller = *it;
        string caller_func_name = caller->getFunction()->getName().str();
        if(caller_func_name == cai_F->getName())
            continue;

        call_chain.push_back(caller->getFunction()->getName().str());
        checkCaller_should_release(caller, arg_pro_id, caller_duty_resources, max_execution_num+1, call_chain, cai_source);
        call_chain.pop_back();

    }
}

//The caller should just release the resource once the caller cai failed
void UAFCheckerPass::handleOnFailReleaseDuty(string fname, 
    map<int, map<string, CallInst*>> dutySum, CallInstSet callers){

    static int freed_callers = 0;

    //OP<<"\n\033[34m" << "fname: "<<fname <<"\033[0m" <<"\n";
    //OP<<"OnFailReleaseDuty: \n";

    
    int callee_idx = 0;
    for(auto p2 : dutySum){
        //OP<<"--idx: "<<p2.first<<"\n";
        callee_idx = p2.first;
        for(auto hash : p2.second){
            //OP<<"---- "<<hash.first<<"\n";
        }
    }

    set<string> duty_resources;
    string cai_str = "";
    for(auto p : dutySum[callee_idx]){
        duty_resources.insert(p.first);
        // cai_str += getSourceLine(p.second) + "\n";
        
        // Get line number and LLVM instruction string
        cai_str += to_string(getInstLineNo(p.second)) + ": ";
        string inst_str;
        raw_string_ostream rso(inst_str);
        p.second->print(rso);
        cai_str += inst_str + "\n";
    }
    
    //Almost all callers' size is 1
    if(dutySum.size() > 1) { return; }

    vector<string> call_chain;
    call_chain.push_back(fname);
    for(auto cai : callers){
        call_chain.push_back(cai->getFunction()->getName().str());
        checkCaller_should_release(cai, callee_idx, duty_resources, 1, call_chain, cai_str);
        call_chain.pop_back();
    }//caller checking loop
}

void UAFCheckerPass::checkCaller_should_not_release(CallInst* caller_cai, int arg_id, 
    set<string> duty_resources, int max_execution_num, vector<string> &call_chain, string cai_source){

    //Currently only handle direct call
    if(caller_cai->isIndirectCall()){
        return;
    }

    if(max_execution_num > 3)
        return;

    string duty_summary = "";
    duty_summary += to_string(arg_id);
    duty_summary += "\n";

    Function *cai_F = caller_cai->getFunction();
    for(auto s : duty_resources){
        duty_summary += s;
        duty_summary += "\n";
    }

    AliasContext* LocalAliasCtx = new AliasContext();        
    for (Instruction& I : instructions(cai_F)) {
        HandleInst(&I, LocalAliasCtx, Ctx);
    }
    
    Value* cai_arg = caller_cai->getArgOperand(arg_id);
    AliasNode *n_cai = getNode(cai_arg, LocalAliasCtx);
    if(!n_cai){
        return;
    }

    //First check whether the caller's err path contains free
    vector<BasicBlock*> err_path, new_err_path;
    bool ret = getCaiFollowingErrPath(caller_cai, err_path);
    if(ret == false){
        for(auto it = err_path.begin(); it != err_path.end(); it++){
            if(*it == caller_cai->getParent()){
                continue;
            }
            new_err_path.push_back(*it);
        }
        return;
    }
    
    for(auto it = err_path.begin(); it != err_path.end(); it++){
        if(*it == caller_cai->getParent()){
            continue;
        }
        new_err_path.push_back(*it);
    }


    for(auto bb : new_err_path){
        // OP<<getBlockName(bb)<<" ";
    }

    set<string> not_handled_hash_set;
    bool is_host_free = false;
    analyzePathFreeAction(LocalAliasCtx, cai_arg, duty_resources, new_err_path, not_handled_hash_set, is_host_free);
    if(is_host_free){
        return;
    }
    if(not_handled_hash_set.size() == duty_resources.size()){

        //Check wthether the resources are freed in other paths
        vector<BasicBlock*> all_path, new_err_path2;
        if(GlobalErrEdgeMap.count(cai_F) == 0){
            return;
        }

        EdgeErrMap errEdgeMap = GlobalErrEdgeMap[cai_F];
        set<BasicBlock*> all_err_path_bb;
        for(auto p : errEdgeMap){
            CFGEdge edge = p.first;
            BasicBlock* firstbb = edge.first->getParent();
            BasicBlock* secondbb = edge.second;
            all_err_path_bb.insert(firstbb);
            all_err_path_bb.insert(secondbb);
        }

        for(auto bb : all_err_path_bb){
            all_path.push_back(bb);
        }
        for(auto it = all_path.begin(); it != all_path.end(); it++){
            if(*it == caller_cai->getParent()){
                continue;
            }
            new_err_path2.push_back(*it);
        }

        set<string> not_handled_hash_set2;
        analyzePathFreeAction(LocalAliasCtx, cai_arg, duty_resources, new_err_path2, not_handled_hash_set2, is_host_free);
        if(not_handled_hash_set2.size() != not_handled_hash_set.size()){
            // OP<<"caller has freed in other path\n";
            return;
        }

        //Check callers
        vector<int> field_access_arr;
        bool is_nullified = false;
        int arg_pro_id = checkFreedValueComesFromArg(caller_cai, field_access_arr, is_nullified, arg_id);
        if(arg_pro_id < 0){
            // OP<<"invalid arg number\n";
            return;
        }

        string access_hash = "";
        for(auto i : field_access_arr){
            access_hash += to_string(i);
        }
        access_hash.pop_back();

        set<string> caller_duty_resources;
        for(auto s : duty_resources){
            s = access_hash + s;
            caller_duty_resources.insert(s);
        }

        CallInstSet callset = Ctx->Callers[cai_F];
        for(auto it = callset.begin(); it != callset.end(); it++){
            CallInst* caller = *it;
            string caller_func_name = caller->getFunction()->getName().str();
            if(caller_func_name == cai_F->getName())
                continue;

            call_chain.push_back(caller->getFunction()->getName().str());
            checkCaller_should_not_release(caller, arg_pro_id, caller_duty_resources, max_execution_num+1, call_chain, cai_source);
            call_chain.pop_back();
        }
        return;
    }

    //Check whether the caller is inside a loop
    for(Loop *LP : Ctx->Global_Loop_Map[cai_F]){
        vector<BasicBlock*> loop_bbs = LP->getBlocks();
        for(auto bb : loop_bbs){
            if(bb == caller_cai->getParent()){
                // OP<<"caller is inside a loop\n";
                return;
            }
        }
    }

    //Check the error path
    // OP<<"we may have a bug\n";
    // OP<<"Release values: \n";
    for(auto s : duty_resources){
        if(not_handled_hash_set.count(s))
            continue;
        // OP<<"--s: "<<s<<"\n";
    }

    //Log the result
    string start_func = call_chain[0];

    string bb_chain = "";
    for(auto bb : new_err_path){
        bb_chain += getBlockName(bb);
        bb_chain += " ";
    }

    string chain_str = "";
    for(auto s : call_chain){
        chain_str += s;
        chain_str += "\n";
        string func_code = "";
        if(getFuncFromName(s, func_code)){
            // insert_func_info_table(db_info, s, func_code);
            // write_func_info_to_logfile(s, func_code);
        }
    }

    // insert_bug_table(db_info, "caller_cannot_free", start_func,cai_source,chain_str, bb_chain);
    // write_bug_to_logfile("caller_has_redundant_free", start_func, cai_source, chain_str, bb_chain);
    
    // Generate detailed bug report for Inter-inconsistency (redundant free case)
    ofstream bug_report("analyzer/logs/Bug_Report.txt", ios::app);
    if(bug_report.is_open()){
        // Get current timestamp
        time_t now = time(0);
        char* time_str = ctime(&now);
        string timestamp(time_str);
        timestamp.pop_back(); // remove newline
        
        bug_report << "========================================\n";
        bug_report << "BUG REPORT - Inter-inconsistency\n";
        bug_report << "========================================\n";
        bug_report << "Timestamp: " << timestamp << "\n";
        bug_report << "Bug Type: Inter-Inconsistency (Redundant Free)\n";
        bug_report << "Description: Memory allocated in callee is already released by callee on failure, but caller also attempts to release it\n\n";
        
        // Allocation information
        bug_report << "Allocation Function: " << call_chain[0] << "\n";
        bug_report << "Allocation Source:\n" << cai_source << "\n";
        
        // Call chain information
        bug_report << "Call Chain (from allocation to problematic caller):\n";
        for(int i = 0; i < call_chain.size(); i++){
            bug_report << "  " << i+1 << ". " << call_chain[i];
            if(i == 0) bug_report << " (allocates and frees memory on failure)";
            else if(i == call_chain.size()-1) bug_report << " (redundantly frees already-freed memory)";
            bug_report << "\n";
        }
        bug_report << "\n";
        
        // Resource information
        bug_report << "Resources Involved:\n";
        for(auto resource : duty_resources){
            bug_report << "  - Resource hash: " << resource << "\n";
        }
        
        // Path information
        bug_report << "\nError Handling Path (where redundant free occurs):\n";
        bug_report << "  Path: " << bb_chain << "\n";
        
        // Freed resources analysis
        bug_report << "Resources NOT Handled by Caller in Error Path:\n";
        for(auto resource : not_handled_hash_set){
            bug_report << "  - " << resource << " (caller attempts to free this despite callee already freeing it)\n";
        }
        
        bug_report << "\nProblem: The callee already handles resource cleanup on failure, but the caller performs additional cleanup\n";
        bug_report << "Impact: This leads to UAF (Use-After-Free) or double-free vulnerabilities\n";
        bug_report << "Recommendation: Remove the redundant free operations in the caller, or modify the callee to not free resources on failure\n";
        bug_report << "========================================\n\n";
        
        bug_report.close();
        
        // Increment bug counter
        Ctx->inter_inconsistency_redundant_free_bugs++;
    } else {
        logger->error("Failed to open Bug_Report.txt for writing");
    }
    
    return;
}

void UAFCheckerPass::handleOnFailureNotReleaseDuty(string fname, 
    map<int, map<string, CallInst*>> dutySum, CallInstSet callers){

    // OP<<"\n\033[34m" << "fname: "<<fname <<"\033[0m" <<"\n";
    // OP<<"OnFailNotReleaseDuty: \n";

    int callee_idx = 0;
    for(auto p2 : dutySum){
        // OP<<"--idx: "<<p2.first<<"\n";
        callee_idx = p2.first;
        for(auto hash : p2.second){
            // OP<<"---- "<<hash.first<<"\n";
        }
    }

    set<string> duty_resources;
    string cai_str = "";
    for(auto p : dutySum[callee_idx]){
        duty_resources.insert(p.first);
        // cai_str += getSourceLine(p.second);
        // cai_str += "\n";
        
        // Get line number and LLVM instruction string
        cai_str += to_string(getInstLineNo(p.second)) + ": ";
        string inst_str;
        raw_string_ostream rso(inst_str);
        p.second->print(rso);
        cai_str += inst_str + "\n";
    }

    set<CallInst*> icaller_set;
    vector<string> call_chain = {fname};

    for(auto cai : callers){
        call_chain.push_back(cai->getFunction()->getName().str());
        checkCaller_should_not_release(cai, callee_idx, 
            duty_resources, 1, call_chain, cai_str);
        call_chain.pop_back();
    }
}