#include "UAFChecker.h"

using namespace llvm;

size_t UAFCheckerPass::getInstSourceInfo(Instruction *I){
    
    if(!I)
        return 0;
    
    unsigned line_number = getInstLineNo(I);
    string loc = getInstFilename(I);
    loc += to_string(line_number);
    
    return strHash(loc);
}

bool UAFCheckerPass::recur_get_pre_path(BasicBlock* current_bb, 
    set<BasicBlock*> &pre_path, BasicBlock *entryBB){

    if(pre_path.count(current_bb)) { return false; }
    
    pre_path.insert(current_bb);

    int NumPred = pred_size(current_bb);
    if(NumPred == 0){
        if(current_bb == entryBB)
            return true;
        else{
            pre_path.erase(current_bb);
            return false;
        }
    }

    for (BasicBlock *PredBB : predecessors(current_bb)){
        bool ret = recur_get_pre_path(PredBB, pre_path, entryBB);
        if(ret)
            return ret;
    }

    pre_path.erase(current_bb);
    return false;
}

void recur_get_post_path(BasicBlock* current_bb, set<BasicBlock*> &post_path){

    if(post_path.count(current_bb))
        return;

    list<BasicBlock*> LB;
    LB.push_back(current_bb);

    while(!LB.empty()){
        
        BasicBlock *TB = LB.front(); //Current checking block
        LB.pop_front();

        if(post_path.count(TB)){
            continue;
        }

        post_path.insert(TB);
        for(BasicBlock *succBB : successors(TB)){
            LB.push_back(succBB);
        }
    }

}

bool UAFCheckerPass::get_field_access_arr(AliasContext*aCtx, AliasNode *start, 
    AliasNode *end, vector<int> &field_access_arr, 
    set<AliasNode*> &analyzed_set){

    if(start == end){
        field_access_arr.push_back(0);
        return true;
    }

    if(analyzed_set.count(start))
        return false;
    
    analyzed_set.insert(start);

    if(aCtx->ToNodeMap.count(start)){
        for(auto m : aCtx->ToNodeMap[start]){
            field_access_arr.push_back(m.first);
            
            bool ret = get_field_access_arr(aCtx, m.second, end, field_access_arr, analyzed_set);
            if(ret)
                return true;

            field_access_arr.pop_back();
        }
    }

    return false;

}

void UAFCheckerPass::recurGetFieldAccessArr(string fname, int f_arg_id, 
    string pre_arr, set<string>&arr, set<string>&nulligivstion_arr,
    map<CallInst*, set<int>> &analyzed_pairs, CallInst* pre_cai){
    
    if(fname.length() == 0 || f_arg_id == -1)
        return;

    if(pre_cai){
        if(analyzed_pairs.count(pre_cai)){
            if(analyzed_pairs[pre_cai].count(f_arg_id)){
                return;
            }
        }
        analyzed_pairs[pre_cai].insert(f_arg_id);
    }

    vector<ReleaseSummary*> RS_arr;
    if(GlobalReleaseTransitMap.count(fname)){
        if(GlobalReleaseTransitMap[fname].count(f_arg_id)){
            RS_arr = GlobalReleaseTransitMap[fname][f_arg_id];

            for(auto RS : RS_arr){
                auto release_cai = RS->release_cai;
                bool is_nullified = RS->is_nullified;
                StringRef release_cai_name = getCalledFuncName(release_cai);

                //release_cai_name is a primitive release (e.g., kfree)
                if(Ctx->FreeFuncs.count(release_cai_name.str())){
                    string field_access_arr = RS->field_access_arr;
                    field_access_arr = pre_arr + field_access_arr;
                    arr.insert(field_access_arr);
                    if(is_nullified){
                        nulligivstion_arr.insert(field_access_arr);
                    }
                    continue;
                }
                //release_cai_name is a wrapper, find the callee relations
                else{
                    int cai_arg_id = RS->cai_arg_id;
                    string field_access_arr = RS->field_access_arr;
                    
                    field_access_arr = pre_arr + field_access_arr;
                    if(is_nullified){
                        nulligivstion_arr.insert(field_access_arr);
                    }
                    field_access_arr.pop_back();
                    recurGetFieldAccessArr(release_cai_name.str(), cai_arg_id, field_access_arr, arr, nulligivstion_arr, analyzed_pairs, release_cai);
                }
            }
        }
    }   
}

//Check if the freed_v is nullified
bool UAFCheckerPass::isFreedValueNullified(CallInst* free_cai, unsigned arg_id){
    
    Value* freed_v = free_cai->getArgOperand(arg_id);
    Function *F = free_cai->getFunction();
    BasicBlock* current_bb = free_cai->getParent();
    
    AliasContext* LocalAliasCtx = new AliasContext();
    set<BasicBlock*> post_path;
    post_path.clear();
    recur_get_post_path(current_bb, post_path);
    for(auto bb : post_path){
        for(BasicBlock::iterator i = bb->begin(); i != bb->end(); i++){
            Instruction *I = dyn_cast<Instruction>(i);
            if(I){
                HandleInst(I, LocalAliasCtx, Ctx, false);
            }
        }
    }
    AliasNode *n_freed_v = getNode(freed_v, LocalAliasCtx);
    if(n_freed_v){
        for(auto v : n_freed_v->aliasclass){
            if(ConstantPointerNull* CNullPtr = dyn_cast<ConstantPointerNull>(v)){
                return true;
            }
        }
    }

    return false;
}

int UAFCheckerPass::checkFreedValueComesFromArg(CallInst* free_cai, 
    vector<int> &field_access_arr, bool &is_nullified, unsigned arg_id,
    AliasContext* LocalAliasCtx){

    if(!free_cai)
        return -1;
    
    Value* freed_v = free_cai->getArgOperand(arg_id);
    Function *F = free_cai->getFunction();
    BasicBlock* current_bb = free_cai->getParent();

    set<BasicBlock*> pre_path;
    pre_path.clear();
    BasicBlock* entryBB = &F->getEntryBlock();
    if(recur_get_pre_path(current_bb, pre_path, entryBB) == false)
        return -1;
    

    if(LocalAliasCtx == NULL){
        LocalAliasCtx = new AliasContext();
        for(auto bb : pre_path){

            for(BasicBlock::iterator i = bb->begin(); i != bb->end(); i++){
                Instruction *I = dyn_cast<Instruction>(i);
                if(I){
                    HandleInst(I, LocalAliasCtx, Ctx);
                }
            }
        }
    }

    set<BasicBlock*> post_path;
    post_path.clear();
    recur_get_post_path(current_bb, post_path);
    for(auto bb : post_path){
        for(BasicBlock::iterator i = bb->begin(); i != bb->end(); i++){
            Instruction *I = dyn_cast<Instruction>(i);
            if(I){
                HandleInst(I, LocalAliasCtx, Ctx, false);
            }
        }
    }
    AliasNode *n_freed_v = getNode(freed_v, LocalAliasCtx);
    if(n_freed_v){
        for(auto v : n_freed_v->aliasclass){
            if(ConstantPointerNull* CNullPtr = dyn_cast<ConstantPointerNull>(v)){
                is_nullified = true;
            }
        }
    }

    set<Value*> targetValueSet;
    getPreviousValues(freed_v, targetValueSet, LocalAliasCtx);

    int arg_idx = -1;
    bool update_tag = false;
    for(auto it = F->arg_begin(); it != F->arg_end();it++){
        arg_idx++;
        Type *arg_type = it->getType();
        if(arg_type->isPointerTy() || arg_type->isStructTy()){
            if(targetValueSet.count(it)){

                AliasNode *n_arg = getNode(it, LocalAliasCtx);
                if(!n_arg){
                    return -1;
                }

                AliasNode *n_freed_v = getNode(freed_v, LocalAliasCtx);
                if(!n_freed_v){
                    return -1;
                }

                set<AliasNode*> analyzed_set;
                
                if(get_field_access_arr(LocalAliasCtx, n_arg, n_freed_v, field_access_arr, analyzed_set)){
                    return arg_idx;
                }

                return -1;
            }
        }
    }

    return -1;
}

bool UAFCheckerPass::getFuncFromName(string fname, string &func_code){

    if(fname.length() == 0)
        return false;
    
    Function *F = NULL;
    
    if(Ctx->GlobalAllFuncs.count(fname)){
        set<size_t> hashSet = Ctx->GlobalAllFuncs[fname];
        for(auto it = hashSet.begin(); it != hashSet.end(); it++){
            F = Ctx->Global_Unique_All_Func_Map[*it];
            break;
        }
    }

    if(!F)
        return false;
    
    func_code = getFunctionSourceCode(F);
    return true;
}