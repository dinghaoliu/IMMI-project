#include "UAFChecker.h"


//#define TEST_ONE_CASE ""

using namespace llvm;

void UAFCheckerPass::identifyReleaseWrappers(CallInst* CI, int free_id){
    
    Value* freed_v = CI->getArgOperand(free_id);
    Function *F = CI->getFunction();
    auto f_arg_size = F->arg_size();
    DominatorTree DT = DominatorTree();
    DT.recalculate(*F);

    size_t hash = getInstSourceInfo(CI);
    if(GlobalAnalyzedSet.count(hash))
        return;
    GlobalAnalyzedSet.insert(hash);

    ReturnInst* RI = NULL;
    for (Instruction& I : instructions(F)) {
        RI = dyn_cast<ReturnInst>(&I);
        if(RI){
            break;
        }
    }
    if(!RI)
        return;

    //First check whether CI must be called
    if(!DT.dominates(CI,RI)){
        return;
    }

    //Then check whether freed_v aliases F's arg
    AliasContext* aliasCtx = new AliasContext();
    analyzeFunction(F, aliasCtx, Ctx);

    //Get the value set that may alias the freed value
    set<Value*> targetValueSet;
    getPreviousValues(freed_v, targetValueSet, aliasCtx);

    int arg_idx = -1;
    bool update_tag = false;
    for(auto it = F->arg_begin(); it != F->arg_end();it++){
        arg_idx++;
        
        //Find if freed v aliases f's args
        Type *arg_type = it->getType();
        if(arg_type->isPointerTy() || arg_type->isStructTy()){
            if(targetValueSet.count(it)){

                //Check callers
                CallInstSet callers = Ctx->Callers[F];
                for(auto j = callers.begin(); j != callers.end();j++){
                    CallInst *caller_inst = *j;
                    if(caller_inst->isInlineAsm() || caller_inst->isIndirectCall()){
                        continue;
                    }

                    unsigned argnum = caller_inst->arg_size();
                    if(f_arg_size != argnum)
                        continue;

                    Function *caller_f = caller_inst->getFunction();
                    GlobalFreeCallMap[caller_inst].insert(arg_idx);
                    
                    identifyReleaseWrappers(caller_inst, arg_idx);
                }
            }
        }
    }
}