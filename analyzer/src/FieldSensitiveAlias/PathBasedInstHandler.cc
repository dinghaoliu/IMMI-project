#include "FieldSensitiveAlias.h"

void HandleOperator_PB(Value* v, AliasContext *aliasCtx){

    GEPOperator *GEPO = dyn_cast<GEPOperator>(v);
    if(GEPO){
        HandleGEP_PB(GEPO, aliasCtx);
        HandleOperator_PB(GEPO->getOperand(0), aliasCtx);
    }

    BitCastOperator *CastO = dyn_cast<BitCastOperator>(v);
    if(CastO){
        HandleMove_PB(CastO, CastO->getOperand(0), aliasCtx);
        HandleOperator_PB(CastO->getOperand(0), aliasCtx);
    }

    PtrToIntOperator *PTIO = dyn_cast<PtrToIntOperator>(v);
    if(PTIO){
        HandleMove_PB(PTIO, PTIO->getOperand(0), aliasCtx);
        HandleOperator_PB(PTIO->getOperand(0), aliasCtx);
    }
}

void HandleInst_PB(Instruction* I, AliasContext *aliasCtx, GlobalContext *Ctx){

    //First filter instructions that do not need to consider
    //e.g., llvm.XXX
    if(isUselessInst(I, Ctx))
        return;

    // Handle GEP and Cast operator
    // Arguments of call are also caught here
    // Note: func call arch_static_branch in pwm-omap-dmtimer.ll
    int opnum = I->getNumOperands();
    for(int i = 0; i < I->getNumOperands(); i++){
        Value* op = I->getOperand(i);
        HandleOperator_PB(op, aliasCtx);
    }

    //Handle target instruction
    AllocaInst* ALI = dyn_cast<AllocaInst>(I);
    if(ALI){
        if(PBgetNode(ALI, aliasCtx) == NULL){
            AliasNode* node = new AliasNode();
            node->insert(ALI);
            aliasCtx->PBNodeMap[ALI] = node;
        }
        return;
    }

    StoreInst *STI = dyn_cast<StoreInst>(I);
    if(STI){
        HandleStore_PB(STI, aliasCtx);
        return;
    }

    LoadInst* LI = dyn_cast<LoadInst>(I);
    if(LI){
        HandleLoad_PB(LI, aliasCtx);
        return;
    }

    GEPOperator *GEP = dyn_cast<GEPOperator>(I);
    if(GEP){
        HandleGEP_PB(GEP, aliasCtx);
        return;
    }

    BitCastInst *BCI = dyn_cast<BitCastInst>(I);
    ZExtInst *ZEXI = dyn_cast<ZExtInst>(I);
    SExtInst *SEXI = dyn_cast<SExtInst>(I);
    TruncInst *TRUI = dyn_cast<TruncInst>(I);
    IntToPtrInst *ITPI = dyn_cast<IntToPtrInst>(I);
    PtrToIntInst *PTII = dyn_cast<PtrToIntInst>(I);
    if(BCI || ZEXI || SEXI || TRUI || ITPI || PTII){
        auto op = I->getOperand(0);
        HandleMove_PB(I, op, aliasCtx);
        return;
    }

    CallInst *CAI = dyn_cast<CallInst>(I);
    if(CAI){
        HandleCai_PB(CAI, aliasCtx, Ctx);
        return;
    }

}

// v1 = *v2
void HandleLoad_PB(LoadInst* LI, AliasContext *aliasCtx){
    
    AliasNode* node1 = PBgetNode(LI, aliasCtx);
    if(node1 == NULL){
        node1 = new AliasNode();
        node1->insert(LI);
        aliasCtx->PBNodeMap[LI] = node1;
    }

    Value* op = LI->getOperand(0);
    AliasNode* node2 = PBgetNode(op, aliasCtx);
    if(node2 == NULL){
        node2 = new AliasNode();
        node2->insert(op);
        aliasCtx->PBNodeMap[op] = node2;
    }

    //node2 has pointed to some nodes
    if(aliasCtx->PBToNodeMap.count(node2)){
        auto node2_toNodeMap = aliasCtx->PBToNodeMap[node2];
        if(node2_toNodeMap.count(-1)){
           AliasNode* node2_toNode = node2_toNodeMap[-1];
           node2_toNode->insert(LI);
           node1->erase(LI);
           aliasCtx->PBNodeMap[LI] = node2_toNode;
           goto end;
        }
    }

    aliasCtx->PBToNodeMap[node2][-1] = node1;
    aliasCtx->PBFromNodeMap[node1][-1] = node2;

end:
    return;
}

void HandleStore_PB(StoreInst* STI, AliasContext *aliasCtx){
    Value* vop = STI->getValueOperand(); //v1
    Value* pop = STI->getPointerOperand(); //v2
    HandleStore_PB(vop, pop, aliasCtx);
}

//store vop to pop
void HandleStore_PB(Value* vop, Value* pop, AliasContext *aliasCtx){

    AliasNode* node1 = PBgetNode(vop, aliasCtx);
    if(node1 == NULL){
        node1 = new AliasNode();
        node1->insert(vop);
        aliasCtx->PBNodeMap[vop] = node1;
    }

    AliasNode* node2 = PBgetNode(pop, aliasCtx);
    if(node2 == NULL){
        node2 = new AliasNode();
        node2->insert(pop);
        aliasCtx->PBNodeMap[pop] = node2;
    }

    //node2 has pointed to some nodes
    if(aliasCtx->PBToNodeMap.count(node2)){

        auto node2_toNodeMap = aliasCtx->PBToNodeMap[node2];
        if(node2_toNodeMap.count(-1)){
           AliasNode* node2_toNode = node2_toNodeMap[-1];
           aliasCtx->PBFromNodeMap[node2_toNode].erase(-1);
        }
    }

    aliasCtx->PBToNodeMap[node2][-1] = node1;
    aliasCtx->PBFromNodeMap[node1][-1] = node2;

    return;
}

// v1 = &v2->f
void HandleGEP_PB(GEPOperator* GEP, AliasContext *aliasCtx){

    int idx = 0;
    if(getGEPLayerIndex(GEP, idx)){
        Value* v2 = GEP->getPointerOperand();
        Value* v1 = GEP;

        AliasNode* node2 = PBgetNode(v2, aliasCtx);
        if(node2 == NULL){

            node2 = new AliasNode();
            node2->insert(v2);
            aliasCtx->PBNodeMap[v2] = node2;
        }

        AliasNode* node1 = PBgetNode(v1, aliasCtx);
        if(node1 == NULL){

            node1 = new AliasNode();
            node1->insert(v1);
            aliasCtx->PBNodeMap[v1] = node1;
        }

        //node2 has pointed to some nodes
        if(aliasCtx->PBToNodeMap.count(node2)){

            auto node2_toNodeMap = aliasCtx->PBToNodeMap[node2];
            if(node2_toNodeMap.count(idx)){
                node2_toNodeMap[idx]->insert(v1);
                node1->erase(v1);
                aliasCtx->PBNodeMap[v1] = node2_toNodeMap[idx];
                goto end;
            }
        }

        aliasCtx->PBToNodeMap[node2][idx] = node1;
        aliasCtx->PBFromNodeMap[node1][idx] = node2;

    }
    else{
        HandleMove_PB(GEP, GEP->getPointerOperand(), aliasCtx);
    }

end:
    return;
}

// v1 = v2
void HandleMove_PB(Value* v1, Value* v2, AliasContext *aliasCtx){

    AliasNode* node2 = PBgetNode(v2, aliasCtx);
    if(node2 == NULL){
        node2 = new AliasNode();
        node2->insert(v2);
        aliasCtx->PBNodeMap[v2] = node2;
    }


    AliasNode* node1 = PBgetNode(v1, aliasCtx);
    if(node1 == NULL){
        node2->insert(v1);
        aliasCtx->PBNodeMap[v1] = node2;
        return;
    }

    if(node1 == node2)
        return;
    
    node1->erase(v1);
    node2->insert(v1);

}

void HandleCai_PB(CallInst* CAI, AliasContext *aliasCtx, GlobalContext *Ctx){
    
    if(PBgetNode(CAI, aliasCtx) == NULL){
        AliasNode* node = new AliasNode();
        node->insert(CAI);
        aliasCtx->PBNodeMap[CAI] = node;
    }

    for (User::op_iterator OI = CAI->op_begin(), OE = CAI->op_end(); OI != OE; ++OI) {
        if(PBgetNode(*OI, aliasCtx) == NULL){
            AliasNode* node = new AliasNode();
            node->insert(*OI);
            aliasCtx->PBNodeMap[*OI] = node;
        }
    }

    // Resolve mem copy functions
    // Usually a copy func is like: copy_func(dst, src, len)
    StringRef FName = getCalledFuncName(CAI);
    if(Ctx->CopyFuncs.count(FName.str())){
        HandleMove_PB(CAI->getArgOperand(0), CAI->getArgOperand(1), aliasCtx);
        return;
    }

}

void HandleReturn_PB(Function* F, CallInst* cai, AliasContext *aliasCtx){

    for (inst_iterator i = inst_begin(F), ei = inst_end(F); i != ei; ++i) {
        ReturnInst *RI = dyn_cast<ReturnInst>(&*i);
        if(RI){
            Value* return_v = RI->getReturnValue();
            if(return_v){
                HandleMove_PB(return_v, cai, aliasCtx);
            }
        }
    }

    vector<Value *>f_arg_vec;
    f_arg_vec.clear();
    for(auto it = F->arg_begin(); it != F->arg_end(); it++){
        f_arg_vec.push_back(it);
    }

    unsigned argnum = cai->arg_size();
    auto f_arg_size = F->arg_size();
    
    unsigned min_num = f_arg_size < argnum ? f_arg_size : argnum;

    for(unsigned j = 0; j < min_num; j++){
        Value* cai_arg = cai->getArgOperand(j);
        HandleMove_PB(cai_arg, f_arg_vec[j], aliasCtx);
        //OP<<"move handled\n";
    }
}

bool is_alias_PB(Value* v1, Value* v2,  AliasContext *aliasCtx){
    if(aliasCtx->PBNodeMap.count(v1) && aliasCtx->PBNodeMap.count(v2)){
        if(aliasCtx->PBNodeMap[v1] == aliasCtx->PBNodeMap[v2])
            return true;
    }

    return false;
}