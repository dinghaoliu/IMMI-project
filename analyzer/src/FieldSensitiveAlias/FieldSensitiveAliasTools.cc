#include "FieldSensitiveAlias.h"

//merge n1 into n2
void mergeNode(AliasNode* n1, AliasNode* n2, AliasContext *aliasCtx){

    if(n1 == n2)    
        return;
    
    for(auto it = n1->aliasclass.begin(); it != n1->aliasclass.end(); it++){
        Value* v = *it;
        n2->insert(v);
        aliasCtx->NodeMap[v] = n2;
    }
    n1->aliasclass.clear();

    //Then change edges
    //Check n1 points to which node
    //All point-to nodes should be merged
    if(aliasCtx->ToNodeMap.count(n1)){
        auto n1_toNodeMap = aliasCtx->ToNodeMap[n1];

        //Both n1 and n2 have point to nodes
        if(aliasCtx->ToNodeMap.count(n2)){
            auto n2_toNodeMap = aliasCtx->ToNodeMap[n2];

            for(auto n1_pair : n1_toNodeMap){
                
                int n1_edge = n1_pair.first;
                AliasNode* n1_toNode= n1_pair.second;

                //merge the same edge : n1_edge
                if(n2_toNodeMap.count(n1_edge)){
                    AliasNode* n2_toNode = n2_toNodeMap[n1_edge];
                    if(n1_toNode == n2_toNode){
                        //do nothing here
                    }
                    else{
                        aliasCtx->ToNodeMap[n1].erase(n1_edge);
                        aliasCtx->ToNodeMap[n2].erase(n1_edge);
                        aliasCtx->FromNodeMap[n1_toNode].erase(n1_edge);
                        aliasCtx->FromNodeMap[n2_toNode].erase(n1_edge);
                        mergeNode(n1_toNode, n2_toNode, aliasCtx);
                        aliasCtx->ToNodeMap[n2][n1_edge] = n2_toNode;
                        aliasCtx->FromNodeMap[n2_toNode][n1_edge].insert(n2);
                    }
                }
                //n1 has, but n2 has no such edge, merge the edge
                else{
                    aliasCtx->ToNodeMap[n1].erase(n1_edge);
                    aliasCtx->ToNodeMap[n2][n1_edge] = n1_toNode;
                    aliasCtx->FromNodeMap[n1_toNode][n1_edge].insert(n2);
                }
            }
        }

        //n2 has no pointed node
        else{
            aliasCtx->ToNodeMap.erase(n1);
            aliasCtx->ToNodeMap[n2] = n1_toNodeMap;
            for(auto n: n1_toNodeMap){
                aliasCtx->FromNodeMap[n.second][n.first].erase(n1);
                aliasCtx->FromNodeMap[n.second][n.first].insert(n2);
            }
        }
    }

    //Check which node points to n1
    //For previous node, only merge * edge
    if(aliasCtx->FromNodeMap.count(n1)){
        auto n1_fromNodeMap = aliasCtx->FromNodeMap[n1];

        //Both n1 and n2 have previous(from) nodes
        if(aliasCtx->FromNodeMap.count(n2)){
            auto n2_fromNodeMap = aliasCtx->FromNodeMap[n2];

            for(auto n1_pair : n1_fromNodeMap){

                int n1_edge = n1_pair.first;
                set<AliasNode*> n1_fromNodeSet = n1_pair.second;
                if(n1_edge == -1){

                    if(n1_fromNodeSet.size() != 1){
                        //OP<<"WARNING IN NODE MERGE 1!!!\n";
                    }
                    AliasNode* n1_fromNode = *n1_fromNodeSet.begin();

                    //merge the same edge : * edge
                    if(n2_fromNodeMap.count(n1_edge)){
                        set<AliasNode*> n2_fromNodeSet = n2_fromNodeMap[n1_edge];
                        if(n2_fromNodeSet.size() != 1){
                            //OP<<"WARNING IN NODE MERGE 2!!!"<<n2_fromNodeSet.size()<<"\n";
                        }
                         
                        AliasNode* n2_fromNode = *n2_fromNodeSet.begin();
                        if(n1_fromNode == n2_fromNode){
                            //do nothing here
                        }
                        else{
                            aliasCtx->FromNodeMap[n1].erase(n1_edge);
                            aliasCtx->FromNodeMap[n2].erase(n1_edge);
                            aliasCtx->ToNodeMap[n1_fromNode].erase(n1_edge);
                            aliasCtx->ToNodeMap[n2_fromNode].erase(n1_edge);
                            mergeNode(n1_fromNode, n2_fromNode, aliasCtx);
                            aliasCtx->FromNodeMap[n2][n1_edge].insert(n2_fromNode);
                            aliasCtx->ToNodeMap[n2_fromNode][n1_edge] = n2;
                        }
                    }
                    //n1 has, but n2 has no such edge, merge the edge
                    else{
                        aliasCtx->FromNodeMap[n1].erase(n1_edge);
                        aliasCtx->FromNodeMap[n2][n1_edge].insert(n1_fromNode);
                        aliasCtx->ToNodeMap[n1_fromNode][n1_edge] = n2;
                    }
                }
                //The previous edge is not *, just add them to the graph
                else{
                    for(AliasNode* n1_fromNode : n1_fromNodeSet){
                        aliasCtx->FromNodeMap[n1].erase(n1_edge);
                        aliasCtx->FromNodeMap[n2][n1_edge].insert(n1_fromNode);
                        aliasCtx->ToNodeMap[n1_fromNode][n1_edge] = n2;
                    }
                }
            }
        }

        //n2 has no pre node
        else{
            aliasCtx->FromNodeMap.erase(n1);
            aliasCtx->FromNodeMap[n2] = n1_fromNodeMap;
            for(auto m: n1_fromNodeMap)
                for(auto n: m.second)
                    aliasCtx->ToNodeMap[n][m.first] = n2;
        }
    }
}

//Filter instructions we do not need to analysis
//Return true if current inst does not need analysis
bool isUselessInst(Instruction* I, GlobalContext *Ctx){

    //Filter debug functions
    CallInst *CAI = dyn_cast<CallInst>(I);
    if(CAI){
        StringRef FName = getCalledFuncName(CAI);
        if(Ctx->DebugFuncs.count(FName.str())){
            return true;
        }
    }

    return false;
}

AliasNode* getNode(Value *V, AliasContext *aliasCtx){

    //Constant value is always regarded as different value
    //Note: this check will influence global values!
    ConstantData *Ct = dyn_cast<ConstantData>(V);
    if(Ct){
        return NULL;
    }

    //Use a map to speed up query
    if(aliasCtx->NodeMap.count(V))
        return aliasCtx->NodeMap[V];

    return NULL;
}

AliasNode* PBgetNode(Value *V, AliasContext *aliasCtx){

    //Constant value is always regarded as different value
    //Note: this check will influence global values!
    ConstantData *Ct = dyn_cast<ConstantData>(V);
    if(Ct){
        return NULL;
    }

    //Use a map to speed up query
    if(aliasCtx->PBNodeMap.count(V))
        return aliasCtx->PBNodeMap[V];

    return NULL;
}

bool checkNodeConnectivity(AliasNode* node1, AliasNode* node2, AliasContext *aliasCtx){

    if(!node1 || !node2)
        return false;

    list<AliasNode *>LN;
    LN.push_back(node1);
    set<AliasNode *> PN; //Global value set to avoid loop
    PN.clear();

    while (!LN.empty()) {
        AliasNode *CN = LN.front();
        LN.pop_front();

        if (PN.find(CN) != PN.end()){
            continue;
        }
        PN.insert(CN);

        if(CN == node2)
            return true;

        if(aliasCtx->ToNodeMap.count(CN)){
            for(auto n : aliasCtx->ToNodeMap[CN]){
                if(n.first == -1)
                    LN.push_back(n.second);
            }
        }

        if(aliasCtx->FromNodeMap.count(CN)){
            for(auto m : aliasCtx->FromNodeMap[CN]){
                if(m.first == -1){
                    for(auto n : m.second)
                        LN.push_back(n);
                }
                
            }
        }
    }

    return false;
}

bool checkValidStructName(Type *Ty){

    if(Ty->isStructTy()){
        StructType* STy = dyn_cast<StructType>(Ty);
        if(STy->isLiteral()){

            auto TyName = Ty->getStructName();
            if(TyName.contains(".union")){
                return false;
            }

            if(TyName.contains(".anon")){
                return false;
            }

            return true;
        }
        else{
            return false;
        }
    }
    else{
        return false;
    }
}

Type *getLayerTwoType(Type* baseTy, vector<int> ids){

    StructType *sty = dyn_cast<StructType>(baseTy);
    if(!sty)
        return NULL;
    
    for(auto it = ids.begin(); it!=ids.end(); it++){
        int idx = *it;

        Type* subTy = sty->getElementType(idx);
        StructType *substy = dyn_cast<StructType>(subTy);
        if(!substy)
            return NULL;
        
        sty = substy;
    }

    return sty;
}

//Return true if we successfully find the layered type
bool getGEPLayerIndex(GEPOperator *GEP, int &Index) {

    Type *PTy = GEP->getPointerOperand()->getType();
    if(!PTy->isPointerTy())
        return false;

    Type *Ty = PTy->getPointerElementType();
    Type *sTy = GEP->getSourceElementType();

    Type* BTy;
    int Idx;

    //Expect the PointerOperand is an identified struct
    if (Ty->isStructTy() && GEP->hasAllConstantIndices()) {
        BTy = Ty;
        User::op_iterator ie = GEP->idx_end();
        ConstantInt *ConstI = dyn_cast<ConstantInt>((--ie)->get());
        Idx = ConstI->getSExtValue(); //Idx is the last indice
        if(Idx < 0)
            return false;
        
        if(!checkValidStructName(Ty))
            return false;

        unsigned indice_num = GEP->getNumIndices();

        //Filter GEP that has invalid indice
        ConstantInt *ConstI_first = dyn_cast<ConstantInt>(GEP->idx_begin()->get());
        int Idx_first = ConstI_first->getSExtValue();
        if(Idx_first != 0 && indice_num>=2){
            if(Ty->isStructTy()){
                return false;
            }
        }
        
        if(indice_num < 2)
            return false;

        Index = Idx;

        return true;
    }
    else if(Ty->isStructTy() || Ty->isArrayTy()){
        Index = 999;
        return true;
    }

    return false;
    
}

//merge S2 into S1
void valueSetMerge(set<Value*> &S1, set<Value*> &S2){
    for(auto v : S2)
        S1.insert(v);
}

void getClusterNodes(AliasNode* startNode, set<AliasNode*> &nodeSet, AliasContext *aliasCtx){

    if(startNode == NULL)
        return;
    
    nodeSet.insert(startNode);

    list<AliasNode *>LN;
    LN.push_back(startNode);
    set<AliasNode *> PN; //Global value set to avoid loop
    PN.clear();

    while (!LN.empty()) {
        AliasNode *CN = LN.front();
        LN.pop_front();

        if (PN.find(CN) != PN.end()){
            continue;
        }
        PN.insert(CN);

        if(aliasCtx->ToNodeMap.count(CN)){
            for(auto m : aliasCtx->ToNodeMap[CN]){
                LN.push_back(m.second);
                nodeSet.insert(m.second);
            }
        }

        if(aliasCtx->FromNodeMap.count(CN)){
            for(auto m : aliasCtx->FromNodeMap[CN]){
                for(auto n : m.second){
                    LN.push_back(n);
                    nodeSet.insert(n);
                }
            }
        }
    }
}

void getClusterValues(Value* v, set<Value*> &valueSet, AliasContext *aliasCtx){

    if(v == NULL)
        return;

    AliasNode *n = getNode(v, aliasCtx);
    if(!n){
        return;
    }

    //Get the cluster value to enable inter-procedural analysis
    set<AliasNode*> targetNodeSet;
    targetNodeSet.clear();
    getClusterNodes(n, targetNodeSet, aliasCtx);
    
    valueSet.clear();
    for(auto it = targetNodeSet.begin(); it != targetNodeSet.end(); it++){
        AliasNode *n = *it;
        valueSetMerge(valueSet, n->aliasclass);
    }
}

void getPreviousNodes(AliasNode* startNode, set<AliasNode*> &nodeSet, AliasContext *aliasCtx){

    if(startNode == NULL)
        return;
    
    nodeSet.insert(startNode);

    list<AliasNode *>LN;
    LN.push_back(startNode);
    set<AliasNode *> PN; //Global value set to avoid loop
    PN.clear();

    while (!LN.empty()) {
        AliasNode *CN = LN.front();
        LN.pop_front();

        if (PN.find(CN) != PN.end()){
            continue;
        }
        PN.insert(CN);

        if(aliasCtx->FromNodeMap.count(CN)){
            for(auto m : aliasCtx->FromNodeMap[CN]){
                for(auto n : m.second){
                    LN.push_back(n);
                    nodeSet.insert(n);
                }
            }
        }
    }
}

void getPreviousValues(Value* v, set<Value*> &valueSet, AliasContext *aliasCtx){

    if(v == NULL)
        return;

    AliasNode *n = getNode(v, aliasCtx);
    if(!n){
        return;
    }

    //Get the cluster value to enable inter-procedural analysis
    set<AliasNode*> previousNodeSet;
    previousNodeSet.clear();
    getPreviousNodes(n, previousNodeSet, aliasCtx);

    valueSet.clear();
    for(auto it = previousNodeSet.begin(); it != previousNodeSet.end(); it++){
        AliasNode *n = *it;
        valueSetMerge(valueSet, n->aliasclass);
    }

}

void showGraph(AliasContext *aliasCtx){
    
    if(!aliasCtx)
        return;
    
    set<AliasNode*> Nodeset;
    for(auto m : aliasCtx->NodeMap){
        AliasNode* n = m.second;
        Nodeset.insert(n);
    }

    for(AliasNode* n : Nodeset){
        OP<<"node: "<<n<<"\n";
        if(aliasCtx->FromNodeMap.count(n)){
            for(auto pre_n : aliasCtx->FromNodeMap[n]){
                for(auto n : pre_n.second)
                    OP<<"previdous nodes: "<<n<<" (" << pre_n.first<<")\n";
            }
        }
        if(aliasCtx->ToNodeMap.count(n)){
            for(auto to_n : aliasCtx->ToNodeMap[n])
                OP<<"to nodes: "<<to_n.second<<" (" << to_n.first<<")\n";
        }
        OP<<"node content: \n";
        n->print_set();
        OP<<"\n";
    }
    OP<<"\n";
}

void showGraph_PB(AliasContext *aliasCtx){
    
    if(!aliasCtx)
        return;
    
    set<AliasNode*> Nodeset;
    for(auto m : aliasCtx->PBNodeMap){
        AliasNode* n = m.second;
        Nodeset.insert(n);
    }

    for(AliasNode* n : Nodeset){
        OP<<"node: "<<n<<"\n";
        if(aliasCtx->PBFromNodeMap.count(n)){
            for(auto pre_n : aliasCtx->PBFromNodeMap[n]){
                OP<<"previdous nodes: "<<pre_n.second<<" (" << pre_n.first<<")\n";
            }
        }
        if(aliasCtx->PBToNodeMap.count(n)){
            for(auto to_n : aliasCtx->PBToNodeMap[n])
                OP<<"to nodes: "<<to_n.second<<" (" << to_n.first<<")\n";
        }
        OP<<"node content: \n";
        n->print_set();
        OP<<"\n";
    }
    OP<<"\n";
}