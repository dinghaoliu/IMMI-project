#ifndef ALIAS_ANALYSIS_H
#define ALIAS_ANALYSIS_H

#include <omp.h>

#include "../utils/include_llvm.h"
#include "../utils/Analyzer.h"
#include "../utils/Tools.h"
#include "../utils/Common.h"

typedef struct AliasNode {

    set<Value*> aliasclass;

    AliasNode(){
        aliasclass.clear();
    }

    int count(Value* V){
        return aliasclass.count(V);
    }

    void insert(Value* V){
        aliasclass.insert(V);
    }

    bool empty(){
        return aliasclass.empty();
    }

    void erase(Value* V){
        if(aliasclass.count(V) == 0)
            return;
        
        aliasclass.erase(V);
    }

    void print_set(){
        for(auto it = aliasclass.begin(); it != aliasclass.end(); it++){
            Value *v = *it;

            //Func definition is too long, just print its name
            if(Function *F = dyn_cast<Function>(v)){
                OP<<"func: "<<F->getName()<<"\n"; 
                continue;
            }
            OP<<*v<<"\n";
        }
    }

} AliasNode;

typedef struct AliasEdge {
    
    AliasNode *fromNode;
    AliasNode *toNode;
    
    int type; 

    AliasEdge(){
        fromNode = NULL;
        toNode = NULL;
        type = -2; // -1: pointer dereference, 0~99999: field index
    }
    
} AliasEdge;

typedef struct AliasContext {

    map<Value*, AliasNode*> NodeMap; //Record one value belongs to which alias node
    map<Value*, AliasNode*> PBNodeMap;

    //Note: for * edge, there should be only one node

    //One node points to which node
    map<AliasNode*, map<int,AliasNode*>> ToNodeMap; 
    map<AliasNode*, map<int,AliasNode*>> PBToNodeMap;

    //One node is pointed by which node
    map<AliasNode*, map<int,set<AliasNode*>>> FromNodeMap; 
    map<AliasNode*, map<int,AliasNode*>> PBFromNodeMap; 


    set<Function*> AnalyzedFuncSet;

    AliasContext(){

        /*NodeMap.clear();
        ToNodeMap.clear();
        FromNodeMap.clear();
        AnalyzedFuncSet.clear();
        PBToNodeMap.clear();
        PBFromNodeMap.clear();*/
    }

    AliasContext(AliasContext *C){
        NodeMap = C->NodeMap;
        PBNodeMap = C->PBNodeMap;
        ToNodeMap = C->ToNodeMap;
        PBToNodeMap = C->PBToNodeMap;
        FromNodeMap = C->FromNodeMap;
        PBFromNodeMap = C->PBFromNodeMap;
    }

    ~AliasContext(){
        //OP<<"delete is called\n";
        set<AliasNode*> nodeSet;
        for(auto it = NodeMap.begin(); it != NodeMap.end(); it++){
            nodeSet.insert(it->second);
        }

        for(AliasNode* n : nodeSet){
            delete n;
        }
    }

} AliasContext;

//InstHandler
void HandleInst(Instruction* I, AliasContext *aliasCtx, GlobalContext *Ctx, bool handle_const = true);
void HandleLoad(LoadInst* LI, AliasContext *aliasCtx);
void HandleStore(StoreInst* STI, AliasContext *aliasCtx, bool handle_const = true);
void HandleStore(Value* vop, Value* pop, AliasContext *aliasCtx, bool handle_const = true);
void HandleGEP(GEPOperator* GEP, AliasContext *aliasCtx);
void HandleAlloc(AllocaInst* ALI, AliasContext *aliasCtx);
void HandleCai(CallInst* CAI, AliasContext *aliasCtx, GlobalContext *Ctx);
void HandleMove(Value* v1, Value* v2, AliasContext *aliasCtx);
void HandleReturn(Function* F, CallInst* cai, AliasContext *aliasCtx);
void HandleOperator(Value* v, AliasContext *aliasCtx);

//InstHandler-path based
void HandleInst_PB(Instruction* I, AliasContext *aliasCtx, GlobalContext *Ctx);
void HandleLoad_PB(LoadInst* LI, AliasContext *aliasCtx);
void HandleStore_PB(StoreInst* STI, AliasContext *aliasCtx);
void HandleStore_PB(Value* vop, Value* pop, AliasContext *aliasCtx);
void HandleGEP_PB(GEPOperator* GEP, AliasContext *aliasCtx);
void HandleAlloc_PB(AllocaInst* ALI, AliasContext *aliasCtx);
void HandleCai_PB(CallInst* CAI, AliasContext *aliasCtx, GlobalContext *Ctx);
void HandleMove_PB(Value* v1, Value* v2, AliasContext *aliasCtx);
void HandleReturn_PB(Function* F, CallInst* cai, AliasContext *aliasCtx);
void HandleOperator_PB(Value* v, AliasContext *aliasCtx);
bool is_alias_PB(Value* v1, Value* v2, AliasContext *aliasCtx);

//Tools
AliasNode* getNode(Value *V, AliasContext *aliasCtx);
AliasNode* PBgetNode(Value *V, AliasContext *aliasCtx);
bool isUselessInst(Instruction* I, GlobalContext *Ctx);
void mergeNode(AliasNode* n1, AliasNode* n2, AliasContext *aliasCtx);
bool checkNodeConnectivity(AliasNode* node1, AliasNode* node2, AliasContext *aliasCtx);
bool getGEPLayerIndex(GEPOperator *GEP, int &Index);
void analyzeFunction(Function* F, AliasContext *aliasCtx, GlobalContext *Ctx, bool handle_const = true);
void getClusterValues(Value* v, set<Value*> &valueSet, AliasContext *aliasCtx);
void getClusterNodes(AliasNode* startNode, set<AliasNode*> &nodeSet, AliasContext *aliasCtx);
void valueSetMerge(set<Value*> &S1, set<Value*> &S2);
void getPreviousValues(Value* v, set<Value*> &valueSet, AliasContext *aliasCtx);
void getPreviousNodes(AliasNode* startNode, set<AliasNode*> &nodeSet, AliasContext *aliasCtx);

//Debug
void showGraph(AliasContext *aliasCtx);
void showGraph_PB(AliasContext *aliasCtx);


#endif