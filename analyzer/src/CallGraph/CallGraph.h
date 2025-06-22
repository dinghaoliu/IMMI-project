#ifndef _CALL_GRAPH_H
#define _CALL_GRAPH_H

#include "../utils/include_llvm.h"
#include "../utils/typedef.h"
#include "../utils/Analyzer.h"
#include "../utils/Tools.h"
#include "../utils/Common.h"
#include <vector>
#include <stdlib.h>
#include <assert.h>


class CallGraphPass : public IterativeModulePass {
public: 
    const DataLayout *DL;
    Type *Int8PtrTy;
    Type *IntPtrTy;

    DenseMap<size_t, FuncSet> typeFuncsMap;
    // 
    unordered_map<size_t, set<size_t>> typeConfineMap;
    unordered_map<size_t, set<size_t>> typeTransitMap;
    map<Value*, Type*> TypeHandlerMap;

    set<size_t> typeEscapeSet;
    
    //Used in checking return a composite type
    DenseMap<size_t, set<CompositeType>> FuncTypesMap; //hash(func_name) with type

    //filter redundant function analysis (use funcname + line number to locate unique icall site)
    map<string, set<unsigned long long>>globalFuncNameMap;

    //used in func analysis
    map<Value*, map<Function*, set<size_t>>> Func_Init_Map;

    //Resolve type casting for one-layer results
    map<string, set<string>> typeStrCastMap;
    map<int, map<size_t, FunctionType*>> funcTypeMap;

    enum SourceFlag {
    // error returning, mask:0xF
        Internal_Global = 1,
        External_Global = 2,
        Argument = 3,
        Local = 4,
        Return = 5,
        InnerFunction = 6,
        Invalid = 7,
    };

    enum LayerFlag {
        Precise_Mode = 1,
        Recall_Mode = 2,
    };

    map<string, set<Function*>> globalFuncInitMap;
    set<string> globalFuncEscapeSet;
    DenseMap<size_t, FuncSet> argStoreFuncSet;
    unordered_map<size_t, set<size_t>>argStoreFuncTransitMap;


    /**************  new type method ********************/
    map<Function*, set<CallInst*>> LLVMDebugCallMap;

    //map type hash to the type pointer
    map<size_t, Type*> hashTypeMap;
    map<size_t, pair<Type*, int>> hashIDTypeMap;

    //cluster equal Types, each type maintains a corresponding equal type set
    //Once we parse a new type, check all recorded type and update this map
    unordered_map<unsigned, set<size_t>>subMemberNumTypeMap; //This faild on union type

    /************** type escape method ********************/
    set<size_t> escapedTypesInTypeAnalysisSet; //A subset of escaped type-id set
    map<size_t, set<StoreInst*>> escapedStoreMap;

    /************** debug data ********************/
    map<string, int> moduleIcallTargetsMap;

    void recordLoops(Function *F);    
    void unrollLoops(Function *F);
    bool checkLoop(Function *F);
    bool topSort(Function *F);

    set<Loop*> getSubLoops(DominatorTree* DT);

    //bool isCompositeType(Type *Ty);
    bool typeConfineInInitializer(GlobalVariable* GV);

    //Old implementation will miss some load/store based layer store
    //because of nextLayerBaseType does not consider store
    void typeConfineInStore_new(StoreInst *SI);
    bool typeConfineInCast(CastInst *CastI);
    bool typeConfineInCast(Type *FromTy, Type *ToTy);
    void escapeType(StoreInst* SI, Type *Ty, int Idx = -1);
    void transitType(Type *ToTy, Type *FromTy,
                    int ToIdx = -1, int FromIdx = -1);
    
    /************** layer analysis method ********************/
    Value *nextLayerBaseType(Value *V, Type * &BTy, int &Idx);
    bool nextLayerBaseType_new(Value *V, list<CompositeType> &TyList, 
        set<Value*> &VisitedSet, LayerFlag Mode = Precise_Mode); // A new implementation
    bool getGEPLayerTypes(GEPOperator *GEP, list<CompositeType> &TyList);
    bool getGEPIndex(Type* baseTy, int offset, Type * &resultTy, int &Idx);
    Type *getBaseType(Value *V, set<Value *> &Visited);
    Type *getPhiBaseType(PHINode *PN, set<Value *> &Visited);
    Type *getFuncPtrType(Value *V);
    Function *getBaseFunction(Value *V);
    Value *recoverBaseType(Value *V);
    void propagateType(Value *ToV, Type *FromTy, int FromIdx, StoreInst* SI);
    bool trackFuncPointer(Value* VO, Value* PO, StoreInst* SI);

    void funcSetIntersection(FuncSet &FS1, FuncSet &FS2,
                            FuncSet &FS); 
    void funcSetMerge(FuncSet &FS1, FuncSet &FS2);
    bool findCalleesWithMLTA(CallInst *CI, FuncSet &FS);
    void getOneLayerResult(CallInst *CI, FuncSet &FS);

    //New added method:
    void findCalleesWithTwoLayerTA(CallInst *CI, FuncSet PreLayerResult, Type *LayerTy, 
        int FieldIdx, FuncSet &FS, int &LayerNo, int &escape);
    Type *getLayerTwoType(Type* baseTy, vector<int> ids);

    //Tools
    bool isEscape(Type *LayerTy, int FieldIdx, CallInst *CI);
    void updateStructInfo(Function *F, Type* Ty, int idx, Value* context = NULL);
    string parseIdentifiedStructName(StringRef str_name);
    size_t callInfoHash(CallInst* CI, Function *Caller, int index);
    bool checkValidStructName(Type *Ty);
    bool checkValidIcalls(CallInst *CI);

    //Given a func declaration, find its global definition
    void getGlobalFuncs(Function *F, FuncSet &FSet);

    //Debug info handler
    BasicBlock* getParentBlock(Value* V);
    Type* getRealType(Value* V);
    void getDebugCall(Function* F);

public:
    CallGraphPass(GlobalContext *Ctx_)
        : IterativeModulePass(Ctx_, "CallGraph") { }
    virtual bool doInitialization(llvm::Module *);
    virtual bool doFinalization(llvm::Module *);
    virtual bool doModulePass(llvm::Module *);

    bool escapeChecker(StoreInst* SI, size_t escapeHash);
    void escapeHandler();
    bool oneLayerChecker(CallInst* CI, FuncSet &FS);
    void oneLayerHandler();

};

#endif
