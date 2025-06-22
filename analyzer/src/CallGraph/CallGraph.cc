#include "CallGraph.h"

using namespace llvm;

#define UNROLL_LOOP_ONCE 1

//#define ONE_LAYER_MLTA 1

//#define TEST_ONE_FUNC ""
//#define TEST_ONE_INIT_GLOBAL ""
//#define TEST_ONE_INIT_STORE ""

#define IGNORE_LINUX_STATIC_CALL 1 

CastInst* current_cast;

void CallGraphPass::typeConfineInStore_new(StoreInst *SI) {

    Value *PO = SI->getPointerOperand();
    Value *VO = SI->getValueOperand();

    if (isa<ConstantData>(VO))
        return;

    //A structure with 2-layer info is stored to PO
    set<Value*> VisitedSet;
    list<CompositeType> TyList;
    bool next_result = nextLayerBaseType_new(VO, TyList, VisitedSet, Recall_Mode);
    if (next_result) {
        for (CompositeType CT : TyList) {
            propagateType(PO, CT.first, CT.second, SI);
        }
        return;
    }
    else if (TyList.size() > 0) {
        
        for (CompositeType CT : TyList) {
            propagateType(PO, CT.first, CT.second, SI);
        }
        VisitedSet.clear();
        TyList.clear();

        nextLayerBaseType_new(PO, TyList, VisitedSet, Recall_Mode);
        for (CompositeType CT : TyList) {
            escapeType(SI, CT.first, CT.second);
            Ctx->num_escape_store++;
        }
        return;
    }

    //A structure/array/vector without 2-layer info is stored to PO
    //This is a common operation, ignore this case
    set<Value *>Visited;
    Type *VO_BTy = getBaseType(VO, Visited);
    if (VO_BTy) {
        
        //A special case: store a func pointer vec to a structure field
        if(VO_BTy->isVectorTy() && VO_BTy->getScalarType()->isPointerTy()){
            VectorType* FVT = dyn_cast<VectorType>(VO_BTy);
            if(!FVT){
                return;
            }

            ConstantVector* CV = dyn_cast<ConstantVector>(VO);
            if(CV){

                unsigned elenum = CV->getNumOperands();

                for (unsigned i = 0; i < elenum; i++) {

                    Value* O = CV->getOperand(i);
                    Function *F = getBaseFunction(O->stripPointerCasts());
                    if(F){

                        if (F->isIntrinsic())
                            continue;

                        FuncSet FSet = {};

                        if(F->isDeclaration()){
                            getGlobalFuncs(F,FSet);
                        }
                        else{
                            FSet.insert(F);
                        }

                        set<Value*> VisitedSet;
                        list<CompositeType> TyList;
                        if (nextLayerBaseType_new(PO, TyList, VisitedSet, Precise_Mode)) {

                            for(CompositeType CT : TyList){

                                Type* STy = CT.first;
                                int Idx = CT.second + i;

                                size_t typehash = typeHash(STy);
                                size_t typeidhash = typeIdxHash(STy,Idx);
                                hashTypeMap[typehash] = STy;
                                hashIDTypeMap[typeidhash] = make_pair(STy,Idx);

                                for(auto it = FSet.begin(); it != FSet.end(); it++){					
                                    F = *it;

                                    typeFuncsMap[typeIdxHash(STy, Idx)].insert(F);
                                    Ctx->sigFuncsMap[funcHash(F, false)].insert(F);

                                    if(Ctx->Global_Arg_Cast_Func_Map.count(F)){
                                        set<size_t> hashset = Ctx->Global_Arg_Cast_Func_Map[F];
                                        for(auto i = hashset.begin(); i!= hashset.end(); i++){
                                            Ctx->sigFuncsMap[*i].insert(F);
                                        }
                                    }
                                    
                                    //If STy is an invalid struct (e.g., union), F will be marked escape
                                    updateStructInfo(F, STy, Idx, SI);
                                }
                            }
                        }
                        else {

                            //A function is (possibly) stored to an unknown one-layer value, 
                            //we cannot track this case.
                            //So we mark this func as escape (record in Global_EmptyTy_Funcs).
                            for(auto it = FSet.begin(); it != FSet.end(); it++){	
                                auto F = *it;
                                Ctx->sigFuncsMap[funcHash(F, false)].insert(F);
                                Ctx->Global_EmptyTy_Funcs[funcHash(F, false)].insert(F);
                            }
                        }
                    }
                }
            }
        }
        return;
    }

    //A function is stored into sth
    Function *F = getBaseFunction(VO->stripPointerCasts());
    if(F){

        if (F->isIntrinsic())
            return;

        FuncSet FSet = {};

        if(F->isDeclaration()){
            getGlobalFuncs(F,FSet);
        }
        else{
            FSet.insert(F);
        }

        set<Value*> VisitedSet;
        list<CompositeType> TyList;
        if (nextLayerBaseType_new(PO, TyList, VisitedSet, Precise_Mode)) {

            for(CompositeType CT : TyList){

                Type* STy = CT.first;
                int Idx = CT.second;

                size_t typehash = typeHash(STy);
                size_t typeidhash = typeIdxHash(STy,Idx);
                hashTypeMap[typehash] = STy;
                hashIDTypeMap[typeidhash] = make_pair(STy,Idx);

                for(auto it = FSet.begin(); it != FSet.end(); it++){					
                    F = *it;

                    typeFuncsMap[typeIdxHash(STy, Idx)].insert(F);
                    Ctx->sigFuncsMap[funcHash(F, false)].insert(F);

                    if(Ctx->Global_Arg_Cast_Func_Map.count(F)){
                        set<size_t> hashset = Ctx->Global_Arg_Cast_Func_Map[F];
                        for(auto i = hashset.begin(); i!= hashset.end(); i++){
                            Ctx->sigFuncsMap[*i].insert(F);
                        }
                    }

                    //If STy is an invalid struct (e.g., union), F will be marked escape
                    updateStructInfo(F, STy, Idx, SI);
                }
            }
        }
        else {

            //A function is (possibly) stored to an unknown one-layer value, 
            //we cannot track this case.
            //So we mark this func as escape (record in Global_EmptyTy_Funcs).
            for(auto it = FSet.begin(); it != FSet.end(); it++){	
                F = *it;
                Ctx->sigFuncsMap[funcHash(F, false)].insert(F);
                Ctx->Global_EmptyTy_Funcs[funcHash(F, false)].insert(F);
            }
        }

        return;
    }

    if(!VO->getType()->isPointerTy())
        return;

    //A general-pointer without a known source is stored to PO
    //TODO: further check whether VO is unknown
    if(trackFuncPointer(VO, PO, SI)){
        return;
    }

    TyList.clear();
    VisitedSet.clear();
    nextLayerBaseType_new(PO, TyList, VisitedSet, Recall_Mode);
    for (CompositeType CT : TyList) {
        escapeType(SI, CT.first, CT.second);
        Ctx->num_escape_store++;
    }

    return;
}

bool CallGraphPass::typeConfineInCast(CastInst *CastI) {

    //OP<<"init - resolve cast: " << *CastI <<"\n";;
    // If a function address is ever cast to another type and stored
    // to a composite type, the escaping analysis will capture the
    // composite type and discard it
    Value *ToV = CastI, *FromV = CastI->getOperand(0);
    Type *ToTy = ToV->getType(), *FromTy = FromV->getType();

    return typeConfineInCast(FromTy, ToTy);
}

bool CallGraphPass::typeConfineInCast(Type *FromTy, Type *ToTy){

    // If a function address is ever cast to another type and stored
    // to a composite type, the escaping analysis will capture the
    // composite type and discard it
    if (isCompositeType(FromTy)) {
        transitType(ToTy, FromTy);
        return true;
    }

    if (!FromTy->isPointerTy() || !ToTy->isPointerTy()){
        return false;
    }

    typeStrCastMap[getTypeStr(ToTy)].insert(getTypeStr(FromTy));

    Type *EToTy = ToTy->getPointerElementType();
    Type *EFromTy = FromTy->getPointerElementType();
    if (isCompositeType(EToTy) && isCompositeType(EFromTy)) {
        transitType(EToTy, EFromTy);
        return true;
    }
    return false;
}

void CallGraphPass::escapeType(StoreInst* SI, Type *Ty, int Idx) {

    if(Ty->isStructTy()){

        if(Ty->getStructName().size() == 0){
            string Ty_name = Ctx->Global_Literal_Struct_Map[typeHash(Ty)];
            typeEscapeSet.insert(typeNameIdxHash(Ty_name, Idx));
            hashIDTypeMap[typeNameIdxHash(Ty_name, Idx)] = make_pair(Ty,Idx);
            escapedStoreMap[typeNameIdxHash(Ty_name, Idx)].insert(SI);
        }
        else{
            StringRef Ty_name = Ty->getStructName();
            string parsed_Ty_name = parseIdentifiedStructName(Ty_name);
            typeEscapeSet.insert(typeNameIdxHash(parsed_Ty_name, Idx));
            hashIDTypeMap[typeNameIdxHash(parsed_Ty_name, Idx)] = make_pair(Ty,Idx);
            escapedStoreMap[typeNameIdxHash(parsed_Ty_name, Idx)].insert(SI);

        }
    }

}

void CallGraphPass::transitType(Type *ToTy, Type *FromTy,
        int ToIdx, int FromIdx) {
    if (ToIdx != -1 && FromIdx != -1){
        //This part is under testing
        typeTransitMap[typeIdxHash(ToTy, ToIdx)].insert(typeIdxHash(FromTy, FromIdx));
        hashIDTypeMap[typeIdxHash(ToTy,ToIdx)] = make_pair(ToTy,ToIdx);
        hashIDTypeMap[typeIdxHash(FromTy,FromIdx)] = make_pair(FromTy,FromIdx);
    } else {
        //may should iteratively update struct member info
        typeTransitMap[typeHash(ToTy)].insert(typeHash(FromTy));
    }

    hashTypeMap[typeHash(ToTy)] = ToTy;
    hashTypeMap[typeHash(FromTy)] = FromTy;
}


bool CallGraphPass::doInitialization(Module *M) {
    current_module = M;
    DL = &(M->getDataLayout());
    
    // Iterate and process globals
    for (auto gi = M->global_begin(); gi != M->global_end(); ++gi) {
        GlobalVariable* GV = &*gi;

        if (!GV->hasInitializer())
            continue;
        
#ifdef TEST_ONE_INIT_GLOBAL
        if(GV->getName() != TEST_ONE_INIT_GLOBAL)
            continue;
#endif
        typeConfineInInitializer(GV);
    }

    
    // Iterate functions and instructions
    for (Function &F : *M) {
        if (F.isDeclaration()){
            if (F.hasAddressTaken()) {
                FuncSet FSet = {};
                getGlobalFuncs(&F,FSet);
                funcSetMerge(Ctx->sigFuncsMap[funcHash(&F, false)], FSet);
                Ctx->AddressTakenFuncs.insert(&F);
            }
            continue;
        }
#ifdef TEST_ONE_INIT_STORE
        if (F.getName() != TEST_ONE_INIT_STORE)
            continue;
#endif

        set<BitCastOperator*> CastSet;
        for (Instruction& I : instructions(F)) {

            if (StoreInst *SI = dyn_cast<StoreInst>(&I)) {
                typeConfineInStore_new(SI);
            }
            //Only this cast is not enough, some cast occurs directly in function arguments!!
            else if (CastInst *CastI = dyn_cast<CastInst>(&I)) {
                current_cast = CastI;
                typeConfineInCast(CastI);
            }
            // Operands of instructions can be BitCastOperator
            for (Use& OI : I.operands()) {
                if (BitCastOperator *CO = dyn_cast<BitCastOperator>(OI)) {
                    CastSet.insert(CO);
                }
            }
        }

        for (auto Cast : CastSet) {
            typeConfineInCast(Cast->getSrcTy(),Cast->getDestTy());
        }

        // Collect address-taken functions.
        if (F.hasAddressTaken()) {
            Ctx->AddressTakenFuncs.insert(&F); //not used in mlta
            Ctx->sigFuncsMap[funcHash(&F, false)].insert(&F); // hash without name, only type info
        }

        // Keep a single copy for same functions (inline functions)
        size_t fh = funcHash(&F);
        if (Ctx->UnifiedFuncMap.find(fh) == Ctx->UnifiedFuncMap.end()) {
            Ctx->UnifiedFuncMap[fh] = &F;
        }
    }
    return false;
}

static bool analyze_once = true;

bool CallGraphPass::doFinalization(Module *M) {
    return false;
}

bool CallGraphPass::doModulePass(Module *M) {
    current_module = M;
#ifdef ENHANCED_ONE_LAYER_COLLECTION
    if(analyze_once == true){
        for(auto p : Ctx->sigFuncsMap){
            FuncSet fset = p.second;
            if (fset.empty()) { continue; }
            // first function is enough, all functions in a FuncSet shares the same signature.
            Function *f = *fset.begin();  
            int ArgNo = f->arg_size();
            funcTypeMap[ArgNo].insert(make_pair(p.first, f->getFunctionType()));
        }
        analyze_once = false;
    }
#endif

    DL = &M->getDataLayout();

    // Use enhanced type-analysis to find possible targets of indirect calls.
    for (auto& f : *M) {
        Function *F = &f;
#ifdef TEST_ONE_FUNC
        if(F->getName()!=TEST_ONE_FUNC){
            continue;
        }
#endif

        //Record Global_Loop_Map
        recordLoops(F);

        //Unroll loops
#ifdef UNROLL_LOOP_ONCE
        unrollLoops(F);

        //Check the loop unroll result
        if(!checkLoop(F)){
            logger->warn("Loop unroll failed!!!");
            Ctx->LoopFuncs.insert(F);
            continue;
        }
        else if(!topSort(F)){
            logger->warn("topSort not pass!!!");
            Ctx->LoopFuncs.insert(F);
            continue;
        }
#endif
        // analysis main
        int icall_id = 0;
        // Collect callers and callees
        for (Instruction& I : instructions(F)) {
            // Map callsite to possible callees. 找间接调用
            if (CallInst *CI = dyn_cast<CallInst>(&I)) {
                bool icalltag = false;
                FuncSet FS = {};
                Function *CF = CI->getCalledFunction();

                //Ignore llvm debug funcs while constructing the global call graph
                if(CF && CF->getName().startswith("llvm.dbg")) {
                    continue; 
                }

                // Indirect call
                if (CI->isIndirectCall()) {
#ifdef IGNORE_LINUX_STATIC_CALL
                    if(checkValidIcalls(CI) == false)
                        continue;
#endif
                    icall_id++;

                    //Different bc files may contain the same call 
                    if(globalFuncNameMap.count(F->getName().str())){
                        size_t hash = callInfoHash(CI, F, icall_id);
                        if(globalFuncNameMap[F->getName().str()].count(hash)){
                            continue;
                        }
                    }

                    icalltag = true;
    
                    // Find the actual called function of CI
                    findCalleesWithMLTA(CI, FS);

                    for (Function* CalleeFunc : FS) {
                        Ctx->Callers[CalleeFunc].insert(CI);
                        Ctx->ICallers[CalleeFunc].insert(CI);
                    }
                    // Save called values for future uses (not used currently).
                    Ctx->IndirectCallInsts.push_back(CI);

                    globalFuncNameMap[F->getName().str()].insert(callInfoHash(CI, F, icall_id));
                }
                // Direct call
                else {
                    // not InlineAsm
                    if (CF) {
                        FuncSet FSet;
                        if(CF->empty())
                            getGlobalFuncs(CF,FSet);
                        else
                            FSet.insert(CF);

                        for(auto f: FSet) {
                            // Use unified function
                            size_t fh = funcHash(f);
                            Function* UF = Ctx->UnifiedFuncMap[fh];
                            if (UF) {
                                FS.insert(UF);
                                Ctx->Callers[UF].insert(CI); 
                            }
                        }
                    }
                    // InlineAsm
                    else {
                        
                    }
                }
                Ctx->Callees[CI] = FS;
                if (icalltag) {
                    Ctx->icallTargets+=FS.size();
                    Ctx->ICallees[CI] = FS;
                }
            }
        }
    }//end for loop
  return false;
}