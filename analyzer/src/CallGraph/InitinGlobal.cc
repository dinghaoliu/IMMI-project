#include "CallGraph.h"

using namespace llvm;

bool CallGraphPass::typeConfineInInitializer(GlobalVariable* GV) {

    Constant *Ini = GV->getInitializer();
    if (!isa<ConstantAggregate>(Ini))
        return false;

    list<User*> LU = {Ini};

    if(GV->getName() == "llvm.used" || GV->getName() == "llvm.compiler.used") return false;

    //maybe should consider deadloop
    set<User*> PB = {};

    //should consider global struct array
    while (!LU.empty()) {
        User *U = LU.front();
        LU.pop_front();

        if (PB.find(U) != PB.end()) { continue; }
        PB.insert(U);

        for (auto oi = U->op_begin(); oi != U->op_end(); ++oi) {
            Value *O = *oi;
            Type *OTy = O->getType();
            // Case 1: function address is assigned to a type
            // FIXME: it seems this cannot get declared func
            if (Function *F = dyn_cast<Function>(O)) {
                Type *ITy = U->getType();
                // TODO: use offset?
                unsigned ONo = oi->getOperandNo();

                FuncSet FSet = {};

                if(F->isDeclaration()){
                    getGlobalFuncs(F,FSet);
                } else {
                    FSet.insert(F);
                }

                for(auto F : FSet){
                    typeFuncsMap[typeIdxHash(ITy, ONo)].insert(F);
                    
                    Ctx->sigFuncsMap[funcHash(F, false)].insert(F); //only single type info
                    
                    if(Ctx->Global_Arg_Cast_Func_Map.count(F)){
                        set<size_t> hashset = Ctx->Global_Arg_Cast_Func_Map[F];
                        for(auto h : hashset){
                            Ctx->sigFuncsMap[h].insert(F);
                        }
                    }

                    //Use the new type to store
                    size_t typehash = typeHash(ITy);
                    size_t typeidhash = typeIdxHash(ITy,ONo);
                    hashTypeMap[typehash] = ITy;
                    hashIDTypeMap[typeidhash] = make_pair(ITy,ONo);

                    updateStructInfo(F, ITy, ONo, GV);
                }
            }
            
            // Case 2: a composite-type object (value) is assigned to a
            // field of another composite-type object
            // A type is confined by another type
            else if (isCompositeType(OTy)) {
                // confine composite types
                Type *ITy = U->getType();
                unsigned ONo = oi->getOperandNo();

                // recognize nested composite types
                User *OU = dyn_cast<User>(O);
                LU.push_back(OU);
            }
            // Case 3: a reference (i.e., pointer) of a composite-type
            // object is assigned to a field of another composite-type
            // object
            else if (PointerType *POTy = dyn_cast<PointerType>(OTy)) {
                if (isa<ConstantPointerNull>(O)) continue;
                // if the pointer points a composite type, skip it as
                // there should be another initializer for it, which
                // will be captured

                Type *eleType = POTy->getPointerElementType();
                if(isCompositeType(eleType)){
                    Type *ITy = U->getType();
                    unsigned ONo = oi->getOperandNo();
                    //FIXME: do we need to omit pointer type info?

                    // recognize nested composite types
                    User *OU = dyn_cast<User>(O);
                    LU.push_back(OU);
                }
                
                if (BitCastOperator *CO = dyn_cast<BitCastOperator>(O)) {

                    Type *ToTy = CO->getDestTy(), *FromTy = CO->getSrcTy();
                    Value *Operand = CO->getOperand(0);

                    if(Function *F = dyn_cast<Function>(Operand)){
                        Type *ITy = U->getType();
                        unsigned ONo = oi->getOperandNo();

                        FuncSet FSet = {};

                        if(F->isDeclaration()){
                            getGlobalFuncs(F,FSet);
                        }
                        else{
                            FSet.insert(F);
                        }

                        for(auto F : FSet){
                            typeFuncsMap[typeIdxHash(ITy, ONo)].insert(F);
                            Ctx->sigFuncsMap[funcHash(F, false)].insert(F);
                            if(Ctx->Global_Arg_Cast_Func_Map.count(F)){
                                set<size_t> hashset = Ctx->Global_Arg_Cast_Func_Map[F];
                                for(auto h : hashset){
                                    Ctx->sigFuncsMap[h].insert(F);
                                }
                            }

                            //Use the new type to store
                            size_t typehash = typeHash(ITy);
                            size_t typeidhash = typeIdxHash(ITy,ONo);
                            hashTypeMap[typehash] = ITy;
                            hashIDTypeMap[typeidhash] = make_pair(ITy,ONo);

                            updateStructInfo(F, ITy, ONo, GV);
                        }
                    }
                }
            }
            else{
            }
        }
    }

    return true;
}
