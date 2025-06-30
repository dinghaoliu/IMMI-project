#include "TypeBuilder.h"
#include "llvm/BinaryFormat/Dwarf.h"
#include "llvm/IR/User.h"
#include "../utils/Errors.h"


using namespace llvm;

//#define TEST_ONE_INIT_GLOBAL ""
//#define DEBUG_PRINT

map<string, StructType*> TypeBuilderPass::identifiedStructType;

map<size_t, string> TypeBuilderPass::ArrayBaseDebugTypeMap;
set<GlobalVariable*> TypeBuilderPass::targetGVSet;

// TODO: could be replaced by my tool
void TypeBuilderPass::checkGlobalDebugInfo(GlobalVariable *GV, size_t TyHash){
    MDNode* N = GV->getMetadata("dbg");
    if (!N) return;
    
    DIGlobalVariableExpression* DIGVE = dyn_cast<DIGlobalVariableExpression>(N);
    if(!DIGVE) return;

    DIGlobalVariable* DIGV = DIGVE->getVariable();
    if(!DIGV) return;

    DIType* DITy = DIGV->getType();
    if(!DITy) return;

    DIType* currentDITy = DITy;
    while(true){
        DIDerivedType* DIDTy = dyn_cast<DIDerivedType>(currentDITy);
        if(DIDTy){
            currentDITy = DIDTy->getBaseType();
            continue;
        } else {
            break;
        }
    }
    //Our target is CompositeType
    DICompositeType* DICTy = dyn_cast<DICompositeType>(currentDITy);
    if (!DICTy) { return; } // TODO: what if not composite Type

    unsigned tag = DICTy->getTag();
    switch (DICTy->getTag()) {
        case dwarf::DW_TAG_array_type: {
            Ctx->Global_Literal_Struct_Map[TyHash] = "Array";

            currentDITy = DICTy->getBaseType();
            DIDerivedType *DIDTy = dyn_cast<DIDerivedType>(currentDITy);
            if(DIDTy){
                currentDITy = DIDTy->getBaseType();
            }

            DICTy = dyn_cast<DICompositeType>(currentDITy);
            if(!DICTy) break;
                    
            tag = DICTy->getTag();
            if(tag == dwarf::DW_TAG_structure_type){
                StringRef typeName = DICTy->getName();
                if(typeName.size() != 0)
                    ArrayBaseDebugTypeMap[TyHash] = typeName.str();
                break;
            }
            break;
        } 
        case dwarf::DW_TAG_structure_type: {
            StringRef typeName = DICTy->getName();
            if(typeName.size() != 0)
                Ctx->Global_Literal_Struct_Map[TyHash] = typeName.str();
            return;
        }
        default: {
            // throw GeneralException("DW_TAG {0} not supported", tag);
            break;
        }
    }
}

void TypeBuilderPass::matchStructTypes(Type *identifiedTy, User *U){
    if(!identifiedTy || !U) return;

    deque<Type*> Ty1_queue = {identifiedTy};
    deque<User*> U2_queue = {U};

    while (!Ty1_queue.empty() && !U2_queue.empty()) {
        Type* type1 = Ty1_queue.front();
        Ty1_queue.pop_front();
        User* u2 = U2_queue.front();
        U2_queue.pop_front();
        Type* type2 = u2->getType();
    
        if ((type1 == type2) || 
            (type1->isPointerTy() && type2->isPointerTy()) ||
            (type1->isFunctionTy() && type2->isFunctionTy()) ||
            (typeHash(type1) == typeHash(type2))
        ) { continue; }

        if (type1->isIntegerTy() && type2->isIntegerTy()) {
            IntegerType* inty1 = dyn_cast<IntegerType>(type1);
            IntegerType* inty2 = dyn_cast<IntegerType>(type2);
            unsigned bitwidth1 = inty1->getBitWidth();
            unsigned bitwidth2 = inty2->getBitWidth();

            if(bitwidth1 == bitwidth2) continue;

            LLVMContext &C = type1->getContext();
            IntegerType* generated_int = IntegerType::get(C,bitwidth2);

            int times = bitwidth1/bitwidth2;
            for(int i = 0; i < times; i++){
                Ty1_queue.push_front(generated_int);
            }
            U2_queue.push_front(u2);
            continue;
        } 

        if (type2->isStructTy()) {
            //We already have name of type2, continue
            if (!type2->getStructName().empty()) { continue; }
            
            if (type1->isStructTy()) {
                //type2 has no name, find it
                if(Ctx->Global_Literal_Struct_Map.count(typeHash(type2)) == 0){
                    StringRef type1_structname = type1->getStructName();
                    string parsed_name = parseIdentifiedStructName(type1_structname);
                    if(parsed_name.size() != 0){
                        Ctx->Global_Literal_Struct_Map[typeHash(type2)] = parsed_name;
                    }
                }

                StringRef type1_structname = type1->getStructName();
                if(type1_structname.contains("union.")){
                    //Once we meet a union, stop further analysis 
                    Ctx->Global_Union_Set.insert(typeHash(type2));
                    continue;
                }

                if(updateUserQueue(u2, U2_queue)){
                    updateTypeQueue(type1, Ty1_queue);
                }
            }

            if (type1->isArrayTy()){
                //We need to mark this case
                if(Ctx->Global_Literal_Struct_Map.count(typeHash(type2)) == 0){
                    Ctx->Global_Literal_Struct_Map[typeHash(type2)] = "Array";
                }

                if(updateUserQueue(u2, U2_queue) == false) { continue; }

                ArrayType* arrTy = dyn_cast<ArrayType>(type1);
                for(int i = 0; i < arrTy->getNumElements(); i++){
                    Ty1_queue.push_front(arrTy->getElementType());
                }
            }
            continue;
        }

        if (type2->isArrayTy()){
            Type* subtype2 = type2->getArrayElementType();
            unsigned subnum2 = type2->getArrayNumElements();

            if(type1->isArrayTy()){
                unsigned subnum1 = type1->getArrayNumElements();

                if(subnum1 == 0 || subnum2 == 0) { continue; }

                if(subnum1 == subnum2) {
                    Ty1_queue.push_front(type1->getArrayElementType());
                    U2_queue.push_front(dyn_cast<User>(*u2->op_begin()));
                }

            } else {
                //Here type1 usually is a single value
                updateQueues(type1, type2, Ty1_queue);

            }
            continue;
        }
        logger->warn("Unexpected case: {0} | {1}", 
            common::llobj_to_string(type1), common::llobj_to_string(type2));
        // OP<<"Unexpected case!\n" << *type1;
    }

    if(Ty1_queue.size() != U2_queue.size()){
        logger->warn("matchStructTypes Ty1_queue.size() != U2_queue.size()");
    }
}

void TypeBuilderPass::checkLayeredDebugInfo(GlobalVariable *GV){

    Constant *Ini = GV->getInitializer();
    list<User *> LU = list<User *>({Ini});
    // Global value set to avoid loop
    set<User *> PB = set<User *>(); 

    //should consider global struct array
    while (!LU.empty()) {
        User *U = LU.front();
        LU.pop_front();

        if (PB.find(U) != PB.end()) { continue; }
        PB.insert(U);

        Type *ITy = U->getType();
        size_t PreTyHash = typeHash(ITy);

        if(!Ctx->Global_Literal_Struct_Map.count(PreTyHash)) { continue; }
        
        string PreLayerName = Ctx->Global_Literal_Struct_Map[PreTyHash];
        
        if(identifiedStructType.count(PreLayerName)) { 
            matchStructTypes(identifiedStructType[PreLayerName], U);
            continue; 
        }
        
        if(!(PreLayerName == "Array")) { continue; }
        if(!ITy->isStructTy() && !ITy->isArrayTy()) { continue; }

        for (auto op_it = U->op_begin(); op_it != U->op_end(); ++op_it) {
            if(dyn_cast<UndefValue>(*op_it)) { continue; }
            if((*op_it)->getType()->isArrayTy()) { continue; };

            if(ArrayBaseDebugTypeMap.count(PreTyHash)){
                string ArrayEleTypeName = ArrayBaseDebugTypeMap[PreTyHash];
                if(identifiedStructType.count(ArrayEleTypeName) == 0){ continue; }

                User *OU = dyn_cast<User>(*op_it);
                matchStructTypes(identifiedStructType[ArrayEleTypeName], OU);
            }
        }  
    }
}

void TypeBuilderPass::collectLiteralStruct(Module* M){

    if(!M)
        return;

    vector<StructType*> structTy_vec = M->getIdentifiedStructTypes();
    for(StructType* STy : structTy_vec){

        if(STy->isOpaque())
            continue;

        StringRef struct_name = STy->getName();
        Ctx->Global_Literal_Struct_Name_Map[struct_name.str()] = STy;
    }
}

// This function precisely collect alias types for general pointers
void TypeBuilderPass::collectAliasStructPtr(Function *F) {

    map<Value *, Value *> &AliasMap = Ctx->AliasStructPtrMap[F];
    set<Value *>ToErase;
    for (inst_iterator i = inst_begin(F), e = inst_end(F); 
            i != e; ++i) {

        Instruction *I = &*i;

        if (CastInst *CI = dyn_cast<CastInst>(I)) {
            Value *FromV = CI->getOperand(0);
            // TODO: we only consider calls for now
            if (!isa<CallInst>(FromV))
                continue;

            Type *FromTy = FromV->getType();
            Type *ToTy = CI->getType();
            if (Int8PtrTy[F->getParent()] != FromTy)
                continue;

            if (!ToTy->isPointerTy())
                continue;
            
            if (!isCompositeType(ToTy->getPointerElementType()))
                continue;

            if (AliasMap.find(FromV) != AliasMap.end()) {
                ToErase.insert(FromV);
                continue;
            }
            AliasMap[FromV] = CI;
        }
    }
    for (auto Erase : ToErase)
        AliasMap.erase(Erase);
}

bool TypeBuilderPass::doInitialization(Module *M) {
    collectLiteralStruct(M);
    Int8PtrTy[M] = Type::getInt8PtrTy(M->getContext());

    for (auto gi = M->global_begin(); gi != M->global_end(); ++gi) {

        GlobalVariable* GV = &*gi;

        //Init global variable map for dataflow analysis
        Ctx->Global_Unique_GV_Map[GV->getGUID()].insert(GV);

        if (!GV->hasInitializer())
            continue;

        Constant *Ini = GV->getInitializer();
        if (!isa<ConstantAggregate>(Ini))
            continue;
        
    #ifdef TEST_ONE_INIT_GLOBAL
            if(GV->getName() != TEST_ONE_INIT_GLOBAL)
                continue;
    #endif

        Type* GType = GV->getType();
        Type* GPType = GType->getPointerElementType();
        size_t TyHash = typeHash(GPType);

        if(GPType->isArrayTy()){
            Type* innerTy = GPType->getArrayElementType();
            if(innerTy->isStructTy()){
                StructType* innerSTy = dyn_cast<StructType>(innerTy);
                if(innerSTy->isLiteral()){
                    checkGlobalDebugInfo(GV, TyHash);
                    targetGVSet.insert(GV);
                }
            }
            continue;
        }

        if(GPType->isStructTy()){
            StructType* GPSType = dyn_cast<StructType>(GPType);
            if(GPSType->isLiteral()){
                Ctx->num_typebuilder_haveNoStructName++;
                checkGlobalDebugInfo(GV, TyHash);
                targetGVSet.insert(GV);
            } else {
                Ctx->num_typebuilder_haveStructName++;
            }
            continue;
        }
    }

    //Init some global info here
    for (Function &F : *M) {

        Ctx->Global_Unique_GV_Map[F.getGUID()].insert(&F);

        if(F.hasAddressTaken()){
            Ctx->Global_AddressTaken_Func_Set.insert(&F);
            size_t funchash = funcInfoHash(&F);
            if(Ctx->Global_Unique_Func_Map.count(funchash) == 0)
                Ctx->Global_Unique_Func_Map[funchash] = &F;
        }

        if (F.isDeclaration())
            continue;
        
        if(!F.empty()){
            StringRef FName = F.getName();
            size_t funchash = funcInfoHash(&F);
            Ctx->GlobalAllFuncs[FName.str()].insert(funchash);
            Ctx->Global_Unique_All_Func_Map[funchash] = &F;
        }

        // Collect global function definitions.
        if ((F.hasExternalLinkage() && !F.empty()) || F.hasAddressTaken()) {
            StringRef FName = F.getName();
            size_t funchash = funcInfoHash(&F);
            Ctx->GlobalFuncs[FName.str()].insert(funchash);
            Ctx->Global_Unique_Func_Map[funchash] = &F;
        }

    }
    return false;
}

bool TypeBuilderPass::doFinalization(Module *M) {

    return false;
}

bool TypeBuilderPass::doModulePass(Module *M) {

    //The struct type tabel in a single module has no redundant info
    vector <StructType*> identifiedStructTys = M->getIdentifiedStructTypes();
    for(auto it = identifiedStructTys.begin(); it != identifiedStructTys.end(); it++){
        StructType* STy = *it;
        StringRef STy_name = STy->getName();
        
        if(STy_name.size() == 0)
            continue;

        string parsed_STy_name = parseIdentifiedStructName(STy_name);
        identifiedStructType[parsed_STy_name] = STy;
    }

    for (Module::global_iterator gi = M->global_begin(); 
            gi != M->global_end(); ++gi) {
        GlobalVariable* GV = &*gi;
    
        if (!GV->hasInitializer())
            continue;
        
        Constant *Ini = GV->getInitializer();
        if (!isa<ConstantAggregate>(Ini))
            continue;
        
    #ifdef TEST_ONE_INIT_GLOBAL
            if(GV->getName() != TEST_ONE_INIT_GLOBAL)
                continue;
    #endif

        //Only focus on target set
        if(targetGVSet.count(GV) == 0)
            continue;

        checkLayeredDebugInfo(GV);

    }

    identifiedStructType.clear();


    return false;
}