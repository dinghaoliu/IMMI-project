#include "CallGraph.h"

//This function could speed up
void CallGraphPass::funcSetIntersection(FuncSet &FS1, FuncSet &FS2, 
        FuncSet &FS) {
    FS.clear();
    
    for (auto F : FS1) {
        //Do not use pointer, use name, or we will miss function delcare
        if (FS2.find(F) != FS2.end())
            FS.insert(F);
    }

    //Use string match, 
    map<string, Function *> FS1_name_set, FS2_name_set;
    FS1_name_set.clear();
    FS2_name_set.clear();

    for (auto F : FS1) {
        string f_name = F->getName().str();
        if(f_name.size()>0)
            FS1_name_set.insert(make_pair(f_name,F));
    }

    for (auto F : FS2) {
        string f_name = F->getName().str();
        if(f_name.size()>0)
            FS2_name_set.insert(make_pair(f_name,F));
    }

    for (auto FName : FS1_name_set) {
        //Do not use pointer, use name, or we will miss function delcare
        if (FS2_name_set.find(FName.first) != FS2_name_set.end())
            FS.insert(FName.second);
    }
}	

//This function could speed up
//Merge FS2 into FS1
void CallGraphPass::funcSetMerge(FuncSet &FS1, FuncSet &FS2){
    for(auto F : FS2)
        FS1.insert(F);
}

Type *CallGraphPass::getLayerTwoType(Type* baseTy, vector<int> ids){

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

void CallGraphPass::updateStructInfo(Function *F, Type* Ty, int idx, Value* context){

    //Union prelayer is regarded as escape
    if(Ctx->Global_Union_Set.count(typeHash(Ty))){
        Ctx->num_local_info_name++;
        Ctx->Global_EmptyTy_Funcs[funcHash(F, false)].insert(F);
        return;
    }

    //Pre layer is struct without name
    if(Ty->isStructTy() && Ty->getStructName().empty()){
        string FuncName = F->getName().str();

        if(Ctx->Global_Literal_Struct_Map.count(typeHash(Ty))){
            // empty struct name but have debug info;
            Ctx->num_emptyNameWithDebuginfo++;
            string TyName = Ctx->Global_Literal_Struct_Map[typeHash(Ty)];
            if(hasSubString(TyName, "union.") || hasSubString(TyName, ".anon")){
                Ctx->num_local_info_name++;
                if(FuncName.size() != 0)
                    Ctx->Global_EmptyTy_Funcs[funcHash(F, false)].insert(F);
                return;
            }

            typeFuncsMap[typeNameIdxHash(TyName, idx)].insert(F);
            hashIDTypeMap[typeNameIdxHash(TyName,idx)] = make_pair(Ty,idx);
            if(context){
                Func_Init_Map[context][F].insert(typeNameIdxHash(TyName, idx));
            }
        } else {
            // empty struct name without debug info;
            //TODO: trace the typename in debuginfo
            Ctx->num_emptyNameWithoutDebuginfo++;
            
            if(FuncName.size() != 0) {
                Ctx->Global_EmptyTy_Funcs[funcHash(F, false)].insert(F);
            }
        }
    } else if(Ty->isStructTy()) { //Pre layer is struct with name
        Ctx->num_haveLayerStructName++;
        auto TyName = Ty->getStructName().str();
        if(hasSubString(TyName, "union.")) {
            Ctx->Global_Union_Set.insert(typeHash(Ty));
        }
        if (hasSubString(TyName, "union.") || hasSubString(TyName, ".anon")) {
            Ctx->num_local_info_name++;
            if(!F->getName().empty()){
                Ctx->Global_EmptyTy_Funcs[funcHash(F, false)].insert(F);
            }
            return;
        }

        // lzp TODO: what about parsed_TyName == "" ? will the Hash still percise?
        string parsed_TyName = parseIdentifiedStructName(TyName);
        typeFuncsMap[typeNameIdxHash(parsed_TyName, idx)].insert(F);
        hashIDTypeMap[typeNameIdxHash(parsed_TyName,idx)] = make_pair(Ty,idx);
        if(context){
            Func_Init_Map[context][F].insert(typeNameIdxHash(parsed_TyName, idx));
        }
    } else if(Ty->isArrayTy()) { //Prelayer is array
        Ctx->num_array_prelayer++;
        Ctx->num_local_info_name++;
        //TODO: resolve array prelayer info
        Ctx->Global_EmptyTy_Funcs[funcHash(F, false)].insert(F);
    } else {
        Ctx->num_local_info_name++;
        Ctx->Global_EmptyTy_Funcs[funcHash(F, false)].insert(F);
    }
}

string CallGraphPass::parseIdentifiedStructName(StringRef str_name){
    if(str_name.empty())
        return "";

    if(str_name.contains("struct.")){
        return str_name.substr(7, str_name.size()-1).str();
    } else if(str_name.contains("union.")){
        return str_name.substr(6, str_name.size()-1).str();
    }

    return "";
}

size_t CallGraphPass::callInfoHash(CallInst* CI, Function *Caller, int index){
    
    hash<string> str_hash;
    string output;
    output = getInstFilename(CI);

    string sig;
    raw_string_ostream rso(sig);
    Type *FTy = Caller->getFunctionType();
    FTy->print(rso);
    output += rso.str();
    output += Caller->getName();

    string::iterator end_pos = remove(output.begin(), 
            output.end(), ' ');
    output.erase(end_pos, output.end());
    
    stringstream ss;
    unsigned linenum = getInstLineNo(CI);
    ss<<linenum;
    ss<<index;
    output += ss.str();

    return str_hash(output);
}

//Given a func declarition, find its global definition
void CallGraphPass::getGlobalFuncs(Function *F, FuncSet &FSet){
    assert(FSet.empty());

    StringRef FName = F->getName();
    if(Ctx->GlobalFuncs.count(FName.str())){
        set<size_t> hashSet = Ctx->GlobalFuncs[FName.str()];
        for(auto key : hashSet){
            Function *f = Ctx->Global_Unique_Func_Map[key];
            FSet.insert(f);
        }
    }

    if(FSet.empty()){
        size_t funchash = funcInfoHash(F);
        if(Ctx->Global_Unique_Func_Map.count(funchash)){
            Function *f = Ctx->Global_Unique_Func_Map[funchash];
            FSet.insert(f);
        }
    }
}

bool CallGraphPass::checkValidStructName(Type *Ty){

    if(Ty->getStructName().size() != 0){

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
        if(Ctx->Global_Literal_Struct_Map.count(typeHash(Ty))){

            string TyName = Ctx->Global_Literal_Struct_Map[typeHash(Ty)];
            if(hasSubString(TyName, ".union")){
                return false;
            }

            if(hasSubString(TyName, ".anon")){
                return false;
            }

            return true;
        }
        else{
            return false;
        }
    }
}

//Used to check the Linux Static calls
//This could be improved
bool CallGraphPass::checkValidIcalls(CallInst *CI){

    unsigned line_number = getInstLineNo(CI);
    string file_loc = getInstFilename(CI);

    for(auto i : Ctx->IcallIgnoreLineNum){
        if(to_string(line_number) == i){
            for(auto j : Ctx->IcallIgnoreFileLoc){
                if(file_loc == j){
                    return false;
                }
            }
        }
    }

    return true;
}