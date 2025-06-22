#include "Tools.h"

//Used for debug
unsigned getInstLineNo(Instruction *I){
begin:
    if(!I){
        //OP << "No such Inst\n";
        return 0;
    }
        
    //DILocation *Loc = dyn_cast<DILocation>(N);
    DILocation *Loc = I->getDebugLoc();
    if (!Loc ){
        //OP << "No such DILocation\n";
        auto nextInst = I->getNextNonDebugInstruction();
        I = nextInst;
        //return 0;
        goto begin;
    }

    unsigned Number = Loc->getLine();

    if(Number < 1){
        //OP << "Number < 1\n";
        auto nextInst = I->getNextNonDebugInstruction();
        I = nextInst;
        goto begin;
    }

    return Number;
}

//Used for debug
string getInstFilename(Instruction *I){
    // return I->getModule()->getSourceFileName();
begin:
    if (!I) { return ""; }
    DILocation *Loc = I->getDebugLoc();
    if (!Loc) {
        auto nextInst = I->getNextNonDebugInstruction();
        I = nextInst;
        goto begin;
    }
    string Filename = Loc->getFilename().str();
    if(Filename.length() == 0) {
        // lzp : tested over all 5.18, seems that the following will never happen:
        ELOG->warn("Get an DILocation without a filename, {0}, in {1}.", 
            common::llobj_to_string(I), I->getModule()->getSourceFileName());
        auto nextInst = I->getNextNonDebugInstruction();
        I = nextInst;
        goto begin;
    }
    return Filename;
}

//Used for debug
string getBlockName(BasicBlock *bb){
    if(!bb) return "NULL block";
    string Str;
    raw_string_ostream OS(Str);
    bb->printAsOperand(OS,false);
    return OS.str();
}

//Used for debug
string getValueName(Value* V){
    string Str;
    raw_string_ostream OS(Str);
    V->printAsOperand(OS,false);
    return OS.str();
}

//Used for debug
string getValueContent(Value* V){
    string Str;
    raw_string_ostream OS(Str);
    V->print(OS,false);
    return OS.str();
}

bool hasSubString(string ori_str, string target_substr) {
    if(ori_str.length() == 0 || target_substr.length() == 0)
        return false;
    return StringRef(ori_str).contains(target_substr);
}

//Check if there is a path from fromBB to toBB 
bool checkBlockPairConnectivity (BasicBlock* fromBB, BasicBlock* toBB){
    if(fromBB == NULL || toBB == NULL)
        return false;
    
    //Use BFS to detect if there is a path from fromBB to toBB
    list<BasicBlock *> EB = {fromBB}; //BFS record list
    set<BasicBlock *> PB; //Global value set to avoid loop

    while (!EB.empty()) {
        BasicBlock *CB = EB.front(); // Current checking block
        EB.pop_front();

        if (PB.count(CB))
            continue;
        PB.insert(CB);

        //Found a path
        if(CB == toBB)
            return true;

        for(BasicBlock *Succ: successors(CB)){
            EB.push_back(Succ);
        }

    }//end while

    return false;
}

bool isCompositeType(Type *Ty) {
    if (Ty->isStructTy() || 
        Ty->isArrayTy()  || 
        Ty->isVectorTy()
    ) { return true; }

    return false;
}

bool isStructOrArrayType(Type *Ty) {
    if (Ty->isStructTy() || Ty->isArrayTy())
        return true;
    else 
        return false;
}

// calculate by the file name | line number | function name.
size_t funcInfoHash(Function *F){
    hash<string> str_hash;
    string output = "";
    DISubprogram *SP = F->getSubprogram();
    if (SP) {
        output += SP->getFilename().str();
        output += to_string(SP->getLine());
    }
    output += F->getName();

    string::iterator end_pos = remove(output.begin(), 
        output.end(), ' ');
    output.erase(end_pos, output.end());
    return str_hash(output);
}

//Get the target string of __symbol_get()
string symbol_get_handler(CallInst* CAI){
    if(!CAI) { return ""; }

    Value* __symbol_get_arg = CAI->getArgOperand(0);
    if(GEPOperator *GEP = dyn_cast<GEPOperator>(__symbol_get_arg)){
        if(!GEP->hasAllConstantIndices()) { return ""; }
        
        // for(Use& it : GEP->indices()) {
        for(auto it = GEP->idx_begin() + 1; it != GEP->idx_end(); it++){
            ConstantInt *ConstI = dyn_cast<ConstantInt>(it->get()); // lzp : always correct? seems true now
            if(ConstI->getSExtValue() != 0) { return ""; }
        }

        Value *PO = GEP->getPointerOperand();
        GlobalVariable* globalVar = dyn_cast<GlobalVariable>(PO);
        if(!globalVar) { return ""; }

        Constant *Ini = globalVar->getInitializer();
        ConstantDataArray* CDA = dyn_cast<ConstantDataArray>(Ini);
        if(!CDA) { return ""; }

        StringRef name = CDA->getAsString();
        if(name.empty()) { return ""; }

        //NOTE: we need to filter the last char in the string
        return name.substr(0, name.size()-1).str();
    }
    return "";
}