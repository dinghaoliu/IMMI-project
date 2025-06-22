#ifndef _GLOBAL_TOOLS_H
#define _GLOBAL_TOOLS_H

#include "include_llvm.h"

#include "Analyzer.h"
#include <algorithm>

bool hasSubString(string ori_str, string targetSubstr);

string getBlockName(BasicBlock *bb);
string getValueName(Value* V);
string getValueContent(Value* V);
string getInstFilename(Instruction *I);
unsigned getInstLineNo(Instruction *I);
bool isCompositeType(Type *Ty);
bool isStructOrArrayType(Type *Ty);

//Check if there is a path from fromBB to toBB 
bool checkBlockPairConnectivity(BasicBlock* fromBB, BasicBlock* toBB);

/////////////////////////////////////////////////
//    Data recording methods
/////////////////////////////////////////////////

//Calculate a unique hash for a function pointer
size_t funcInfoHash(Function *F);

/////////////////////////////////////////////////
//    Special case handler
/////////////////////////////////////////////////

//Get the target string of __symbol_get()
string symbol_get_handler(CallInst* CAI);


#endif