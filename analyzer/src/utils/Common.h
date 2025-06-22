#ifndef _COMMON_H_
#define _COMMON_H_

#include "include_llvm.h"

#include <unistd.h>
#include <bitset>
#include <chrono>
#include <time.h>
#include <fstream>
#include <regex>
#include <sstream>
#include "utils_macro.h"

using namespace llvm;
using namespace std;

string getFileName(DILocation *Loc, DISubprogram *SP=NULL, DIGlobalVariable *GV=NULL);
  
bool isConstant(Value *V);

string getSourceLine(string fn_str, unsigned lineno);
string getSourceLine(Instruction *I);
string getSourceLine(Function *F);
string getFunctionSourceCode(Function *F);

string getSourceFuncName(Instruction *I);

bool checkprintk(Instruction *I);

StringRef getCalledFuncName(CallInst *CI);

string extractMacro(string, Instruction* I);

DILocation *getSourceLocation(Instruction *I);

void printSourceCodeInfo(Value *V);
void printSourceCodeInfo(Function *F);
string getMacroInfo(Value *V);

void getSourceCodeInfo(Value *V, string &file,
                               unsigned &line);

Argument *getArgByNo(Function *F, int8_t ArgNo);

size_t valueHash(Value* V);
size_t funcHash(Function *F, bool withName = true);
size_t callHash(CallInst *CI);
size_t stringIdHash(string str, int Idx);
size_t typeHash(Type *Ty);
size_t typeNameIdxHash(Type *Ty, int Idx = -1);
size_t typeNameIdxHash(string Ty_name, int Idx = -1);
size_t typeIdxHash(Type *Ty, int Idx = -1);
size_t strHash(string str);
size_t hashIdxHash(size_t Hs, int Idx = -1);
string getTypeStr(Type *Ty);


#endif
