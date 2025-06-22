#ifndef TYPEDEF_H
#define TYPEDEF_H

#include "include_llvm.h"
#include <map>

using namespace std;

typedef map<string, Module*> ModuleMap;
// Mapping module to its file name.
typedef map<Module*, StringRef> ModuleNameMap;
// The set of all functions.
typedef SmallPtrSet<Function*, 8> FuncSet;
// Mapping from function name to function.
typedef map<string, set<size_t>> NameFuncMap;
typedef SmallPtrSet<CallInst*, 8> CallInstSet;
typedef DenseMap<Function*, CallInstSet> CallerMap;
typedef DenseMap<CallInst*, FuncSet> CalleeMap;
// Pointer analysis types.
typedef map<Value*, set<Value*>> PointerAnalysisMap;
typedef map<Function*, AAResults*> FuncAAResultsMap;
// init-fini analysis    
typedef map<ConstantStruct*, set<Function*>> StructInfoMap;
//struct type -> field offset.
typedef std::pair<Type*, int> CompositeType;

#endif