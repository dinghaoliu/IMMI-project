#ifndef _TYPE_BUILDER_H
#define _TYPE_BUILDER_H

#include "../utils/include_llvm.h"
#include "../utils/Analyzer.h"
#include "../utils/Tools.h"
#include "../utils/Common.h"

#include <map> 
#include <vector> 
#include <stdlib.h>
#include <assert.h>
#include <set>

class TypeBuilderPass : public IterativeModulePass {

    public:

        static map<string, StructType*> identifiedStructType;

        static set<GlobalVariable*> targetGVSet;
        static map<size_t, string> ArrayBaseDebugTypeMap;

        // Use type-based analysis to find targets of indirect calls
        // Multi-layer type analysis supported

        void checkGlobalDebugInfo(GlobalVariable *GV, size_t Tyhash);
        void checkLayeredDebugInfo(GlobalVariable *GV);

        void matchStructTypes(Type *identifiedTy, User *U);

        //Tools
        string parseIdentifiedStructName(StringRef str_name);
        void updateTypeQueue(Type* Ty, deque<Type*> &Ty_queue);
        bool updateUserQueue(User* U, deque<User*> &U_queue);
        void updateQueues(Type* Ty1, Type* Ty2, deque<Type*> &Ty_queue);

        //Check if function arg cast to another type (for function pointer args)
        bool checkArgCast(Function *F);
        void combinate(int start, map<unsigned, set<Type*>> CastMap, vector<Type*> &cur_results);

        //Collect global literal structures
        void collectLiteralStruct(Module* M);
        void collectAliasStructPtr(Function *F);

    public:

        // General pointer types like char * and void *
        map<Module *, Type *>Int8PtrTy;

        TypeBuilderPass(GlobalContext *Ctx_)
            : IterativeModulePass(Ctx_, "TypeBuilder") { }
        virtual bool doInitialization(llvm::Module *);
        virtual bool doFinalization(llvm::Module *);
        virtual bool doModulePass(llvm::Module *);
};

#endif
