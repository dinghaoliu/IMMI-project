#ifndef _UAF_CHECKER_H
#define _UAF_CHECKER_H

#include "../utils/include_llvm.h"
#include "../utils/Analyzer.h"
#include "../utils/Common.h"
#include "../utils/Tools.h"
#include "../utils/DBTools.h"
#include "../utils/DBTools.h"
#include "../FieldSensitiveAlias/FieldSensitiveAlias.h"
#include <mysql/mysql.h>
#include <sys/time.h>
#include <sstream>

class UAFCheckerPass : public IterativeModulePass {

    private:

        typedef struct DBInfo {

            string server;
            string user;
            string pw;
            string database;

            DBInfo(string s, string u, string p, string db){
                server = s;
                user = u;
                pw = p;
                database = db;
            }

        } DBInfo;
        
        typedef struct ReleaseDutySummary {

            // A callee function that allocated resources on heap,
            // which is visible to its callers
            string callee_name;

            //The callee does not release the resource on failure
            //In this case, the caller should release them on failure
            map<int, map<string, CallInst*>> OnFailReleaseDuty;

            //The callee has released the resource on failure
            //In this case, the caller should not release them on failure
            map<int, map<string, CallInst*>> OnFailureNotReleaseDuty;

            //Record the caller should release which values on success of callee
            map<int, set<string>> OnSuccessReleaseDuty;
            
            
            CallInstSet callers;

            ReleaseDutySummary(){
                callee_name = "";
                OnFailReleaseDuty.clear();
                OnFailureNotReleaseDuty.clear();
                OnSuccessReleaseDuty.clear();
                callers.clear();
            }

            ReleaseDutySummary(string fname, 
                map<int, map<string, CallInst*>> fail_duty,
                map<int, set<string>> success_duty){
                
                callee_name = fname;
                OnFailReleaseDuty = fail_duty;
                OnSuccessReleaseDuty = success_duty;
            }

        } ReleaseDutySummary;

        //Record release duty summary
        static map<string, ReleaseDutySummary*> GlobalDutySummaryMap;

        //Record release summary
        static map<string, map<int, set<string>>> GlobalReleaseSummaryMap;

        //Record nullification summary
        static map<string, map<int, set<string>>> GlobalNullSummaryMap;

        typedef struct ReleaseSummary {
            
            string Fname;
            int F_arg_id;
            CallInst* release_cai;
            int cai_arg_id;
            string field_access_arr;
            bool is_nullified;

            ReleaseSummary(){
                Fname = "";
                F_arg_id = -1;
                release_cai = NULL;
                cai_arg_id = -1;
                field_access_arr = "";
                is_nullified = false;
            }

            ReleaseSummary(string fname, int f_id, CallInst* cai, int cai_id, string arr, bool is_null){
                Fname = fname;
                F_arg_id = f_id;
                release_cai = cai;
                cai_arg_id = cai_id;
                field_access_arr = arr;
                is_nullified = is_null;
            }

        } ReleaseSummary;

        static map<string, map<CallInst*, set<int>>> GlobalAnalyzedFuncMap;
        static map<string, map<int, vector<ReleaseSummary*>>> GlobalReleaseTransitMap;

        //Return value check:
        enum ErrFlag {
            // error returning, mask:0xF
            Must_Return_Err = 1,
            May_Return_Err = 2,
            Not_Return_Err = 0,
            Reserved_Return2 = 8,
            // error handling, mask: 0xF0
            Must_Handle_Err = 16,
            May_Handle_Err = 32,
            Reserved_Handle1 = 64,
            Reserved_Handle2 = 128,
            Completed_Flag = 256,
        };

        typedef std::map<BasicBlock *, int> BBErrMap;
        typedef std::pair<Instruction *, BasicBlock *> CFGEdge;
        typedef std::pair<CFGEdge, Value *> EdgeValue;
        typedef std::map<CFGEdge, int> EdgeIgnoreMap;
        typedef std::map<CFGEdge, int> EdgeErrMap;
        static set<Instruction *>ErrSelectInstSet;

        static map<Function*, EdgeErrMap> GlobalErrEdgeMap;

        //Inst(key): branch inst(which is simple if)
        //BasicBlock(value): the end point of the if statement
        static map<Function*,map<Instruction*, BasicBlock*>> GlobalSimpleIfMap;

        //Global alias context
        AliasContext* GlobalAliasCtx = new AliasContext();
        
        static map<Function*, set<int>> GlobalFreeFuncMap;
        static map<CallInst*, set<int>> GlobalFreeCallMap;
        static map<Value*, CallInst*> GlobalFreedValueMap;
        static map<Value*, CallInst*> GlobalFreedValueWrapperMap;

        static set<size_t> GlobalAnalyzedSet; //Prevent redundant analysis

        //Run during the wrapper detection, record which functions are potential callers of v
        static map<Value*, set<Function*>> GlobalFreeInfluenceMap; 

        //key: funcname 
        //value: freed value, free_call_inst
        //TODO: record and summarize the free path's contrains
        static map<string, map<Value*, CallInst*>> GlobalFuncReleaseMap;
        static map<CallInst*, set<Value*>> GlobalFreeCallSummaryMap;

        //Find release function wrappers
        void identifyReleaseFuncs(Function *F);

        void identifyReleaseRange(Function *F, unsigned free_id, CallInst* free_cai);
        void identifyReleaseWrappers(CallInst* CI, int free_id);

        //Tools
        size_t getInstSourceInfo(Instruction *I);

        int checkFreedValueComesFromArg(CallInst* free_cai, 
            vector<int> &field_access_arr, bool &is_nullified, unsigned arg_id = 0,  
            AliasContext* LocalAliasCtx = NULL);
        bool isFreedValueNullified(CallInst* free_cai, unsigned arg_id);
        void recurGetFieldAccessArr(string fname, int f_arg_id, string pre_arr, 
            set<string>&arr, set<string>&nulligivstion_arr,
            map<CallInst*, set<int>> &analyzed_pairs, CallInst* pre_cai);
        bool get_field_access_arr(AliasContext*aCtx, AliasNode *start, 
            AliasNode *end, vector<int> &field_access_arr, 
            set<AliasNode*> &analyzed_set);
        bool recur_get_pre_path(BasicBlock* current_bb, set<BasicBlock*> &pre_path, 
            BasicBlock *entryBB);
        
        bool getFuncFromName(string fname, string &func_code);

        ////////////////////////////////////////////////////////
        //Duty analysis
        ////////////////////////////////////////////////////////
        void dutyAnalyzer(Function *F);
        Instruction* getArgStoreInst(CallInst *CI, int &Arg_idx, string &field_access_arr);
        void getReturnCheckBlocks(CallInst* CI, set<BasicBlock*> &bb_set);
        void getErrPath(EdgeErrMap errEdgeMap, BasicBlock *headBB, 
            vector<BasicBlock*> &path);
        void getFollowingErrPaths(Instruction* begin_I, CallInst* CI, 
            map<BasicBlock*, vector<BasicBlock*>> &err_path_map);
        void freeBehaviorAnalyzer(CallInst* CI, 
            map<BasicBlock*, vector<BasicBlock*>> err_path_map,
            int arg_idx, string access_hash);
        bool getCaiFollowingErrPath(CallInst* CI, vector<BasicBlock*> &err_path);
        bool getAliasNodeAccessArr(AliasContext*aCtx, 
            AliasNode *start, AliasNode *end, string &access_hash);

        ////////////////////////////////////////////////////////
        //Duty bug analysis
        ////////////////////////////////////////////////////////
        void dutyBugDetector();
        void handleOnFailReleaseDuty(string fname, map<int, map<string, CallInst*>> dutySum, CallInstSet callers);
        void handleOnFailureNotReleaseDuty(string fname, map<int, map<string, CallInst*>> dutySum, CallInstSet callers);
        void analyzePathFreeAction(AliasContext* actx, 
        Value* duty_value, set<string> duty_hash_set, 
        vector<BasicBlock*> path, set<string> &not_handled_hash_set, 
        bool &is_host_free);
        void checkCaller_should_release(CallInst* caller_cai, int arg_id, set<string> duty_resources, int max_execution_num,
        vector<string> &call_chain, string cai_source);
        void checkCaller_should_not_release(CallInst* caller_cai, int arg_id, set<string> duty_resources, int max_execution_num, vector<string> &call_chain, string cai_source);

        ////////////////////////////////////////////////////////
        //Return value analysis
        ////////////////////////////////////////////////////////

        // Find and record blocks with error returning
        void checkErrReturn(Function *F, BBErrMap &bbErrMap,
            std::map<BasicBlock *,Value *> &blockAttributeMap);

        // Collect all blocks that influence the return value
        void checkErrValueFlow(Function *F, ReturnInst *RI, 
            std::set<Value *> &PV, BBErrMap &bbErrMap,
            std::map<BasicBlock *,Value *> &blockAttributeMap);
        
        bool isValueErrno(Value *V, Function *F);

        // Mark the given block with an error flag.
        void markBBErr(BasicBlock *BB, ErrFlag flag, BBErrMap &bbErrMap);

        // Find same-origin variables from the given variable
        void findSameVariablesFrom(Value *V, std::set<Value *> &VSet);

        // A lighweiht and inprecise way to check if the function may
        // return an error
        bool mayReturnErr(Function *F);

        // infer error-handling branch for a condition
        int inferErrBranch(Instruction *Cond);

        // Traverse CFG to mark all edges with error flags
        bool markAllEdgesErrFlag(Function *F, BBErrMap &bbErrMap, EdgeErrMap &edgeErrMap);

        // Recursively mark edges from the error-handling block to the
        // closest branches
        void recurMarkEdgesToErrHandle(BasicBlock *BB, EdgeErrMap &edgeErrMap);

        // Incorporate newFlag into existing flag
        void updateReturnFlag(int &errFlag, int &newFlag);
        void updateHandleFlag(int &errFlag, int &newFlag);
        void mergeFlag(int &errFlag, int &newFlag);

        // Recursively mark all edges to the given block
        void recurMarkEdgesToBlock(CFGEdge &CE, int flag, 
            BBErrMap &bbErrMap, EdgeErrMap &edgeErrMap);

        // Recursively mark all edges from the given block
        void recurMarkEdgesFromBlock(CFGEdge &CE, int flag, 
            BBErrMap &bbErrMap, EdgeErrMap &edgeErrMap);

        // Recursively mark edges to the error-returning block
        void recurMarkEdgesToErrReturn(BasicBlock *BB, int flag, EdgeErrMap &edgeErrMap);

        // Some return values of function cannot be identified, use this to solve this problem
        void markCallCases(Function *F,Value * Cond, EdgeErrMap &edgeErrMap);

        void addSelfLoopEdges(Function *F,
            EdgeIgnoreMap &edgeIgnoreMap
        );

        bool checkEdgeErr(CFGEdge edge, EdgeErrMap edgeErrMap);

        // Dump marked edges.
        void dumpErrEdges(EdgeErrMap &edgeErrMap);
        void recurMarkErrEdges(EdgeIgnoreMap &errEdgeMap);

        ////////////////////////////////////////////////////////
        //DB Tools
        ////////////////////////////////////////////////////////
        void update_database(GlobalContext *Ctx, string bug_func_name, 
            string cai_info, string func_code_info);

        string insert_internal_bug_table(GlobalContext *Ctx, string bug_func_name, 
            string cai_info, string func_code_info);
        
        int init_database(DBInfo *db_info, MYSQL *mysql);

        int insert_func_info_table(DBInfo *db_info,
            string bug_func_name, string func_code_info);
        
        int insert_bug_table(DBInfo *db_info,
            string caller_responsibility, string bug_func_name, 
            string cai_info, string call_chain, string bb_chain);
        
        int init_release_db(DBInfo *db_info);

    public:
        UAFCheckerPass(GlobalContext *Ctx_)
         : IterativeModulePass(Ctx_, "UAFAnalysis") { }
        virtual bool doInitialization(llvm::Module *);
        virtual bool doFinalization(llvm::Module *);
        virtual bool doModulePass(llvm::Module *);

};

#endif