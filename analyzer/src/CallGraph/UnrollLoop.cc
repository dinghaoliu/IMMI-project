#include "CallGraph.h"

//return true if sort successed, or return false (there is a loop inside function)
bool CallGraphPass::topSort(Function *F){
    if(!F){
        return true;
    }

    map<BasicBlock*,int> indegreeMap;
    BasicBlock* currentblock;
    indegreeMap.clear();

    //init
    for (auto& bb : *F) {
        pair<BasicBlock*,int> value(&bb,0);
        indegreeMap.insert(value);
    }

    //init indegreeMap
    for (auto& bb : *F) {
        for (BasicBlock *Succ : successors(&bb)) {
            if(Succ == &bb)
                continue;
            indegreeMap[Succ]++;
        }
    }

    bool found = false;
    while(!indegreeMap.empty()){

        found = false;
        //find a block with 0 indegree
        for(auto it = indegreeMap.begin(); it != indegreeMap.end(); it++){
            if(it->second==0){
                currentblock = it->first;
                found=true;
                break;
            }
        }

        if(!found){
            return false;
        }

        for (BasicBlock *Succ : successors(currentblock)) {
            if(Succ == currentblock)
                continue;
            indegreeMap[Succ]--;
        }

        indegreeMap.erase(currentblock);

    }
    return true;

}

void CallGraphPass::recordLoops(Function *F) {
    if (F->isDeclaration()) { return; }
    
    DominatorTree DT = DominatorTree();
    DT.recalculate(*F);
    LoopInfo *LI = new LoopInfo();
    LI->releaseMemory();
    LI->analyze(DT);

    for (LoopInfo::iterator i = LI->begin(), e = LI->end(); i!=e; ++i) {
        Loop *LP = *i;
        Ctx->Global_Loop_Map[F].insert(LP);
    }	
}

//lzp long-term todo: split this into unroll single loop and unroll loops in function
void CallGraphPass::unrollLoops(Function *F) {
    if (F->isDeclaration()) return;
    DominatorTree DT = DominatorTree();
    DT.recalculate(*F);
    set<Loop*> LPSet = getSubLoops(&DT);

    for (Loop *LP : LPSet) {
        // Get the header, latch block, exiting block of every loop
        BasicBlock* HeaderBB = LP->getHeader();
        unsigned NumBE = LP->getNumBackEdges();
        SmallVector<BasicBlock*, 4> LatchBBs;

        LP->getLoopLatches(LatchBBs);

        for (BasicBlock* LatchBB : LatchBBs) {
            if (!HeaderBB || !LatchBB) {
                logger->error("Cannot find Header Block or Latch Block\n");
                continue;
            }
            // Two cases:
            // 1. Latch Block has only one successor:
            //  for loop or while loop;
            //  In this case: set the successor of the Latch Block to 
            //  the exit successor of Header block
            // 2. Latch Block has two successor: 
            // do-while loop:
            // In this case: set the Successor of Latch Block to the
            // exit successor of Latch block 

            // get the last instruction in the Latch block
            Instruction *LBB_TI = LatchBB->getTerminator();
            // Case 1:
            //If assume this is a for loop, then assume there must be one
            //successor of HeaderBB can jump out the loop, which may be broken
            //by some goto instructions (no successor can jump out) 
            
            if (LatchBB->getSingleSuccessor()) {
                int NumDominate = 0;
                for (succ_iterator sit = succ_begin(HeaderBB); 
                        sit != succ_end(HeaderBB); ++sit) {  

                    BasicBlock *SuccBB = *sit;
                    BasicBlockEdge BBE = BasicBlockEdge(HeaderBB, SuccBB);
                    // Header block has two successor,
                    // one edge dominate Latch block;
                    // another does not.
                    if (DT.dominates(BBE, LatchBB)){
                        continue;
                    } else {
                        NumDominate++;
                        // lzp : set the successor of latch into the exit BB (non-latch branch in header)
                        LBB_TI->setSuccessor(0, SuccBB); 
                    }
                }

                //Special case: all successors fall in loop or out of loop
                //Equal to 0 or 2
                if(NumDominate!=1){
                    // logger->warn("Unexpected NumDominate {0} in {1} \n staring at {2}", 
                    //     NumDominate, F->getName().str(), common::llobj_to_string(HeaderBB));
                    //Set the successor to itself
                    LBB_TI->setSuccessor(0, LatchBB);
                }
            }
            // Case 2:
            else {
                for (int i = 0; i < LBB_TI->getNumSuccessors(); ++i) {

                    BasicBlock *SuccB = LBB_TI->getSuccessor(i);
                    if (SuccB == HeaderBB){
                        BasicBlock* targetBB;
                        if(i!=0)
                            targetBB=LBB_TI->getSuccessor(0);
                        else
                            targetBB=LBB_TI->getSuccessor(1);

                        Value *Cond = NULL;
                        BranchInst *BI = dyn_cast<BranchInst>(LBB_TI);
                        if(BI){
                            if(BI->isConditional())
                                Cond = BI->getCondition();
                        }
                        if(Cond){

                            Constant *Ct = dyn_cast<Constant>(Cond);
                            if(Ct && Ct->isOneValue() && targetBB != LBB_TI->getSuccessor(0)){
                                //OP<<"This is invalid\n";
                                continue;
                            }
                        }

                        LBB_TI->setSuccessor(i, targetBB);
                        continue;
                    }
                }	
            }
        }

        Instruction *HeaderBB_TI = HeaderBB->getTerminator();
        map<BasicBlock *,int> HeaderBB_Follow_BBs = {};
        for(int i = 0; i < HeaderBB_TI->getNumSuccessors(); ++i){
            BasicBlock *SuccBB = HeaderBB_TI->getSuccessor(i);
            if(SuccBB == HeaderBB) { continue; }
            HeaderBB_Follow_BBs[SuccBB] = i;
        }

        for (BasicBlock *LatchBB : LatchBBs) {
            if (!HeaderBB || !LatchBB) {
                OP<<"ERROR: Cannot find Header Block or Latch Block\n";
                continue;
            }
            
            Instruction *LatchB_TI = LatchBB->getTerminator();
            for (int i = 0; i < LatchB_TI->getNumSuccessors(); ++i) {
                BasicBlock *SuccBB = LatchB_TI->getSuccessor(i);
                if(HeaderBB_Follow_BBs.count(SuccBB) != 0 && SuccBB!= LatchBB){
                    HeaderBB_TI->setSuccessor( HeaderBB_Follow_BBs[SuccBB],HeaderBB);
                    //OP << "Resolve: "<<getBlockName(SuccB)<<"\n";
                }
            }

        }
    }
}

bool CallGraphPass::checkLoop(Function *F){
    if (F->isDeclaration()) return true;
    DominatorTree DT = DominatorTree();
    DT.recalculate(*F);
    set<Loop*> LPSet = getSubLoops(&DT);

    if(LPSet.empty())
        return true;
    else{
        //OP << "Warning: loop failed once\n";
        int Loopnum = LPSet.size();
        for(Function::iterator b = F->begin(); 
            b != F->end(); b++){
            
            BasicBlock* bb = &*b;
            auto TI = bb->getTerminator();
            int NumSucc = TI->getNumSuccessors();
            
            if(NumSucc == 0)
                continue;

            for(BasicBlock *succblock : successors(bb)){
                
                if(succblock==bb){
                    //OP << "Loopnum-- block-"<<getBlockName(succblock)<<"\n";
                    Loopnum--;
                    continue;
                }
            }
        }

        if(Loopnum<1){
            //OP << "Now loop is: "<<Loopnum<<"\n";
            return true;
        }
            
        else 
            return false;
    }

}

set<Loop*> CallGraphPass::getSubLoops(DominatorTree* DT){
    LoopInfo *LI = new LoopInfo();
    LI->releaseMemory();
    LI->analyze(*DT);

    // Collect all loops in the function
    set<Loop*> LPSet = {};
    for (Loop* LP : *LI) {
        LPSet.insert(LP);
        list<Loop*> LPL = {LP};
        while (!LPL.empty()) {
            LP = LPL.front();
            LPL.pop_front();
            vector<Loop *> SubLPs = LP->getSubLoops();
            for (auto SubLP : SubLPs) {
                LPSet.insert(SubLP);
                LPL.push_back(SubLP);
            }
        }
    }
    return LPSet;
}