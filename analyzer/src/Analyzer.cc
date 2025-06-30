//===-- KRace.cc - the KRace framework------------------------===//
// 
// This file implements the KRace framework. It calls the pass for
// building call-graph and the pass for finding lacking security operation bugs.
//
//===-----------------------------------------------------------===//

#include <vector>

#include "TypeBuilder/TypeBuilder.h"
#include "CallGraph/CallGraph.h"
#include "UAFChecker/UAFChecker.h"
#include "utils/Analyzer.h"
#include "utils/utils.h"


// Command line parameters.
cl::list<std::string> InputFilenames(
    cl::Positional, cl::OneOrMore, cl::desc("<input bitcode files>"));

cl::opt<unsigned> VerboseLevel(
    "verbose-level", cl::desc("Print information at which verbose level"),
    cl::init(0));

GlobalContext GlobalCtx;

void IterativeModulePass::run(ModuleMap &modules) {
    int i = 0;
    logger->info("Initializing {0} modules.", modules.size());
    for (auto p : modules) { 
        logger->info("[{0}/{1}] Initializing {2}", ++i, modules.size(), p.second->getName().str());
        doInitialization(p.second); 
    }
    logger->info("Initializing Finish");

    i = 0;
    logger->info("Passing {0} modules.", modules.size());
    for (auto p : modules) { 
        logger->info("[{0}/{1}] Passing {2}", ++i, modules.size(), p.second->getName().str());
        doModulePass(p.second); 
    }
    logger->info("Passing Finish");

    i = 0;
    logger->info("Postprocessing {0} modules", modules.size());
    for (auto p : modules) { 
        logger->info("[{0}/{1}] Postprocessing {2}", ++i, modules.size(), p.second->getName().str());
        doFinalization(p.second); 
    }
    logger->info("Postprocessing Finish");

    logger->info("Done!\n");
}

void loadStaticData(GlobalContext *GCtx) {
    // Set ignored icall list, mainly designed for the Linux Static Calls
    config::setIcallIgnoreList(GCtx->IcallIgnoreFileLoc, GCtx->IcallIgnoreLineNum);
    // load functions that copy/move values
    config::SetCopyFuncs(GCtx->CopyFuncs);
    // load llvm debug functions
    config::setDebugFuncs(GCtx->DebugFuncs);
    // load pre-defined alloc and free functions
    config::setAllocFuncs(GCtx->AllocFuncs);
    config::setFreeFuncs(GCtx->FreeFuncs);
    // load heap alloc functions
    config::setHeapAllocFuncs(GCtx->HeapAllocFuncs);
}

void PrintResults(GlobalContext *GCtx) {
    size_t one_layer_num = 0;
    size_t two_layer_num = 0;
    size_t mix_layer_num = 0;
    size_t escape_num = 0;
    for(auto p : GCtx->Global_MLTA_Result_Map){
        switch(p.second) {
            case OneLayer: { one_layer_num++; break; }
            case TwoLayer: { two_layer_num++; break; }
            case MixedLayer: { mix_layer_num++; break; }
            case TypeEscape: { escape_num++; break; }
            default:
                break;
        }
    }

    /*OP<< "############## Result Statistics ##############\n";
    OP<< "# Number total icall targets   \t\t\t"<<GCtx->icallTargets<<"\n";
    OP<< "# Number valid_icallNumber \t\t\t"<<GCtx->valid_icallNumber<<"\n";
    OP<< "# Number 1-layer icall targets \t\t\t"<<GCtx->icallTargets_OneLayer<<"\n";
    OP<< "# Number 2-layer icall targets \t\t\t"<<GCtx->valid_icallTargets<<"\n";
    OP<< "# Number icalls \t\t\t\t"<<GCtx->IndirectCallInsts.size()<<"\n";
    OP<< "# Number 1-layer icalls \t\t\t"<<one_layer_num<<"\n";
    OP<< "# Number 2-layer icalls \t\t\t"<<two_layer_num<<"\n";
    OP<< "# Number mixed layer icalls \t\t\t"<<mix_layer_num<<"\n";
    OP<< "# Number escaped icalls \t\t\t"<<escape_num<<"\n";
    OP<< "# Number escaped stores \t\t\t"<<GCtx->num_escape_store<<"\n";
    OP<< "# Number escaped struct def \t\t\t"<<GCtx->Global_missing_type_def_struct_num<<"\n";
    OP<< "# Number anon pre layer \t\t\t"<<GCtx->Global_pre_anon_icall_num<<"\n";
    OP<< "# Number 1-layer set size\t\t\t"<<GCtx->sigFuncsMap.size()<<"\n";
    OP<< "\n";*/

    OP<< "############## Bug Detection Statistics ##############\n";
    OP<< "# Number Intro-inconsistency bugs \t\t\t"<<GCtx->intro_inconsistency_bugs<<"\n";
    OP<< "# Number Inter-inconsistency (Host Free) bugs \t\t"<<GCtx->inter_inconsistency_host_free_bugs<<"\n";
    OP<< "# Number Inter-inconsistency (Missing Free) bugs \t"<<GCtx->inter_inconsistency_missing_free_bugs<<"\n";
    OP<< "# Number Inter-inconsistency (Redundant Free) bugs \t"<<GCtx->inter_inconsistency_redundant_free_bugs<<"\n";
    OP<< "# Total bugs found \t\t\t\t\t"<<(GCtx->intro_inconsistency_bugs + GCtx->inter_inconsistency_host_free_bugs + GCtx->inter_inconsistency_missing_free_bugs + GCtx->inter_inconsistency_redundant_free_bugs)<<"\n";
    OP<< "\n";

    OP<< "############## Time Statistics ##############\n";
    OP<< "# Load time                \t\t" << timer::diff("main start", "load")              <<"\n";
    OP<< "# Call graph building time \t\t" << timer::diff("load", "MLTA")                    <<"\n";
    OP<< "# Summarize time           \t\t" << timer::get("uaf_dmp")                          <<"\n";
    OP<< "# Duty analysis time       \t\t" << timer::get("duty_analysis")                    <<"\n";
    OP<< "# Inter analysis time      \t\t" << timer::diff("uaf_fin_start", "uaf_fin_end")    <<"\n";
    OP<<"\n";
}


int main(int argc, char **argv) {
    // Print a stack trace if we signal out.
    sys::PrintStackTraceOnErrorSignal(argv[0]);
    PrettyStackTraceProgram X(argc, argv);
    logging::setup_logger();

    cl::ParseCommandLineOptions(argc, argv, "global analysis\n");

    timer::record("main start");

    int loaded = load::loadModules(InputFilenames, GlobalCtx.Modules);
    GLOG->info("Total {0} files and {1} are loaded", InputFilenames.size(),loaded);
    loadStaticData(&GlobalCtx);
    timer::record("load");

    // Main workflow
    TypeBuilderPass TBPass(&GlobalCtx);
    TBPass.run(GlobalCtx.Modules);


    CallGraphPass CGPass(&GlobalCtx);
    CGPass.run(GlobalCtx.Modules);
    
    CGPass.oneLayerHandler();
    CGPass.escapeHandler();
    
    timer::record("MLTA");

    UAFCheckerPass UAFCPass(&GlobalCtx);
    UAFCPass.run(GlobalCtx.Modules);
    
    PrintResults(&GlobalCtx);

    return 0;
}

