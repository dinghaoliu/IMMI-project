#ifndef UTILS_MACRO_H
#define UTILS_MACRO_H

#define GET_MACRO_5(_1, _2, _3, _4, _5, NAME, ...) NAME

#define LABEL_MARK_OP OP << "MARK: " << std::filesystem::path(__FILE__).filename().string() << ":" << __LINE__ << "\n";
#define LABEL_MARK_OP_INFO(INFO) OP << "MARK: " << std::filesystem::path(__FILE__).filename().string() << ":" << __LINE__ << " info: " << INFO <<"\n";
#define LABEL_MARK_LOGGER logger->info("MARK: {0}:{1}", __FILE__, __LINE__);
#define LABEL_MARK_LOGGER_INFO(...) \
    GET_MACRO_5(__VA_ARGS__, \
    LABEL_MARK_LOGGER_INFO_5, \
    LABEL_MARK_LOGGER_INFO_4, \
    LABEL_MARK_LOGGER_INFO_3, \
    LABEL_MARK_LOGGER_INFO_2, \
    LABEL_MARK_LOGGER_INFO_1)(__VA_ARGS__)
#define LABEL_MARK_LOGGER_INFO_1(ARG0) logger->info("MARK: {}:{} | {} ", __FILE__, __LINE__, ARG0);
#define LABEL_MARK_LOGGER_INFO_2(ARG0, ARG1) logger->info("MARK: {}:{} | {}{} ", __FILE__, __LINE__, ARG0, ARG1);
#define LABEL_MARK_LOGGER_INFO_3(ARG0, ARG1, ARG2) logger->info("MARK: {}:{} | {}{}{}", __FILE__, __LINE__, ARG0, ARG1, ARG2);
#define LABEL_MARK_LOGGER_INFO_4(ARG0, ARG1, ARG2, ARG3) logger->info("MARK: {}:{} | {}{}{}{}", __FILE__, __LINE__, ARG0, ARG1, ARG2, ARG3);
#define LABEL_MARK_LOGGER_INFO_5(ARG0, ARG1, ARG2, ARG3, ARG4)  logger->info("MARK: {}:{} | {}{}{}{}{}", __FILE__, __LINE__, ARG0, ARG1, ARG2, ARG3, ARG4);

#define OP llvm::errs()
#define GLOG logging::global_log
#define ELOG logging::exc_log

#define LLTS(llobj) common::llobj_to_string(llobj)

#endif