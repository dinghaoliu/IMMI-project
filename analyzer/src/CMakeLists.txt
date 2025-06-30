cmake_minimum_required(VERSION 3.5.1)
project(ANALYZER)

# LLVM
find_package(LLVM REQUIRED PATHS ${LLVM_INSTALL_DIR})
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

include_directories(${LLVM_INCLUDE_DIRS})
# for clangd only. find_package won't include llvm explictly, and thus clangd won't work

include(CheckCXXCompilerFlag)

# Set your openmp include path here
# For Mac OS with openmp installed by brew, using the following flags
set(OMP_INCLUDE_DRIS "/usr/lib/llvm-18/lib/clang/18/include")
set(OMP_LIB_DRIS "/usr/lib/llvm-18/lib")
include_directories(${OMP_INCLUDE_DRIS})
link_directories(${OMP_LIB_DRIS})

# Manually add OpenMP compilation flags
add_compile_options(-fopenmp)

# Set your mysql include path here
# For Mac OS with mysql installed by brew, using the following flags
#set(MYSQL_INCLUDE_DIRS "/opt/homebrew/Cellar/mysql-client/9.2.0/include")
#set(MYSQL_LIB_DRIS "/opt/homebrew/Cellar/mysql-client/9.2.0/lib")
#include_directories(${MYSQL_INCLUDE_DIRS})
#link_directories(${MYSQL_LIB_DRIS})

# Set your spdlog include path here
# For Mac OS with spdlog installed by brew, using the following flags
#set(SPDLOG_INSTALL_DIR "/opt/homebrew/Cellar/spdlog/1.15.0")
#find_package(spdlog REQUIRED PATHS ${SPDLOG_INSTALL_DIR})
#add_compile_options(-I${SPDLOG_INSTALL_DIR}/include)
find_package(spdlog REQUIRED PATHS ${SPDLOG_INSTALL_DIR})
add_compile_options(-I${SPDLOG_INSTALL_DIR}/include)

# Set your nlohmann-json include path here
# For Mac OS with nlohmann-json installed by brew, using the following flags
#set(JSON_INSTALL_DIR "/opt/homebrew/Cellar/nlohmann-json/3.11.3")
#find_package(nlohmann_json REQUIRED PATHS ${JSON_INSTALL_DIR})
#add_compile_options(-I${JSON_INSTALL_DIR}/include)


add_definitions(${LLVM_DEFINITIONS})

# traverse all .h and .cc files under directory
file (GLOB CallGraph CallGraph/*.h CallGraph/*.cc)
file (GLOB TypeBuilder TypeBuilder/*.h TypeBuilder/*.cc)
file (GLOB UAFChecker UAFChecker/*.h UAFChecker/*.cc)
file (GLOB FieldSensitiveAlias FieldSensitiveAlias/*.h FieldSensitiveAlias/*.cc)
file (GLOB utils utils/*.hpp utils/*.h utils/*.cc)

set(AnalyzerDependency
  ${TypeBuilder}
	${CallGraph}
  ${UAFChecker}
  ${FieldSensitiveAlias}
  ${utils}
)

set(AnalyzerMain Analyzer.cc)

# Build executable analyzer.
add_executable(analyzer ${AnalyzerMain} ${AnalyzerDependency})

llvm_map_components_to_libnames(llvm_libs core support analysis irreader)

target_link_libraries(analyzer
  PUBLIC
  ${llvm_libs}
  mysqlclient
  spdlog::spdlog
  omp
)