CURDIR = $(shell pwd)
LLVM_INSTALL_RELEASE := YOUE_LLVM_BUILD_PATH
LLVM_USED := ${LLVM_INSTALL_RELEASE}
#SPDLOG_INSTALL := ${MYENVS}/spdlog_emoji
SRC_DIR := ${CURDIR}/src
SRC_BUILD := ${CURDIR}/build
LOG_BUILD := ${CURDIR}/analyzer/logs
OUTPUT_BUILD := ${CURDIR}/analyzer

NPROC := ${shell nproc}

# Find all source files for dependency tracking
SRC_FILES := $(shell find ${SRC_DIR} -name "*.cc" -o -name "*.h" 2>/dev/null)
CMAKE_FILE := ${SRC_DIR}/CMakeLists.txt
ANALYZER_BIN := ${SRC_BUILD}/analyzer

# pass argument to cmake by -D except clang & clang++ 
# remember -O3 with final release version
# -fvar-tracking -fvar-tracking-assignments

build_src_func = \
	(mkdir -p ${2} \
		&& cd ${2} \
		&& PATH=${LLVM_INSTALL_RELEASE}/bin:${PATH}\
			CC=clang CXX=clang++ \
			cmake ${1} \
				-DCMAKE_BUILD_TYPE=Release \
				-DCMAKE_CXX_FLAGS="-std=c++17 -fno-rtti -fpic -O3" \
				-DLLVM_INSTALL_DIR=${LLVM_USED} \
		&& make -j${NPROC})

.PHONY: all clean remake force

all: analyzer

# Build analyzer binary - depends on source files and cmake file
${ANALYZER_BIN}: ${SRC_FILES} ${CMAKE_FILE}
	@echo "Building analyzer..."
	@$(call build_src_func, ${SRC_DIR}, ${SRC_BUILD})

# Main target
analyzer: ${ANALYZER_BIN}
	@echo "Analyzer build complete"

# Force rebuild
force:
	@echo "Force rebuilding..."
	@$(call build_src_func, ${SRC_DIR}, ${SRC_BUILD})

clean:
	rm -rf ${SRC_BUILD}
	rm -rf ${LOG_BUILD}
	rm -rf ${OUTPUT_BUILD}

remake: clean analyzer