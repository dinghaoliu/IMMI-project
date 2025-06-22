CURDIR = $(shell pwd)
LLVM_INSTALL_RELEASE := YOUE_LLVM_BUILD_PATH
LLVM_USED := ${LLVM_INSTALL_RELEASE}
#SPDLOG_INSTALL := ${MYENVS}/spdlog_emoji
SRC_DIR := ${CURDIR}/src
SRC_BUILD := ${CURDIR}/build
LOG_BUILD := ${CURDIR}/logs

NPROC := ${shell sysctl -n hw.ncpu}

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
				-DCMAKE_CXX_FLAGS="-std=c++17 -fno-rtti -fpic -fuse-ld=lld -O3" \
				-DLLVM_INSTALL_DIR=${LLVM_USED} \
		&& make -j${NPROC})

all: analyzer

analyzer:
	echo ${LLVM_INSTALL_RELEASE}
	$(call build_src_func, ${SRC_DIR}, ${SRC_BUILD})

clean:
	rm -rf ${SRC_BUILD}
	rm -rf ${LOG_BUILD}

remake: clean analyzer