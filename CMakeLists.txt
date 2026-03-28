cmake_minimum_required(VERSION 3.28)

project(encfs-tpm VERSION 0.1.0)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(PkgConfig)

pkg_check_modules(OPENSSL REQUIRED libcrypto)
pkg_check_modules(FUSE REQUIRED fuse3)
pkg_check_modules(TSS2 REQUIRED tss2-esys tss2-tctildr tss2-rc tss2-mu)

add_library(encfs-core STATIC
    src/tpm.c
    src/crypto.c
)
target_include_directories(encfs-core PUBLIC
    include/
    ${TSS2_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIRS}
)
target_link_libraries(encfs-core PUBLIC
    ${TSS2_LIBRARIES}
    ${OPENSSL_LIBRARIES}
)

add_executable(encfs-tpm src/fs.c src/main.c)

target_compile_definitions(encfs-tpm
    PRIVATE FUSE_USE_VERSION=31
    ENCFS_VERSION_STR="${PROJECT_VERSION}"
)
target_include_directories(encfs-tpm PRIVATE ${FUSE_INCLUDE_DIRS})
target_link_libraries(encfs-tpm PRIVATE ${FUSE_LIBRARIES} encfs-core)
