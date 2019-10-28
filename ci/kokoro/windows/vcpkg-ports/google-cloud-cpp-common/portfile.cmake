include(vcpkg_common_functions)

vcpkg_check_linkage(ONLY_STATIC_LIBRARY)

vcpkg_from_github(
    OUT_SOURCE_PATH
    SOURCE_PATH
    REPO
    dopiera/google-cloud-cpp-common
    REF
    v0.16.0
    SHA512
    a29fbbcd7db0beba3e52519f92512d108ddc94b68e9844273772f9860b805a051da1383c864aee6800de8bf73899a71b11a51c35047d995aaf23f299a7192015
    HEAD_REF
    master)

vcpkg_configure_cmake(
    SOURCE_PATH ${SOURCE_PATH} PREFER_NINJA DISABLE_PARALLEL_CONFIGURE OPTIONS
    -DGOOGLE_CLOUD_CPP_ENABLE_MACOS_OPENSSL_CHECK=OFF)

vcpkg_install_cmake(ADD_BIN_TO_PATH)

file(REMOVE_RECURSE ${CURRENT_PACKAGES_DIR}/debug/include)
vcpkg_fixup_cmake_targets(CONFIG_PATH lib/cmake TARGET_PATH share)

file(REMOVE_RECURSE ${CURRENT_PACKAGES_DIR}/debug/share)
file(
    INSTALL ${SOURCE_PATH}/LICENSE
    DESTINATION ${CURRENT_PACKAGES_DIR}/share/google-cloud-cpp-common
    RENAME copyright)

vcpkg_copy_pdbs()
