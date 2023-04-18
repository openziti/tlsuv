if(PROJECT_IS_TOP_LEVEL)
  set(
      CMAKE_INSTALL_INCLUDEDIR "include/tlsuv-${PROJECT_VERSION}"
      CACHE PATH ""
  )
endif()

include(CMakePackageConfigHelpers)
include(GNUInstallDirs)

# find_package(<package>) call for consumers to find this project
set(package tlsuv)

install(
    DIRECTORY
    include/
    "${PROJECT_BINARY_DIR}/export/"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
    COMPONENT tlsuv_Development
)

install(
    TARGETS tlsuv_lib
    EXPORT tlsuvTargets
    RUNTIME #
    COMPONENT tlsuv_Runtime
    LIBRARY #
    COMPONENT tlsuv_Runtime
    NAMELINK_COMPONENT tlsuv_Development
    ARCHIVE #
    COMPONENT tlsuv_Development
    INCLUDES #
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)

write_basic_package_version_file(
    "${package}ConfigVersion.cmake"
    COMPATIBILITY SameMajorVersion
)

# Allow package maintainers to freely override the path for the configs
set(
    tlsuv_INSTALL_CMAKEDIR "${CMAKE_INSTALL_LIBDIR}/cmake/${package}"
    CACHE PATH "CMake package config location relative to the install prefix"
)
mark_as_advanced(tlsuv_INSTALL_CMAKEDIR)

install(
    FILES cmake/install-config.cmake
    DESTINATION "${tlsuv_INSTALL_CMAKEDIR}"
    RENAME "${package}Config.cmake"
    COMPONENT tlsuv_Development
)

install(
    FILES "${PROJECT_BINARY_DIR}/${package}ConfigVersion.cmake"
    DESTINATION "${tlsuv_INSTALL_CMAKEDIR}"
    COMPONENT tlsuv_Development
)

install(
    EXPORT tlsuvTargets
    NAMESPACE tlsuv::
    DESTINATION "${tlsuv_INSTALL_CMAKEDIR}"
    COMPONENT tlsuv_Development
)

if(PROJECT_IS_TOP_LEVEL)
  include(CPack)
endif()
