include(CMakeFindDependencyMacro)
find_dependency(llhttp)
find_dependency(libuv)

include("${CMAKE_CURRENT_LIST_DIR}/tlsuvTargets.cmake")
