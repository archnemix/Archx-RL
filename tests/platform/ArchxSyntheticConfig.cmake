# Synthetic test package only. No platform collector or production support.
include(CMakeFindDependencyMacro)
if(NOT WIN32)
  find_dependency(Threads)
endif()
include("${CMAKE_CURRENT_LIST_DIR}/ArchxSyntheticTargets.cmake")
