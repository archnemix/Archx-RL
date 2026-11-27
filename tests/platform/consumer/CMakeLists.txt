# Exercise relocated synthetic test-only shared and static exports.
cmake_minimum_required(VERSION 3.20)
project(ArchxSyntheticConsumer LANGUAGES C)
find_package(ArchxSynthetic CONFIG REQUIRED)
foreach(kind IN ITEMS core static)
  add_executable(consumer_${kind} ../../cmake_consumer/consumer.c)
  target_link_libraries(consumer_${kind} PRIVATE ArchxSynthetic::${kind})
endforeach()
if(WIN32)
  add_custom_command(TARGET consumer_core POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
      $<TARGET_FILE:ArchxSynthetic::core> $<TARGET_FILE_DIR:consumer_core>)
endif()
enable_testing()
add_test(NAME synthetic_shared_consumer COMMAND consumer_core)
add_test(NAME synthetic_static_consumer COMMAND consumer_static)
