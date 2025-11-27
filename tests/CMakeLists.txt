add_executable(unit_tests unit_tests.cpp)
target_link_libraries(unit_tests GTest::gtest_main P2PShareCore)
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../third_party/miniupnpc/miniupnpc/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../third_party/googletest/googlemock/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../third_party/googletest/googletest/include
)
add_test(NAME unit_tests COMMAND unit_tests)