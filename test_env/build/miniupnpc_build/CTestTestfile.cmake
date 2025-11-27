# CMake generated Testfile for 
# Source directory: /home/anonymous/Documents/GitHub/P2PShare/third_party/miniupnpc/miniupnpc
# Build directory: /home/anonymous/Documents/GitHub/P2PShare/test_env/build/miniupnpc_build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(validateminixml "/home/anonymous/Documents/GitHub/P2PShare/test_env/build/miniupnpc_build/minixmlvalid")
set_tests_properties(validateminixml PROPERTIES  _BACKTRACE_TRIPLES "/home/anonymous/Documents/GitHub/P2PShare/third_party/miniupnpc/miniupnpc/CMakeLists.txt;255;add_test;/home/anonymous/Documents/GitHub/P2PShare/third_party/miniupnpc/miniupnpc/CMakeLists.txt;0;")
add_test(validateminiwget "/home/anonymous/Documents/GitHub/P2PShare/test_env/testminiwget.sh")
set_tests_properties(validateminiwget PROPERTIES  ENVIRONMENT "TESTSERVER=/home/anonymous/Documents/GitHub/P2PShare/test_env/build/minihttptestserver;TESTMINIWGET=/home/anonymous/Documents/GitHub/P2PShare/test_env/build/testminiwget" _BACKTRACE_TRIPLES "/home/anonymous/Documents/GitHub/P2PShare/third_party/miniupnpc/miniupnpc/CMakeLists.txt;257;add_test;/home/anonymous/Documents/GitHub/P2PShare/third_party/miniupnpc/miniupnpc/CMakeLists.txt;0;")
add_test(validateupnpreplyparse "/home/anonymous/Documents/GitHub/P2PShare/test_env/testupnpreplyparse.sh")
set_tests_properties(validateupnpreplyparse PROPERTIES  ENVIRONMENT "TESTUPNPREPLYPARSE=/home/anonymous/Documents/GitHub/P2PShare/test_env/build/testupnpreplyparse" WORKING_DIRECTORY "/home/anonymous/Documents/GitHub/P2PShare/test_env" _BACKTRACE_TRIPLES "/home/anonymous/Documents/GitHub/P2PShare/third_party/miniupnpc/miniupnpc/CMakeLists.txt;265;add_test;/home/anonymous/Documents/GitHub/P2PShare/third_party/miniupnpc/miniupnpc/CMakeLists.txt;0;")
add_test(validateportlistingparse "/home/anonymous/Documents/GitHub/P2PShare/test_env/build/miniupnpc_build/testportlistingparse")
set_tests_properties(validateportlistingparse PROPERTIES  _BACKTRACE_TRIPLES "/home/anonymous/Documents/GitHub/P2PShare/third_party/miniupnpc/miniupnpc/CMakeLists.txt;271;add_test;/home/anonymous/Documents/GitHub/P2PShare/third_party/miniupnpc/miniupnpc/CMakeLists.txt;0;")
add_test(validateigddescparse1 "/home/anonymous/Documents/GitHub/P2PShare/test_env/build/miniupnpc_build/testigddescparse" "new_LiveBox_desc.xml" "new_LiveBox_desc.values")
set_tests_properties(validateigddescparse1 PROPERTIES  WORKING_DIRECTORY "/home/anonymous/Documents/GitHub/P2PShare/test_env/testdesc" _BACKTRACE_TRIPLES "/home/anonymous/Documents/GitHub/P2PShare/third_party/miniupnpc/miniupnpc/CMakeLists.txt;273;add_test;/home/anonymous/Documents/GitHub/P2PShare/third_party/miniupnpc/miniupnpc/CMakeLists.txt;0;")
add_test(validateigddescparse2 "/home/anonymous/Documents/GitHub/P2PShare/test_env/build/miniupnpc_build/testigddescparse" "linksys_WAG200G_desc.xml" "linksys_WAG200G_desc.values")
set_tests_properties(validateigddescparse2 PROPERTIES  WORKING_DIRECTORY "/home/anonymous/Documents/GitHub/P2PShare/test_env/testdesc" _BACKTRACE_TRIPLES "/home/anonymous/Documents/GitHub/P2PShare/third_party/miniupnpc/miniupnpc/CMakeLists.txt;276;add_test;/home/anonymous/Documents/GitHub/P2PShare/third_party/miniupnpc/miniupnpc/CMakeLists.txt;0;")
add_test(validateaddr_is_reserved "/home/anonymous/Documents/GitHub/P2PShare/test_env/build/miniupnpc_build/testaddr_is_reserved")
set_tests_properties(validateaddr_is_reserved PROPERTIES  _BACKTRACE_TRIPLES "/home/anonymous/Documents/GitHub/P2PShare/third_party/miniupnpc/miniupnpc/CMakeLists.txt;279;add_test;/home/anonymous/Documents/GitHub/P2PShare/third_party/miniupnpc/miniupnpc/CMakeLists.txt;0;")
