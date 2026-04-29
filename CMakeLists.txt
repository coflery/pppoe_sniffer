cmake_minimum_required(VERSION 3.10)
project(PPPOE CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

include_directories(${PCAP_INCLUDE_DIRS})

add_executable(PPPOE pppoe.cpp common.cpp)
target_link_libraries(PPPOE ${PCAP_LIBRARIES})

install(TARGETS PPPOE DESTINATION bin)
