cmake_minimum_required(VERSION 3.4)

# Project Name
project(cmdns)

# Generate shared librarry libcmdns
add_library(cmdns SHARED mdns.c)

if(WIN32)
  target_link_libraries(cmdns iphlpapi ws2_32)
endif()

