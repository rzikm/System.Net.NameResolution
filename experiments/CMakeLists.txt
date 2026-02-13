cmake_minimum_required(VERSION 3.20)
project(dns_experiments C)

add_executable(dns_server_test dns_server_test.c)
target_link_libraries(dns_server_test PRIVATE dnsapi ws2_32)
