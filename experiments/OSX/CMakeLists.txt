cmake_minimum_required(VERSION 3.20)
project(dns_experiments_osx C)

add_executable(dns_sd_test dns_sd_test.c)

# dns_sd.h symbols (DNSServiceQueryRecord, DNSServiceProcessResult, etc.)
# live in libSystem on macOS and are implicitly linked. No target_link_libraries
# entry is needed.
