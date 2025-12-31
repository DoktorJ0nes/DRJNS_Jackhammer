cmake_minimum_required(VERSION 3.16)
project(DRJNS_Jackhammer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.11.3
)

FetchContent_MakeAvailable(nlohmann_json)

add_executable(DRJNS_Jackhammer
    jackhammer.cpp
)

target_link_libraries(DRJNS_Jackhammer PRIVATE
    nlohmann_json::nlohmann_json
    advapi32
    crypt32
    psapi
)
