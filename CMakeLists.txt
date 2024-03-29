cmake_minimum_required(VERSION 3.13)
project(soc_net_aut C CXX)
set(CMAKE_CXX_STANDARD 17)
include(third_party/userver/cmake/SetupEnvironment.cmake)
include(GNUInstallDirs)
find_package(OpenSSL REQUIRED)
add_subdirectory(third_party/userver)

# Common sources
add_library(${PROJECT_NAME}_crypto OBJECT
    src/cryptCore.hpp
    src/cryptCore.cpp
)
target_include_directories(${PROJECT_NAME}_crypto PRIVATE ${CMAKE_SOURCE_DIR}/third_party/libScrypt)
add_library( libScrypt SHARED IMPORTED )
set_target_properties( libScrypt PROPERTIES IMPORTED_LOCATION ${CMAKE_SOURCE_DIR}/third_party/libScrypt/libscrypt.so.0)
target_link_libraries(${PROJECT_NAME}_crypto PRIVATE libScrypt)
target_include_directories(${PROJECT_NAME}_crypto PUBLIC ${OpenSSL_INCLUDE_DIR})
target_link_libraries(${PROJECT_NAME}_crypto PRIVATE ${OpenSSL_LIBRARIES} userver-core)
add_library(${PROJECT_NAME}_jwtTok OBJECT
    src/jwt.hpp
    src/jwt.cpp
    )
target_link_libraries(${PROJECT_NAME}_jwtTok PUBLIC ${PROJECT_NAME}_crypto)
target_link_libraries(${PROJECT_NAME}_jwtTok PRIVATE userver-core)
add_library(${PROJECT_NAME}_pgAuth OBJECT
    src/pgAuth.hpp
    src/pgAuth.cpp
)
target_link_libraries(${PROJECT_NAME}_pgAuth PRIVATE ${PROJECT_NAME}_jwtTok ${PROJECT_NAME}_crypto userver-core userver-postgresql)
add_library(${PROJECT_NAME}_objs OBJECT
    src/hello.hpp
    src/hello.cpp
)
target_link_libraries(${PROJECT_NAME}_objs PUBLIC userver-core userver-postgresql userver-grpc)


#The proto get
include(GrpcTargets)
add_grpc_library(${PROJECT_NAME}_proto PROTOS AuthServ.proto)


#GRPC server impl
add_library(${PROJECT_NAME}_grpc OBJECT
    src/AuthGRPC.hpp
    src/AuthGRPC.cpp
)
target_link_libraries(${PROJECT_NAME}_grpc PUBLIC ${PROJECT_NAME}_proto)
target_link_libraries(${PROJECT_NAME}_grpc PRIVATE ${PROJECT_NAME}_pgAuth userver-core userver-postgresql userver-grpc)



# The Service
add_executable(${PROJECT_NAME} src/main.cpp)
target_link_libraries(${PROJECT_NAME} PRIVATE ${PROJECT_NAME}_grpc ${PROJECT_NAME}_pgAuth ${PROJECT_NAME}_jwtTok ${PROJECT_NAME}_crypto userver-core userver-postgresql userver-grpc)




# Unit Tests
add_executable(${PROJECT_NAME}_unittest
    src/hello_test.cpp
)
target_link_libraries(${PROJECT_NAME}_unittest PRIVATE ${PROJECT_NAME}_objs ${PROJECT_NAME}_crypto ${PROJECT_NAME}_jwtTok userver-utest)
add_google_tests(${PROJECT_NAME}_unittest)


# Benchmarks
add_executable(${PROJECT_NAME}_benchmark
	src/hello_benchmark.cpp
)
target_link_libraries(${PROJECT_NAME}_benchmark PRIVATE ${PROJECT_NAME}_objs userver-ubench)
add_google_benchmark_tests(${PROJECT_NAME}_benchmark)

# Functional Tests
add_subdirectory(tests)

if(DEFINED ENV{PREFIX})
	message(STATUS "Set install prefix: $ENV{PREFIX}")
	file(TO_CMAKE_PATH "$ENV{PREFIX}" PREFIX_PATH)
	set(CMAKE_INSTALL_PREFIX ${PREFIX_PATH})
endif()

set(CONFIG_VAR_PATH ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_SYSCONFDIR}/${PROJECT_NAME}/config_vars.yaml)
set(CONFIG_FALLBACK_PATH ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_SYSCONFDIR}/${PROJECT_NAME}/dynamic_config_fallback.json)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/configs/static_config.yaml.in ${CMAKE_CURRENT_SOURCE_DIR}/configs/static_config.yaml)

FILE(GLOB CONFIGS_FILES ${CMAKE_CURRENT_SOURCE_DIR}/configs/*.yaml ${CMAKE_CURRENT_SOURCE_DIR}/configs/*.json)

install(TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT ${PROJECT_NAME})
install(FILES ${CONFIGS_FILES} DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/${PROJECT_NAME} COMPONENT ${PROJECT_NAME})
