# VTIL-Optimizer target
#

set(optimizer_SOURCES passes/normalize_stack.cpp
    passes/eliminate_dead.cpp
)

add_library(optimizer STATIC ${optimizer_SOURCES})
target_include_directories(optimizer PUBLIC "./includes")
target_link_libraries(optimizer common)
target_link_libraries(optimizer symex)
target_link_libraries(optimizer architecture)
