# Build options that are specific to MSVC

if(MSVC)
    # Enable parallel builds
    add_compile_options(/MP)

    # Ensure static or dynamic build selection trickles down to all dependencies
    if(aescrypt_cli_MSVC_STATIC)
        set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    else()
        set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
    endif()

    # Set global compiler options for Release builds
    add_compile_options(
        $<$<CONFIG:Release>:/GL>    # Whole program optimization
        $<$<CONFIG:Release>:/Gy>    # Enable function-level linking
        $<$<CONFIG:Release>:/Gw>    # Optimize global data
    )

    # Set global linker options for Release builds
    add_link_options(
        $<$<CONFIG:Release>:/LTCG>              # Link-time code generation
        $<$<CONFIG:Release>:/OPT:REF>           # Remove unreferenced code and data
        $<$<CONFIG:Release>:/OPT:ICF>           # Fold identical COMDATs
        $<$<CONFIG:Release>:/INCREMENTAL:NO>    # Disable incremental linking for cleaner optimization
    )

    # Inter-procedural Optimization (IPO) for release builds
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)
endif()
