# Limit parallel compile jobs based on available RAM.
# Full parallel builds (e.g. make -j$(nproc)) can OOM machines with many cores
# but limited memory because each C++ translation unit is memory-heavy here.

option(ZATHURA_LIMIT_BUILD_PARALLELISM
    "Cap parallel build jobs from available RAM (recommended on Linux)"
    ON)

set(ZATHURA_MB_PER_JOB 1200 CACHE STRING
    "Estimated RAM (MiB) per parallel C++ compile job for this project")
set(ZATHURA_MAX_BUILD_JOBS 0 CACHE STRING
    "Hard cap on parallel build jobs (0 = auto from RAM and CPU count)")

function(zathura_compute_build_jobs out_var)
    set(jobs 1)

    if(ZATHURA_MAX_BUILD_JOBS GREATER 0)
        set(jobs ${ZATHURA_MAX_BUILD_JOBS})
    elseif(ZATHURA_LIMIT_BUILD_PARALLELISM)
        if(EXISTS "/proc/meminfo")
            file(READ "/proc/meminfo" _zathura_meminfo)
            if(_zathura_meminfo MATCHES "MemAvailable:[ \t]+([0-9]+)")
                math(EXPR _zathura_avail_mb "${CMAKE_MATCH_1} / 1024")
                if(ZATHURA_MB_PER_JOB GREATER 0)
                    math(EXPR jobs "${_zathura_avail_mb} / ${ZATHURA_MB_PER_JOB}")
                endif()
                if(jobs LESS 1)
                    set(jobs 1)
                endif()
            endif()
        endif()
    else()
        include(ProcessorCount)
        ProcessorCount(_zathura_nproc)
        if(_zathura_nproc GREATER 0)
            set(jobs ${_zathura_nproc})
        endif()
    endif()

    include(ProcessorCount)
    ProcessorCount(_zathura_nproc)
    if(_zathura_nproc GREATER 0 AND jobs GREATER _zathura_nproc)
        set(jobs ${_zathura_nproc})
    endif()

    set(${out_var} ${jobs} PARENT_SCOPE)
endfunction()

zathura_compute_build_jobs(ZATHURA_BUILD_JOBS)

if(NOT CMAKE_BUILD_PARALLEL_LEVEL)
    set(CMAKE_BUILD_PARALLEL_LEVEL ${ZATHURA_BUILD_JOBS}
        CACHE STRING "Parallel build jobs used by cmake --build")
endif()

message(STATUS "Parallel build jobs: ${CMAKE_BUILD_PARALLEL_LEVEL} "
    "(override with -DZATHURA_MAX_BUILD_JOBS=N or cmake --build -j N)")
