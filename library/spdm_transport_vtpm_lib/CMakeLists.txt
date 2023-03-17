cmake_minimum_required(VERSION 2.8.12)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include)

SET(src_spdm_transport_vtpm_lib
    libspdm_vtpm_common.c
    libspdm_vtpm_vtpm.c
)

ADD_LIBRARY(spdm_transport_vtpm_lib STATIC ${src_spdm_transport_vtpm_lib})
