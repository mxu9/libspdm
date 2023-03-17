/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 **/

#ifndef VTPM_BINDING_H
#define VTPM_BINDING_H

#pragma pack(1)

/* vtpm header*/
typedef struct {
    uint8_t version;
    uint8_t tag;
    uint16_t signature;
} vtpm_header_t;

typedef struct {
    uint16_t message_length;
    uint8_t version;
    uint8_t message_type;
} vtpm_message_header_t;

typedef struct {
    uint8_t app_message_type;
} vtpm_app_message_header_t;

#define VTPM_MESSAGE_TYPE_SPDM 0x01
#define VTPM_MESSAGE_TYPE_SECURED_SPDM 0x02

#define VTPM_APP_MESSAGE_TYPE_SPDM 0x01
#define VTPM_APP_MESSAGE_TYPE_VTPM 0x03

#pragma pack()

#endif /* VTPM_BINDING_H */
