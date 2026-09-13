/*
 * tpm_tis.h - QEMU's TPM TIS common header
 *
 * Copyright (C) 2006,2010-2013 IBM Corporation
 *
 * Authors:
 *  Stefan Berger <stefanb@us.ibm.com>
 *  David Safford <safford@us.ibm.com>
 *
 * Xen 4 support: Andrease Niederl <andreas.niederl@iaik.tugraz.at>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 * Implementation of the TIS interface according to specs found at
 * http://www.trustedcomputinggroup.org. This implementation currently
 * supports version 1.3, 21 March 2013
 * In the developers menu choose the PC Client section then find the TIS
 * specification.
 *
 * TPM TIS for TPM 2 implementation following TCG PC Client Platform
 * TPM Profile (PTP) Specification, Family 2.0, Revision 00.43
 */
#ifndef TPM_TPM_TIS_H
#define TPM_TPM_TIS_H

#include "system/tpm_backend.h"
#include "tpm_ppi.h"

#define TPM_TIS_NUM_LOCALITIES      5     /* per spec */
#define TPM_TIS_LOCALITY_SHIFT      12
#define TPM_TIS_NO_LOCALITY         0xff

#define TPM_TIS_IS_VALID_LOCTY(x)   ((x) < TPM_TIS_NUM_LOCALITIES)

#define TPM_TIS_BUFFER_MAX          4096
#define TPM_TIS_PLATFORM_TIMEOUT_MS 30000

typedef enum {
    TPM_TIS_STATE_IDLE = 0,
    TPM_TIS_STATE_READY,
    TPM_TIS_STATE_COMPLETION,
    TPM_TIS_STATE_EXECUTION,
    TPM_TIS_STATE_RECEPTION,
} TPMTISState;

/* locality data  -- all fields are persisted */
typedef struct TPMLocality {
    TPMTISState state;
    uint8_t access;
    uint32_t sts;
    uint32_t iface_id;
    uint32_t inte;
    uint32_t ints;
} TPMLocality;

typedef struct TPMState {
    MemoryRegion mmio;

    unsigned char buffer[TPM_TIS_BUFFER_MAX];
    uint16_t rw_offset;

    uint8_t active_locty;
    uint8_t aborting_locty;
    uint8_t next_locty;

    TPMLocality loc[TPM_TIS_NUM_LOCALITIES];

    qemu_irq irq;
    uint32_t irq_num;

    TPMBackendCmd cmd;

    /* Persistent storage for a synchronous platform/firmware transaction. */
    TPMBackendCmd platform_cmd;
    uint8_t platform_request[TPM_TIS_BUFFER_MAX];
    uint8_t platform_response[TPM_TIS_BUFFER_MAX];
    bool platform_cmd_active;
    bool guest_cmd_queued;
    int platform_cmd_ret;

    /* Arm DRTM mediation is opt-in and only applies to tpm-tis-device. */
    bool drtm_enabled;
    uint8_t drtm_closed_localities;
    uint8_t drtm_hash_state;

    TPMBackend *be_driver;
    TPMVersion be_tpm_version;

    size_t be_buffer_size;

    TPMPPI ppi;
    bool ppi_enabled;
} TPMState;

extern const VMStateDescription vmstate_locty;
extern const MemoryRegionOps tpm_tis_memory_ops;

int tpm_tis_pre_save(TPMState *s);
void tpm_tis_reset(TPMState *s, bool ppi_enabled);
enum TPMVersion tpm_tis_get_tpm_version(TPMState *s);
void tpm_tis_request_completed(TPMState *s, int ret);
bool tpm_tis_deliver_platform_request(TPMState *s, uint8_t locality,
                                      const uint8_t *request,
                                      size_t request_size,
                                      uint8_t *response,
                                      size_t *response_size,
                                      Error **errp);
bool tpm_tis_enable_drtm(TPMState *s, Error **errp);
bool tpm_tis_drtm_no_active_locality(TPMState *s, bool *no_active,
                                     Error **errp);
bool tpm_tis_drtm_open_localities(TPMState *s, Error **errp);
bool tpm_tis_drtm_close_locality(TPMState *s, uint8_t locality,
                                 TPMDRTMLocalityCloseResult *result,
                                 Error **errp);
bool tpm_tis_drtm_activate_locality2(TPMState *s, Error **errp);
bool tpm_tis_drtm_hash(TPMState *s,
                       TPMBackendDRTMHashOperation operation,
                       const uint8_t *data, size_t data_size, Error **errp);
uint32_t tpm_tis_read_data(TPMState *s, hwaddr addr, unsigned size);
void tpm_tis_write_data(TPMState *s, hwaddr addr, uint64_t val, uint32_t size);
uint16_t tpm_tis_get_checksum(TPMState *s);

#endif /* TPM_TPM_TIS_H */
