/*
 * Arm DRTM TPM measurement execution
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HW_ARM_VIRT_DRTM_TPM_H
#define HW_ARM_VIRT_DRTM_TPM_H

#include "hw/arm/virt-drtm-measurement.h"
#include "system/tpm.h"

typedef enum VirtDRTMTPMStatus {
    VIRT_DRTM_TPM_OK,
    VIRT_DRTM_TPM_INVALID,
    VIRT_DRTM_TPM_HASH_ERROR,
    VIRT_DRTM_TPM_TRANSPORT_ERROR,
    VIRT_DRTM_TPM_RESPONSE_ERROR,
} VirtDRTMTPMStatus;

typedef struct VirtDRTMTPMResult {
    VirtDRTMTPMStatus status;
    bool irreversible;
    size_t failed_operation;
    uint32_t response_code;
} VirtDRTMTPMResult;

typedef struct VirtDRTMTPMOps {
    bool (*hash)(void *opaque, uint8_t locality,
                 TPMBackendDRTMHashOperation operation,
                 const uint8_t *data, size_t data_size, Error **errp);
    bool (*command)(void *opaque, uint8_t locality,
                    const uint8_t *request, size_t request_size,
                    uint8_t *response, size_t *response_size, Error **errp);
} VirtDRTMTPMOps;

typedef struct VirtDRTMTPMExecution {
    const VirtDRTMMeasurementManifest *manifest;
    size_t next_operation;
    bool initialized;
    bool failed;
} VirtDRTMTPMExecution;

typedef enum VirtDRTMTPMBankStatus {
    VIRT_DRTM_TPM_BANKS_OK,
    VIRT_DRTM_TPM_BANKS_INVALID,
    VIRT_DRTM_TPM_BANKS_TRANSPORT_ERROR,
    VIRT_DRTM_TPM_BANKS_RESPONSE_ERROR,
    VIRT_DRTM_TPM_BANKS_TPM_ERROR,
} VirtDRTMTPMBankStatus;

typedef struct VirtDRTMTPMBanks {
    VirtDRTMTPMBankStatus status;
    uint32_t response_code;
    uint16_t selected_algorithm;
    uint16_t banks[VIRT_DRTM_MAX_PCR_BANKS];
    size_t bank_count;
} VirtDRTMTPMBanks;

/*
 * Query the active TPM 2 PCR banks without changing TPM or DRTM state.
 * Success guarantees that every returned bank implements PCR17 and PCR18,
 * and that selected_algorithm is suitable for virt_drtm_tcb_init().
 */
VirtDRTMTPMBanks virt_drtm_tpm_discover_banks(
    const VirtDRTMTPMOps *ops, void *opaque, Error **errp);

/*
 * Execute a fully validated firmware-measurement manifest.  Any attempted
 * HASH_START makes the result irreversible, including ambiguous transport
 * failures, so a caller can route all subsequent failures to remediation.
 */
VirtDRTMTPMResult virt_drtm_tpm_execute(
    const VirtDRTMMeasurementManifest *manifest,
    const VirtDRTMTPMOps *ops, void *opaque, Error **errp);

/*
 * Staged form used by a DRTM launch transaction.  init has no TPM effects;
 * execute_hash performs exactly HASH_START/DATA/END at locality 4, and
 * execute_dcrtm_extends performs the Table 25 PCR caps/extends, and
 * execute_dce_extends performs the later DCE-owned extends at locality 3.
 */
bool virt_drtm_tpm_execution_init(VirtDRTMTPMExecution *execution,
    const VirtDRTMMeasurementManifest *manifest, Error **errp);
VirtDRTMTPMResult virt_drtm_tpm_execute_hash(
    VirtDRTMTPMExecution *execution, const VirtDRTMTPMOps *ops,
    void *opaque, Error **errp);
VirtDRTMTPMResult virt_drtm_tpm_execute_dcrtm_extends(
    VirtDRTMTPMExecution *execution, const VirtDRTMTPMOps *ops,
    void *opaque, Error **errp);
VirtDRTMTPMResult virt_drtm_tpm_execute_dce_extends(
    VirtDRTMTPMExecution *execution, const VirtDRTMTPMOps *ops,
    void *opaque, Error **errp);

#ifdef CONFIG_TPM
typedef struct VirtDRTMTPMFrontendExecution {
    VirtDRTMTPMExecution execution;
    TPMIf *tpm;
} VirtDRTMTPMFrontendExecution;

/*
 * Execute through QEMU's serialized TPM frontend paths.  Caller holds BQL.
 *
 * The staged context validates the complete manifest and frontend before any
 * TPM effect, then retains both for the ordered locality-4 hash, locality-3
 * D-CRTM extend, and locality-3 DCE extend phases.  The manifest must remain
 * valid until the final phase completes.  The TPMIf pointer is also borrowed:
 * the TPM frontend must remain realized and valid for that entire interval.
 * A failed phase poisons the context; it cannot be retried.
 */
bool virt_drtm_tpm_frontend_execution_init(
    VirtDRTMTPMFrontendExecution *frontend,
    const VirtDRTMMeasurementManifest *manifest, TPMIf *tpm, Error **errp);
VirtDRTMTPMResult virt_drtm_tpm_frontend_execute_hash(
    VirtDRTMTPMFrontendExecution *frontend, Error **errp);
VirtDRTMTPMResult virt_drtm_tpm_frontend_execute_dcrtm_extends(
    VirtDRTMTPMFrontendExecution *frontend, Error **errp);
VirtDRTMTPMResult virt_drtm_tpm_frontend_execute_dce_extends(
    VirtDRTMTPMFrontendExecution *frontend, Error **errp);

VirtDRTMTPMResult virt_drtm_tpm_execute_frontend(
    const VirtDRTMMeasurementManifest *manifest, TPMIf *tpm, Error **errp);
VirtDRTMTPMBanks virt_drtm_tpm_discover_banks_frontend(
    TPMIf *tpm, Error **errp);
#endif

#endif
