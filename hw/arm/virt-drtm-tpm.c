/*
 * Arm DRTM TPM measurement execution
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "hw/arm/virt-drtm-tpm.h"
#include "qapi/error.h"
#include "qemu/bswap.h"
#include "qemu/cutils.h"

#define TPM2_ST_NO_SESSIONS 0x8001
#define TPM2_ST_SESSIONS    0x8002
#define TPM2_CC_PCR_EXTEND  0x00000182
#define TPM2_RS_PW          0x40000009
#define TPM2_SUCCESS_RESPONSE_SIZE 19
#define TPMA_SESSION_CONTINUESESSION 0x01

static size_t digest_size(uint16_t algorithm)
{
    switch (algorithm) {
    case VIRT_DRTM_TPM_ALG_SHA1:
        return 20;
    case VIRT_DRTM_TPM_ALG_SHA256:
        return 32;
    case VIRT_DRTM_TPM_ALG_SHA384:
        return 48;
    case VIRT_DRTM_TPM_ALG_SHA512:
        return 64;
    default:
        return 0;
    }
}

static bool bank_present(const VirtDRTMMeasurementManifest *manifest,
                         uint16_t algorithm)
{
    size_t i;

    for (i = 0; i < virt_drtm_measurement_manifest_bank_count(manifest); i++) {
        if (virt_drtm_measurement_manifest_bank(manifest, i) == algorithm) {
            return true;
        }
    }
    return false;
}

static bool operation_valid(const VirtDRTMMeasurementManifest *manifest,
                            size_t index,
                            const VirtDRTMMeasurementOperation *op)
{
    size_t expected_size;

    if (index == 0) {
        return op->type == VIRT_DRTM_MEASUREMENT_HASH_START;
    }
    if (index == 1) {
        return op->type == VIRT_DRTM_MEASUREMENT_HASH_DATA && op->pcr == 17 &&
               op->digest.algorithm ==
               virt_drtm_measurement_manifest_algorithm(manifest) &&
               op->digest.size == digest_size(op->digest.algorithm);
    }
    if (index == 2) {
        return op->type == VIRT_DRTM_MEASUREMENT_HASH_END;
    }
    if (op->type != VIRT_DRTM_MEASUREMENT_PCR_CAP &&
        op->type != VIRT_DRTM_MEASUREMENT_PCR_EXTEND) {
        return false;
    }
    if (op->pcr != 17 && op->pcr != 18) {
        return false;
    }
    expected_size = digest_size(op->digest.algorithm);
    if (!expected_size || op->digest.size != expected_size ||
        !bank_present(manifest, op->digest.algorithm)) {
        return false;
    }
    if (op->type == VIRT_DRTM_MEASUREMENT_PCR_EXTEND) {
        return op->digest.algorithm ==
               virt_drtm_measurement_manifest_algorithm(manifest);
    }
    return op->digest.algorithm !=
           virt_drtm_measurement_manifest_algorithm(manifest) &&
           buffer_is_zero(op->digest.value, op->digest.size);
}

static bool operation_matches_event(const VirtDRTMMeasurementOperation *op,
                                    const VirtDRTMMeasurementEvent *event)
{
    return op->type == VIRT_DRTM_MEASUREMENT_PCR_EXTEND &&
           event->digest_count == 1 && event->pcr == op->pcr &&
           event->digests[0].algorithm == op->digest.algorithm &&
           event->digests[0].size == op->digest.size &&
           !memcmp(event->digests[0].value, op->digest.value,
                   op->digest.size);
}

static bool manifest_valid(const VirtDRTMMeasurementManifest *manifest)
{
    const VirtDRTMMeasurementEvent *event;
    const VirtDRTMMeasurementOperation *op;
    uint16_t selected;
    size_t count, event_count, bank_count, dce_operation, separator17 = 0;
    size_t dlme18 = 0, i, pos = 3;

    if (!manifest) {
        return false;
    }
    count = virt_drtm_measurement_manifest_operation_count(manifest);
    event_count = virt_drtm_measurement_manifest_event_count(manifest);
    bank_count = virt_drtm_measurement_manifest_bank_count(manifest);
    dce_operation = virt_drtm_measurement_manifest_dce_operation(manifest);
    selected = virt_drtm_measurement_manifest_algorithm(manifest);
    if (count < 4 || !event_count || !bank_count ||
        dce_operation <= 3 || dce_operation >= count ||
        !bank_present(manifest, selected)) {
        return false;
    }
    for (i = 0; i < 3; i++) {
        if (!operation_valid(manifest, i,
                virt_drtm_measurement_manifest_operation(manifest, i))) {
            return false;
        }
    }

    event = virt_drtm_measurement_manifest_event(manifest, 0);
    op = virt_drtm_measurement_manifest_operation(manifest, 1);
    if (event->pcr != 17 || event->type != VIRT_DRTM_EV_DCE ||
        event->event_data.size != 2 + op->digest.size ||
        lduw_le_p(event->event_data.data) != op->digest.algorithm ||
        memcmp(event->event_data.data + 2, op->digest.value,
               op->digest.size)) {
        return false;
    }

    /* R62175: cap PCR17 then PCR18 in every non-selected active bank. */
    for (i = 0; i < bank_count; i++) {
        uint16_t bank = virt_drtm_measurement_manifest_bank(manifest, i);
        unsigned int pcr;

        if (bank == selected) {
            continue;
        }
        for (pcr = 17; pcr <= 18; pcr++, pos++) {
            if (pos >= count) {
                return false;
            }
            op = virt_drtm_measurement_manifest_operation(manifest, pos);
            if (!operation_valid(manifest, pos, op) ||
                op->type != VIRT_DRTM_MEASUREMENT_PCR_CAP ||
                op->pcr != pcr || op->digest.algorithm != bank) {
                return false;
            }
        }
    }

    /*
     * Operations are phase ordered even though the log is PCR ordered:
     * Table 25 D-CRTM events precede the R45300/Table 30 DCE events.
     */
    if (count - pos != event_count - 1) {
        return false;
    }
    for (i = 1; i < event_count; i++) {
        event = virt_drtm_measurement_manifest_event(manifest, i);
        if (event->pcr == 17 && event->type == VIRT_DRTM_EV_SEPARATOR) {
            if (separator17) {
                return false;
            }
            separator17 = i;
        } else if (event->pcr == 18 && event->type == VIRT_DRTM_EV_DLME) {
            if (dlme18) {
                return false;
            }
            dlme18 = i;
        }
    }
    if (!separator17 || !dlme18 || separator17 >= dlme18) {
        return false;
    }
    for (i = 1; i < separator17; i++, pos++) {
        op = virt_drtm_measurement_manifest_operation(manifest, pos);
        event = virt_drtm_measurement_manifest_event(manifest, i);
        if (!operation_valid(manifest, pos, op) ||
            !operation_matches_event(op, event)) {
            return false;
        }
    }
    for (i = separator17 + 1; i < dlme18; i++, pos++) {
        op = virt_drtm_measurement_manifest_operation(manifest, pos);
        event = virt_drtm_measurement_manifest_event(manifest, i);
        if (!operation_valid(manifest, pos, op) ||
            !operation_matches_event(op, event)) {
            return false;
        }
    }
    if (pos != dce_operation) {
        return false;
    }
    op = virt_drtm_measurement_manifest_operation(manifest, pos++);
    event = virt_drtm_measurement_manifest_event(manifest, separator17);
    if (!operation_valid(manifest, pos - 1, op) ||
        !operation_matches_event(op, event)) {
        return false;
    }
    for (i = dlme18; i < event_count; i++, pos++) {
        op = virt_drtm_measurement_manifest_operation(manifest, pos);
        event = virt_drtm_measurement_manifest_event(manifest, i);
        if (!operation_valid(manifest, pos, op) ||
            !operation_matches_event(op, event)) {
            return false;
        }
    }
    return pos == count;
}

static size_t make_pcr_extend(uint8_t request[97],
                              const VirtDRTMMeasurementOperation *op)
{
    size_t size = 33 + op->digest.size;

    stw_be_p(request, TPM2_ST_SESSIONS);
    stl_be_p(request + 2, size);
    stl_be_p(request + 6, TPM2_CC_PCR_EXTEND);
    stl_be_p(request + 10, op->pcr);
    stl_be_p(request + 14, 9);       /* authorizationSize */
    stl_be_p(request + 18, TPM2_RS_PW);
    stw_be_p(request + 22, 0);       /* nonce size */
    request[24] = 0;                 /* session attributes */
    stw_be_p(request + 25, 0);       /* password size */
    stl_be_p(request + 27, 1);       /* TPML_DIGEST_VALUES count */
    stw_be_p(request + 31, op->digest.algorithm);
    memcpy(request + 33, op->digest.value, op->digest.size);
    return size;
}

static bool success_response(const uint8_t *response, size_t size,
                             uint32_t *response_code)
{
    if (size >= 10) {
        *response_code = ldl_be_p(response + 6);
    }
    return size == TPM2_SUCCESS_RESPONSE_SIZE &&
           lduw_be_p(response) == TPM2_ST_SESSIONS &&
           ldl_be_p(response + 2) == size &&
           *response_code == 0 &&
           ldl_be_p(response + 10) == 0 && /* parameterSize */
           lduw_be_p(response + 14) == 0 && /* nonce size */
           /* TPMS_AUTH_RESPONSE.sessionAttributes */
           response[16] == TPMA_SESSION_CONTINUESESSION &&
           lduw_be_p(response + 17) == 0;   /* HMAC size */
}

VirtDRTMTPMResult virt_drtm_tpm_execute(
    const VirtDRTMMeasurementManifest *manifest,
    const VirtDRTMTPMOps *ops, void *opaque, Error **errp)
{
    VirtDRTMTPMExecution execution;
    VirtDRTMTPMResult result;

    /* Preserve the combined API's pre-effect atomic validation contract. */
    if (!ops || !ops->hash || !ops->command) {
        error_setg(errp, "invalid DRTM TPM measurement transport");
        return (VirtDRTMTPMResult) {
            .status = VIRT_DRTM_TPM_INVALID,
            .failed_operation = SIZE_MAX,
        };
    }
    if (!virt_drtm_tpm_execution_init(&execution, manifest, errp)) {
        return (VirtDRTMTPMResult) {
            .status = VIRT_DRTM_TPM_INVALID,
            .failed_operation = SIZE_MAX,
        };
    }
    result = virt_drtm_tpm_execute_hash(&execution, ops, opaque, errp);
    if (result.status != VIRT_DRTM_TPM_OK) {
        return result;
    }
    result = virt_drtm_tpm_execute_dcrtm_extends(&execution, ops, opaque,
                                                 errp);
    if (result.status != VIRT_DRTM_TPM_OK) {
        return result;
    }
    return virt_drtm_tpm_execute_dce_extends(&execution, ops, opaque, errp);
}

bool virt_drtm_tpm_execution_init(VirtDRTMTPMExecution *execution,
    const VirtDRTMMeasurementManifest *manifest, Error **errp)
{
    if (!execution || !manifest_valid(manifest)) {
        error_setg(errp, "invalid DRTM TPM measurement plan");
        return false;
    }
    *execution = (VirtDRTMTPMExecution) {
        .manifest = manifest,
        .initialized = true,
    };
    return true;
}

VirtDRTMTPMResult virt_drtm_tpm_execute_hash(
    VirtDRTMTPMExecution *execution, const VirtDRTMTPMOps *ops,
    void *opaque, Error **errp)
{
    VirtDRTMTPMResult result = {
        .status = VIRT_DRTM_TPM_INVALID,
        .failed_operation = SIZE_MAX,
    };
    size_t i;

    if (!execution || !execution->initialized || execution->failed ||
        execution->next_operation ||
        !ops || !ops->hash) {
        error_setg(errp, "invalid DRTM TPM hash phase");
        return result;
    }

    for (i = 0; i < 3; i++) {
        const VirtDRTMMeasurementOperation *op =
            virt_drtm_measurement_manifest_operation(execution->manifest, i);
        TPMBackendDRTMHashOperation hash_op =
            TPM_BACKEND_DRTM_HASH_START + op->type;
        const uint8_t *data = NULL;
        size_t data_size = 0;

        result.failed_operation = i;
        if (op->type == VIRT_DRTM_MEASUREMENT_HASH_DATA) {
            data = op->digest.value;
            data_size = op->digest.size;
        }
        if (op->type == VIRT_DRTM_MEASUREMENT_HASH_START) {
            result.irreversible = true;
        }
        if (!ops->hash(opaque, 4, hash_op, data, data_size, errp)) {
            execution->failed = true;
            result.status = VIRT_DRTM_TPM_HASH_ERROR;
            return result;
        }
    }
    execution->next_operation = 3;
    result.status = VIRT_DRTM_TPM_OK;
    result.irreversible = true;
    result.failed_operation = SIZE_MAX;
    return result;
}

static VirtDRTMTPMResult execute_extends(VirtDRTMTPMExecution *execution,
    const VirtDRTMTPMOps *ops, void *opaque, size_t first, size_t limit,
    Error **errp)
{
    VirtDRTMTPMResult result = {
        .status = VIRT_DRTM_TPM_INVALID,
        .irreversible = true,
        .failed_operation = SIZE_MAX,
    };
    size_t count, i;

    if (!execution || !execution->initialized || execution->failed ||
        execution->next_operation != first || !ops || !ops->command ||
        limit < first || limit > virt_drtm_measurement_manifest_operation_count(
            execution->manifest)) {
        error_setg(errp, "invalid DRTM TPM extend phase");
        return result;
    }
    count = limit;
    for (i = first; i < count; i++) {
        const VirtDRTMMeasurementOperation *op =
            virt_drtm_measurement_manifest_operation(execution->manifest, i);
        uint8_t request[97] = { };
        uint8_t response[64] = { };
        size_t request_size = make_pcr_extend(request, op);
        size_t response_size = sizeof(response);

        result.failed_operation = i;
        if (!ops->command(opaque, 3, request, request_size,
                          response, &response_size, errp)) {
            execution->failed = true;
            result.status = VIRT_DRTM_TPM_TRANSPORT_ERROR;
            return result;
        }
        if (!success_response(response, response_size,
                              &result.response_code)) {
            execution->failed = true;
            error_setg(errp, "invalid TPM2_PCR_Extend response");
            result.status = VIRT_DRTM_TPM_RESPONSE_ERROR;
            return result;
        }
        execution->next_operation = i + 1;
    }
    result.status = VIRT_DRTM_TPM_OK;
    result.failed_operation = SIZE_MAX;
    return result;
}

VirtDRTMTPMResult virt_drtm_tpm_execute_dcrtm_extends(
    VirtDRTMTPMExecution *execution, const VirtDRTMTPMOps *ops,
    void *opaque, Error **errp)
{
    size_t boundary = execution && execution->manifest ?
        virt_drtm_measurement_manifest_dce_operation(execution->manifest) : 0;

    return execute_extends(execution, ops, opaque, 3, boundary, errp);
}

VirtDRTMTPMResult virt_drtm_tpm_execute_dce_extends(
    VirtDRTMTPMExecution *execution, const VirtDRTMTPMOps *ops,
    void *opaque, Error **errp)
{
    size_t boundary = execution && execution->manifest ?
        virt_drtm_measurement_manifest_dce_operation(execution->manifest) : 0;
    size_t count = execution && execution->manifest ?
        virt_drtm_measurement_manifest_operation_count(execution->manifest) : 0;

    return execute_extends(execution, ops, opaque, boundary, count, errp);
}
