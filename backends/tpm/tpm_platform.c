/*
 * TPM platform/firmware command transport
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/main-loop.h"
#include "system/tpm.h"
#include "system/tpm_util.h"

#define TPM2_HEADER_SIZE       10
#define TPM2_ST_NO_SESSIONS    0x8001
#define TPM2_ST_SESSIONS       0x8002
#define TPM2_MAX_LOCALITY      4

static bool tpm2_valid_tag(uint16_t tag)
{
    return tag == TPM2_ST_NO_SESSIONS || tag == TPM2_ST_SESSIONS;
}

static TPMIfClass *tpm_drtm_frontend(TPMIf *ti, Error **errp)
{
    if (!ti) {
        error_setg(errp, "no TPM frontend is available");
        return NULL;
    }
    if (tpm_get_version(ti) != TPM_VERSION_2_0) {
        error_setg(errp, "DRTM localities require a TPM 2 frontend");
        return NULL;
    }

    return TPM_IF_GET_CLASS(ti);
}

bool tpm_enable_drtm(TPMIf *ti, Error **errp)
{
    TPMIfClass *tc;

    g_assert(bql_locked());
    tc = tpm_drtm_frontend(ti, errp);
    if (!tc) {
        return false;
    }
    if (!tc->enable_drtm) {
        error_setg(errp, "TPM frontend does not support DRTM localities");
        return false;
    }
    return tc->enable_drtm(ti, errp);
}

bool tpm_drtm_no_active_locality(TPMIf *ti, bool *no_active, Error **errp)
{
    TPMIfClass *tc;

    g_assert(bql_locked());
    if (!no_active) {
        error_setg(errp, "missing TPM locality probe result");
        return false;
    }
    tc = tpm_drtm_frontend(ti, errp);
    if (!tc) {
        return false;
    }
    if (!tc->drtm_no_active_locality) {
        error_setg(errp, "TPM frontend does not support DRTM localities");
        return false;
    }
    return tc->drtm_no_active_locality(ti, no_active, errp);
}

bool tpm_drtm_open_localities(TPMIf *ti, Error **errp)
{
    TPMIfClass *tc;

    g_assert(bql_locked());
    tc = tpm_drtm_frontend(ti, errp);
    if (!tc) {
        return false;
    }
    if (!tc->drtm_open_localities) {
        error_setg(errp, "TPM frontend does not support DRTM localities");
        return false;
    }
    return tc->drtm_open_localities(ti, errp);
}

bool tpm_drtm_close_locality(TPMIf *ti, uint8_t locality,
                             TPMDRTMLocalityCloseResult *result,
                             Error **errp)
{
    TPMIfClass *tc;

    g_assert(bql_locked());
    if (!result || (locality != 2 && locality != 3)) {
        error_setg(errp, "invalid DRTM locality close request");
        return false;
    }
    tc = tpm_drtm_frontend(ti, errp);
    if (!tc) {
        return false;
    }
    if (!tc->drtm_close_locality) {
        error_setg(errp, "TPM frontend does not support DRTM localities");
        return false;
    }
    return tc->drtm_close_locality(ti, locality, result, errp);
}

bool tpm_drtm_activate_locality2(TPMIf *ti, Error **errp)
{
    TPMIfClass *tc;

    g_assert(bql_locked());
    tc = tpm_drtm_frontend(ti, errp);
    if (!tc) {
        return false;
    }
    if (!tc->drtm_activate_locality2) {
        error_setg(errp, "TPM frontend does not support DRTM localities");
        return false;
    }
    return tc->drtm_activate_locality2(ti, errp);
}

bool tpm_drtm_hash(TPMIf *ti, TPMBackendDRTMHashOperation operation,
                   const uint8_t *data, size_t data_size, Error **errp)
{
    TPMIfClass *tc;

    g_assert(bql_locked());
    if (operation > TPM_BACKEND_DRTM_HASH_END ||
        (operation == TPM_BACKEND_DRTM_HASH_DATA &&
         (!data || !data_size)) ||
        (operation != TPM_BACKEND_DRTM_HASH_DATA && data_size)) {
        error_setg(errp, "invalid PTP hash operation");
        return false;
    }
    tc = tpm_drtm_frontend(ti, errp);
    if (!tc) {
        return false;
    }
    if (!tc->drtm_hash) {
        error_setg(errp, "TPM frontend does not support PTP hashing");
        return false;
    }
    return tc->drtm_hash(ti, operation, data, data_size, errp);
}

bool tpm_deliver_platform_request(TPMIf *ti, uint8_t locality,
                                  const uint8_t *request,
                                  size_t request_size,
                                  uint8_t *response,
                                  size_t *response_size,
                                  uint32_t *response_code,
                                  Error **errp)
{
    ERRP_GUARD();
    TPMIfClass *tc;
    size_t response_capacity = response_size ? *response_size : 0;
    size_t actual_size;

    g_assert(bql_locked());

    if (response_size) {
        *response_size = 0;
    }

    if (!ti) {
        error_setg(errp, "no TPM frontend is available");
        return false;
    }
    if (locality > TPM2_MAX_LOCALITY) {
        error_setg(errp, "invalid TPM locality %u", locality);
        return false;
    }
    if (!request || request_size < TPM2_HEADER_SIZE ||
        request_size > UINT32_MAX) {
        error_setg(errp, "invalid TPM request buffer size %zu", request_size);
        return false;
    }
    if (!response || !response_size || response_capacity < TPM2_HEADER_SIZE ||
        response_capacity > UINT32_MAX) {
        error_setg(errp, "invalid TPM response buffer");
        return false;
    }

    if (!tpm2_valid_tag(tpm_cmd_get_tag(request))) {
        error_setg(errp, "invalid TPM 2 request tag 0x%04x",
                   tpm_cmd_get_tag(request));
        return false;
    }
    if (tpm_cmd_get_size(request) != request_size) {
        error_setg(errp, "TPM request size field does not match its buffer");
        return false;
    }
    if (tpm_get_version(ti) != TPM_VERSION_2_0) {
        error_setg(errp, "platform commands require a TPM 2 frontend");
        return false;
    }

    tc = TPM_IF_GET_CLASS(ti);
    if (!tc->deliver_platform_request) {
        error_setg(errp, "TPM frontend does not support platform commands");
        return false;
    }

    actual_size = response_capacity;
    if (!tc->deliver_platform_request(ti, locality, request, request_size,
                                      response, &actual_size, errp)) {
        if (!*errp) {
            error_setg(errp, "TPM platform command transport failed");
        }
        return false;
    }
    if (actual_size < TPM2_HEADER_SIZE || actual_size > response_capacity) {
        error_setg(errp, "invalid TPM response size %zu", actual_size);
        return false;
    }
    if (!tpm2_valid_tag(tpm_cmd_get_tag(response))) {
        error_setg(errp, "invalid TPM 2 response tag 0x%04x",
                   tpm_cmd_get_tag(response));
        return false;
    }
    if (tpm_cmd_get_size(response) != actual_size) {
        error_setg(errp, "TPM response size field does not match its buffer");
        return false;
    }

    *response_size = actual_size;
    if (response_code) {
        *response_code = tpm_cmd_get_errcode(response);
    }
    return true;
}
