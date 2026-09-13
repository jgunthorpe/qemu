/*
 * Arm DRTM TPM PCR bank discovery
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "hw/arm/virt-drtm-tpm.h"
#include "qapi/error.h"
#include "qemu/bswap.h"

#define TPM2_ST_NO_SESSIONS       0x8001
#define TPM2_CC_GET_CAPABILITY    0x0000017a
#define TPM2_CAP_PCRS             0x00000005
#define TPM2_GET_CAPABILITY_SIZE  22
#define TPM2_RESPONSE_HEADER_SIZE 10
#define TPM2_PCRS_RESPONSE_PREFIX 19
#define TPM2_PCR_SELECT_MIN       3

static bool pcr_selected(const uint8_t *select, uint8_t size,
                         unsigned int pcr)
{
    return pcr / 8 < size && (select[pcr / 8] & (1U << (pcr % 8)));
}

static bool selection_active(const uint8_t *select, uint8_t size)
{
    uint8_t i;

    for (i = 0; i < size; i++) {
        if (select[i]) {
            return true;
        }
    }
    return false;
}

static bool parse_pcr_banks(const uint8_t *response, size_t size,
                            VirtDRTMTPMBanks *result)
{
    uint32_t count;
    size_t offset;
    unsigned int i, j;

    if (size < TPM2_PCRS_RESPONSE_PREFIX ||
        lduw_be_p(response) != TPM2_ST_NO_SESSIONS ||
        ldl_be_p(response + 2) != size ||
        response[10] > 1 || response[10] ||
        ldl_be_p(response + 11) != TPM2_CAP_PCRS) {
        return false;
    }

    count = ldl_be_p(response + 15);
    if (!count || count > (size - TPM2_PCRS_RESPONSE_PREFIX) / 3) {
        return false;
    }
    offset = TPM2_PCRS_RESPONSE_PREFIX;
    for (i = 0; i < count; i++) {
        uint16_t algorithm;
        uint8_t select_size;
        const uint8_t *select;

        if (size - offset < 3) {
            return false;
        }
        algorithm = lduw_be_p(response + offset);
        select_size = response[offset + 2];
        offset += 3;
        if (select_size < TPM2_PCR_SELECT_MIN || select_size > size - offset) {
            return false;
        }
        select = response + offset;
        offset += select_size;

        if (!selection_active(select, select_size)) {
            /* TPM_CAP_PCRS may also report supported, unallocated banks. */
            continue;
        }
        switch (algorithm) {
        case VIRT_DRTM_TPM_ALG_SHA1:
        case VIRT_DRTM_TPM_ALG_SHA256:
        case VIRT_DRTM_TPM_ALG_SHA384:
        case VIRT_DRTM_TPM_ALG_SHA512:
            break;
        default:
            return false;
        }
        for (j = 0; j < result->bank_count; j++) {
            if (result->banks[j] == algorithm) {
                return false;
            }
        }
        if (!pcr_selected(select, select_size, 17) ||
            !pcr_selected(select, select_size, 18)) {
            return false;
        }
        result->banks[result->bank_count++] = algorithm;
    }
    if (offset != size || !result->bank_count) {
        return false;
    }
    return virt_drtm_firmware_hash_select(result->banks, result->bank_count,
                                           &result->selected_algorithm) ==
           VIRT_DRTM_EVENT_LOG_OK;
}

VirtDRTMTPMBanks virt_drtm_tpm_discover_banks(
    const VirtDRTMTPMOps *ops, void *opaque, Error **errp)
{
    VirtDRTMTPMBanks result = { .status = VIRT_DRTM_TPM_BANKS_INVALID };
    uint8_t request[TPM2_GET_CAPABILITY_SIZE] = { };
    uint8_t response[1024] = { };
    size_t response_size = sizeof(response);

    if (!ops || !ops->command) {
        error_setg(errp, "invalid DRTM TPM bank discovery transport");
        return result;
    }

    stw_be_p(request, TPM2_ST_NO_SESSIONS);
    stl_be_p(request + 2, sizeof(request));
    stl_be_p(request + 6, TPM2_CC_GET_CAPABILITY);
    stl_be_p(request + 10, TPM2_CAP_PCRS);
    stl_be_p(request + 14, 0); /* property is ignored for TPM_CAP_PCRS */
    stl_be_p(request + 18, 1);

    if (!ops->command(opaque, 0, request, sizeof(request), response,
                      &response_size, errp)) {
        result.status = VIRT_DRTM_TPM_BANKS_TRANSPORT_ERROR;
        if (errp && !*errp) {
            error_setg(errp, "TPM2_GetCapability transport failed");
        }
        return result;
    }
    if (response_size < TPM2_RESPONSE_HEADER_SIZE ||
        response_size > sizeof(response)) {
        result.status = VIRT_DRTM_TPM_BANKS_RESPONSE_ERROR;
        error_setg(errp, "invalid TPM2_GetCapability response size %zu",
                   response_size);
        return result;
    }
    result.response_code = ldl_be_p(response + 6);
    if (result.response_code) {
        if (response_size != TPM2_RESPONSE_HEADER_SIZE ||
            lduw_be_p(response) != TPM2_ST_NO_SESSIONS ||
            ldl_be_p(response + 2) != response_size) {
            result.status = VIRT_DRTM_TPM_BANKS_RESPONSE_ERROR;
            error_setg(errp, "malformed TPM2_GetCapability error response");
            return result;
        }
        result.status = VIRT_DRTM_TPM_BANKS_TPM_ERROR;
        error_setg(errp, "TPM2_GetCapability failed with response code 0x%x",
                   result.response_code);
        return result;
    }
    if (!parse_pcr_banks(response, response_size, &result)) {
        result.status = VIRT_DRTM_TPM_BANKS_RESPONSE_ERROR;
        result.bank_count = 0;
        result.selected_algorithm = 0;
        error_setg(errp, "invalid TPM2_GetCapability PCR bank response");
        return result;
    }
    result.status = VIRT_DRTM_TPM_BANKS_OK;
    return result;
}
