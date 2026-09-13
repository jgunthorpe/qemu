/*
 * Arm DRTM adapter for QEMU's serialized TPM frontend paths
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "hw/arm/virt-drtm-tpm.h"
#include "qapi/error.h"
#include "qemu/main-loop.h"

#ifdef CONFIG_TPM
static bool frontend_hash(void *opaque, uint8_t locality,
                          TPMBackendDRTMHashOperation operation,
                          const uint8_t *data, size_t data_size, Error **errp)
{
    g_assert(locality == 4);
    return tpm_drtm_hash(opaque, operation, data, data_size, errp);
}

static bool frontend_command(void *opaque, uint8_t locality,
                             const uint8_t *request, size_t request_size,
                             uint8_t *response, size_t *response_size,
                             Error **errp)
{
    return tpm_deliver_platform_request(opaque, locality,
                                        request, request_size,
                                        response, response_size, NULL, errp);
}

static const VirtDRTMTPMOps frontend_ops = {
    .hash = frontend_hash,
    .command = frontend_command,
};

static VirtDRTMTPMResult invalid_result(void)
{
    return (VirtDRTMTPMResult) {
        .status = VIRT_DRTM_TPM_INVALID,
        .failed_operation = SIZE_MAX,
    };
}

bool virt_drtm_tpm_frontend_execution_init(
    VirtDRTMTPMFrontendExecution *frontend,
    const VirtDRTMMeasurementManifest *manifest, TPMIf *tpm, Error **errp)
{
    TPMIfClass *tc;

    g_assert(bql_locked());
    if (!frontend) {
        error_setg(errp, "missing DRTM TPM frontend execution context");
        return false;
    }
    memset(frontend, 0, sizeof(*frontend));
    if (!tpm || tpm_get_version(tpm) != TPM_VERSION_2_0) {
        error_setg(errp, "DRTM measurement requires a TPM 2 frontend");
        return false;
    }
    tc = TPM_IF_GET_CLASS(tpm);
    if (!tc->drtm_hash || !tc->deliver_platform_request) {
        error_setg(errp,
                   "TPM frontend lacks DRTM hash or platform commands");
        return false;
    }
    if (!virt_drtm_tpm_execution_init(&frontend->execution, manifest, errp)) {
        return false;
    }
    frontend->tpm = tpm;
    return true;
}

VirtDRTMTPMResult virt_drtm_tpm_frontend_execute_hash(
    VirtDRTMTPMFrontendExecution *frontend, Error **errp)
{
    g_assert(bql_locked());
    if (!frontend) {
        error_setg(errp, "missing DRTM TPM frontend execution context");
        return invalid_result();
    }
    return virt_drtm_tpm_execute_hash(&frontend->execution, &frontend_ops,
                                      frontend->tpm, errp);
}

VirtDRTMTPMResult virt_drtm_tpm_frontend_execute_dcrtm_extends(
    VirtDRTMTPMFrontendExecution *frontend, Error **errp)
{
    g_assert(bql_locked());
    if (!frontend) {
        error_setg(errp, "missing DRTM TPM frontend execution context");
        return invalid_result();
    }
    return virt_drtm_tpm_execute_dcrtm_extends(&frontend->execution,
                                               &frontend_ops, frontend->tpm,
                                               errp);
}

VirtDRTMTPMResult virt_drtm_tpm_frontend_execute_dce_extends(
    VirtDRTMTPMFrontendExecution *frontend, Error **errp)
{
    g_assert(bql_locked());
    if (!frontend) {
        error_setg(errp, "missing DRTM TPM frontend execution context");
        return invalid_result();
    }
    return virt_drtm_tpm_execute_dce_extends(&frontend->execution,
                                             &frontend_ops, frontend->tpm,
                                             errp);
}

VirtDRTMTPMResult virt_drtm_tpm_execute_frontend(
    const VirtDRTMMeasurementManifest *manifest, TPMIf *tpm, Error **errp)
{
    VirtDRTMTPMFrontendExecution frontend;
    VirtDRTMTPMResult result;

    g_assert(bql_locked());
    if (!virt_drtm_tpm_frontend_execution_init(&frontend, manifest, tpm,
                                                errp)) {
        return invalid_result();
    }
    result = virt_drtm_tpm_frontend_execute_hash(&frontend, errp);
    if (result.status != VIRT_DRTM_TPM_OK) {
        return result;
    }
    result = virt_drtm_tpm_frontend_execute_dcrtm_extends(&frontend, errp);
    if (result.status != VIRT_DRTM_TPM_OK) {
        return result;
    }
    return virt_drtm_tpm_frontend_execute_dce_extends(&frontend, errp);
}

VirtDRTMTPMBanks virt_drtm_tpm_discover_banks_frontend(
    TPMIf *tpm, Error **errp)
{
    static const VirtDRTMTPMOps ops = {
        .command = frontend_command,
    };

    g_assert(bql_locked());
    return virt_drtm_tpm_discover_banks(&ops, tpm, errp);
}
#endif
