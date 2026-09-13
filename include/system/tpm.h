/*
 * Public TPM functions
 *
 * Copyright (C) 2011-2013 IBM Corporation
 *
 * Authors:
 *  Stefan Berger    <stefanb@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */
#ifndef QEMU_TPM_H
#define QEMU_TPM_H

#include "qapi/qapi-types-tpm.h"
#include "qom/object.h"

#ifdef CONFIG_TPM

int tpm_config_parse(QemuOptsList *opts_list, const char *optstr);
int tpm_init(void);
void tpm_cleanup(void);

typedef enum TPMVersion {
    TPM_VERSION_UNSPEC = 0,
    TPM_VERSION_1_2 = 1,
    TPM_VERSION_2_0 = 2,
} TPMVersion;

#define TYPE_TPM_IF "tpm-if"
typedef struct TPMIfClass TPMIfClass;
DECLARE_CLASS_CHECKERS(TPMIfClass, TPM_IF,
                       TYPE_TPM_IF)
#define TPM_IF(obj)                             \
    INTERFACE_CHECK(TPMIf, (obj), TYPE_TPM_IF)

typedef struct TPMIf TPMIf;

typedef enum TPMDRTMLocalityCloseResult {
    TPM_DRTM_LOCALITY_CLOSED,
    TPM_DRTM_LOCALITY_ALREADY_CLOSED,
    TPM_DRTM_LOCALITY_NOT_RELINQUISHED,
} TPMDRTMLocalityCloseResult;

struct TPMIfClass {
    InterfaceClass parent_class;

    enum TpmModel model;
    void (*request_completed)(TPMIf *obj, int ret);
    enum TPMVersion (*get_version)(TPMIf *obj);
    bool (*deliver_platform_request)(TPMIf *obj, uint8_t locality,
                                     const uint8_t *request,
                                     size_t request_size,
                                     uint8_t *response,
                                     size_t *response_size,
                                     Error **errp);
    bool (*enable_drtm)(TPMIf *obj, Error **errp);
    bool (*drtm_no_active_locality)(TPMIf *obj, bool *no_active,
                                    Error **errp);
    bool (*drtm_open_localities)(TPMIf *obj, Error **errp);
    bool (*drtm_close_locality)(TPMIf *obj, uint8_t locality,
                                TPMDRTMLocalityCloseResult *result,
                                Error **errp);
    bool (*drtm_activate_locality2)(TPMIf *obj, Error **errp);
    bool ppi_enabled;
};

/*
 * Submit a TPM 2 command on behalf of platform firmware.
 *
 * The TPM frontend owns serialization with guest traffic.  This synchronous
 * interface keeps request and response storage valid until the frontend has
 * received the backend completion.  A successful transport may still return
 * a non-zero TPM response code in @response_code.
 *
 * The caller must hold the BQL.  This is a command-buffer primitive, not a
 * TPM locality lifecycle or PTP HASH_START/HASH_DATA/HASH_END interface.  It
 * stops waiting after 30 seconds for each backend turn, requests cancellation,
 * and keeps a timed-out request owned until its late completion.  A backend's
 * cancellation operation can itself add latency.
 */
bool tpm_deliver_platform_request(TPMIf *ti, uint8_t locality,
                                  const uint8_t *request,
                                  size_t request_size,
                                  uint8_t *response,
                                  size_t *response_size,
                                  uint32_t *response_code,
                                  Error **errp);

/*
 * Enable and operate the Arm DRTM dynamic-locality mediation contract.
 *
 * Enabling the contract is a platform setup operation and requires no active
 * TPM locality.  It closes dynamic localities 1-3 immediately and on every
 * subsequent device reset.  Opening them is atomic and also requires that no
 * locality is active, matching the two phases of DRTM_DYNAMIC_LAUNCH.
 *
 * Closing locality 2 or 3 reports protocol state separately from transport
 * failure so DRTM_CLOSE_LOCALITY can distinguish ALREADY_CLOSED from DENIED.
 * The caller must hold the BQL for all of these operations.
 */
bool tpm_enable_drtm(TPMIf *ti, Error **errp);
bool tpm_drtm_no_active_locality(TPMIf *ti, bool *no_active, Error **errp);
bool tpm_drtm_open_localities(TPMIf *ti, Error **errp);
bool tpm_drtm_close_locality(TPMIf *ti, uint8_t locality,
                             TPMDRTMLocalityCloseResult *result,
                             Error **errp);
bool tpm_drtm_activate_locality2(TPMIf *ti, Error **errp);

#define TYPE_TPM_TIS_ISA            "tpm-tis"
#define TYPE_TPM_TIS_SYSBUS         "tpm-tis-device"
#define TYPE_TPM_CRB                "tpm-crb"
#define TYPE_TPM_SPAPR              "tpm-spapr"
#define TYPE_TPM_TIS_I2C            "tpm-tis-i2c"

#define TPM_IS_TIS_ISA(chr)                         \
    object_dynamic_cast(OBJECT(chr), TYPE_TPM_TIS_ISA)
#define TPM_IS_TIS_SYSBUS(chr)                      \
    object_dynamic_cast(OBJECT(chr), TYPE_TPM_TIS_SYSBUS)
#define TPM_IS_CRB(chr)                             \
    object_dynamic_cast(OBJECT(chr), TYPE_TPM_CRB)
#define TPM_IS_SPAPR(chr)                           \
    object_dynamic_cast(OBJECT(chr), TYPE_TPM_SPAPR)
#define TPM_IS_TIS_I2C(chr)                      \
    object_dynamic_cast(OBJECT(chr), TYPE_TPM_TIS_I2C)

/* returns NULL unless there is exactly one TPM device */
static inline TPMIf *tpm_find(void)
{
    Object *obj = object_resolve_path_type("", TYPE_TPM_IF, NULL);

    return TPM_IF(obj);
}

static inline TPMVersion tpm_get_version(TPMIf *ti)
{
    if (!ti) {
        return TPM_VERSION_UNSPEC;
    }

    return TPM_IF_GET_CLASS(ti)->get_version(ti);
}

static inline bool tpm_ppi_enabled(TPMIf *ti)
{
    if (!ti) {
        return false;
    }
    return TPM_IF_GET_CLASS(ti)->ppi_enabled;
}

#else /* CONFIG_TPM */

#define tpm_init()  (0)
#define tpm_cleanup()

/* needed for an alignment check in non-tpm code */
static inline Object *TPM_IS_CRB(Object *obj)
{
     return NULL;
}

#endif /* CONFIG_TPM */

#endif /* QEMU_TPM_H */
