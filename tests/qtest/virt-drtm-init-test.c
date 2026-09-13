/*
 * Arm virt DRTM machine-initialization test
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include <glib/gstdio.h>

#include "hw/acpi/tpm.h"
#include "io/channel-socket.h"
#include "libqtest-single.h"
#include "qemu/module.h"
#include "tpm-emu.h"

#define TPM_TIS_BASE                  0xc000000

static uint64_t access_address(unsigned int locality)
{
    return TPM_TIS_BASE + (locality << TPM_TIS_LOCALITY_SHIFT) +
           TPM_TIS_REG_ACCESS;
}

static void assert_dynamic_localities_closed(void)
{
    unsigned int locality;

    for (locality = 1; locality <= 3; locality++) {
        uint64_t address = access_address(locality);

        g_assert_cmphex(readb(address), ==,
                        TPM_TIS_ACCESS_TPM_REG_VALID_STS |
                        TPM_TIS_ACCESS_TPM_ESTABLISHMENT);
        writeb(address, TPM_TIS_ACCESS_REQUEST_USE);
        g_assert_cmphex(readb(address), ==,
                        TPM_TIS_ACCESS_TPM_REG_VALID_STS |
                        TPM_TIS_ACCESS_TPM_ESTABLISHMENT);
    }
}

static void test_init_and_reset(const void *opaque)
{
    const TPMTestState *test = opaque;

    g_assert_cmpint(g_atomic_int_get(&test->pcr_bank_queries), ==, 0);
    assert_dynamic_localities_closed();
    qtest_system_reset(global_qtest);
    g_assert_cmpint(g_atomic_int_get(&test->pcr_bank_queries), ==, 0);
    assert_dynamic_localities_closed();
}

int main(int argc, char **argv)
{
    g_autofree char *test_dir = NULL;
    g_autofree char *args = NULL;
    TPMTestState test = { .tpm_version = TPM_VERSION_2_0,
                          .provide_pcr_banks = true };
    GThread *thread;
    int ret;

    module_call_init(MODULE_INIT_QOM);
    g_test_init(&argc, &argv, NULL);

    test_dir = g_dir_make_tmp("qemu-virt-drtm-init-test.XXXXXX", NULL);
    g_assert_nonnull(test_dir);
    test.addr = g_new0(SocketAddress, 1);
    test.addr->type = SOCKET_ADDRESS_TYPE_UNIX;
    test.addr->u.q_unix.path = g_build_filename(test_dir, "sock", NULL);
    g_mutex_init(&test.data_mutex);
    g_cond_init(&test.data_cond);

    thread = g_thread_new(NULL, tpm_emu_ctrl_thread, &test);
    tpm_emu_test_wait_cond(&test);

    args = g_strdup_printf(
        "-machine virt,gic-version=max,virtualization=on,x-drtm=on "
        "-accel tcg -cpu max -chardev socket,id=chr,path=%s "
        "-tpmdev emulator,id=dev,chardev=chr "
        "-device tpm-tis-device,tpmdev=dev",
        test.addr->u.q_unix.path);
    qtest_start(args);

    /* Startup itself verifies that SMC routing preceded MACHINE_READY. */
    qtest_add_data_func("/virt-drtm/init-before-registry-freeze-reset", &test,
                        test_init_and_reset);

    ret = g_test_run();
    qtest_end();
    g_thread_join(thread);
    g_unlink(test.addr->u.q_unix.path);
    qapi_free_SocketAddress(test.addr);
    g_rmdir(test_dir);
    return ret;
}
