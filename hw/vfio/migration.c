/*
 * Migration support for VFIO devices
 *
 * Copyright NVIDIA, Inc. 2020
 *
 * This work is licensed under the terms of the GNU GPL, version 2. See
 * the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "qemu/cutils.h"
#include <linux/vfio.h>
#include <sys/ioctl.h>

#include "sysemu/runstate.h"
#include "hw/vfio/vfio-common.h"
#include "migration/migration.h"
#include "migration/vmstate.h"
#include "migration/qemu-file.h"
#include "migration/register.h"
#include "migration/blocker.h"
#include "migration/misc.h"
#include "qapi/error.h"
#include "exec/ramlist.h"
#include "exec/ram_addr.h"
#include "pci.h"
#include "trace.h"
#include "hw/hw.h"

/*
 * Flags to be used as unique delimiters for VFIO devices in the migration
 * stream. These flags are composed as:
 * 0xffffffff => MSB 32-bit all 1s
 * 0xef10     => Magic ID, represents emulated (virtual) function IO
 * 0x0000     => 16-bits reserved for flags
 *
 * The beginning of state information is marked by _DEV_CONFIG_STATE,
 * _DEV_SETUP_STATE, or _DEV_DATA_STATE, respectively. The end of a
 * certain state information is marked by _END_OF_STATE.
 */
#define VFIO_MIG_FLAG_END_OF_STATE      (0xffffffffef100001ULL)
#define VFIO_MIG_FLAG_DEV_CONFIG_STATE  (0xffffffffef100002ULL)
#define VFIO_MIG_FLAG_DEV_SETUP_STATE   (0xffffffffef100003ULL)
#define VFIO_MIG_FLAG_DEV_DATA_STATE    (0xffffffffef100004ULL)

static int64_t bytes_transferred;

static int vfio_migration_set_state(VFIODevice *vbasedev,
                                    enum vfio_device_mig_state new_state,
                                    enum vfio_device_mig_state recover_state)
{
    VFIOMigration *migration = vbasedev->migration;
    struct vfio_device_mig_set_state set_state = {
        .argsz = sizeof(set_state),
        .device_state = new_state,
        .data_fd = -1,
    };
    int ret;

    ret = ioctl(vbasedev->fd, VFIO_DEVICE_MIG_SET_STATE, &set_state);
    if (ret) {
        /* Try to put the device in some good state */
        set_state.device_state = recover_state;
        if (ioctl(vbasedev->fd, VFIO_DEVICE_MIG_SET_STATE, &set_state)) {
            /* FIXME: Need to reset the device to recover it */
            hw_error("%s: Device in error state 0x%x", vbasedev->name,
                     set_state.device_state);
            return ret;
        }
        error_report("%s: Failed changing device state to %d", vbasedev->name,
                     new_state);
        return ret;
    }

    if (set_state.data_fd != -1) {
        if (migration->data_fd != -1) {
            error_report("%s: data_fd out of sync", vbasedev->name);
            close(migration->data_fd);
        }
        migration->data_fd = set_state.data_fd;
    }
    migration->device_state = set_state.device_state;

    trace_vfio_migration_set_state(vbasedev->name, set_state.device_state);
    return 0;
}

static int vfio_load_buffer(QEMUFile *f, VFIODevice *vbasedev,
                            uint64_t data_size)
{
    VFIOMigration *migration = vbasedev->migration;
    int ret;

    ret = qemu_file_get_to_fd(f, migration->data_fd, data_size);
    if (ret) {
        return ret;
    }
    trace_vfio_load_state_device_data(vbasedev->name, data_size);
    return 0;
}

static int vfio_save_device_config_state(QEMUFile *f, void *opaque)
{
    VFIODevice *vbasedev = opaque;

    qemu_put_be64(f, VFIO_MIG_FLAG_DEV_CONFIG_STATE);

    if (vbasedev->ops && vbasedev->ops->vfio_save_config) {
        vbasedev->ops->vfio_save_config(vbasedev, f);
    }

    qemu_put_be64(f, VFIO_MIG_FLAG_END_OF_STATE);

    trace_vfio_save_device_config_state(vbasedev->name);

    return qemu_file_get_error(f);
}

static int vfio_load_device_config_state(QEMUFile *f, void *opaque)
{
    VFIODevice *vbasedev = opaque;
    uint64_t data;

    if (vbasedev->ops && vbasedev->ops->vfio_load_config) {
        int ret;

        ret = vbasedev->ops->vfio_load_config(vbasedev, f);
        if (ret) {
            error_report("%s: Failed to load device config space",
                         vbasedev->name);
            return ret;
        }
    }

    data = qemu_get_be64(f);
    if (data != VFIO_MIG_FLAG_END_OF_STATE) {
        error_report("%s: Failed loading device config space, "
                     "end flag incorrect 0x%"PRIx64, vbasedev->name, data);
        return -EINVAL;
    }

    trace_vfio_load_device_config_state(vbasedev->name);
    return qemu_file_get_error(f);
}

static void vfio_migration_cleanup(VFIODevice *vbasedev)
{
    VFIOMigration *migration = vbasedev->migration;

    close(migration->data_fd);
    migration->data_fd = -1;
}

/* ---------------------------------------------------------------------- */

static int vfio_save_precopy_setup(QEMUFile *f, void *opaque)
{
    VFIODevice *vbasedev = opaque;
    VFIOMigration *migration = vbasedev->migration;
    int ret;

    trace_vfio_save_setup(vbasedev->name);

    qemu_put_be64(f, VFIO_MIG_FLAG_DEV_SETUP_STATE);

    switch (migration->device_state) {
    case VFIO_DEVICE_STATE_RUNNING:
        ret = vfio_migration_set_state(vbasedev, VFIO_DEVICE_STATE_PRE_COPY,
                                       VFIO_DEVICE_STATE_RUNNING);
        if (ret) {
            error_report("%s: Failed to set state PRE_COPY", vbasedev->name);
            return ret;
        }
        break;
    case VFIO_DEVICE_STATE_STOP:
        /* vfio_save_complete_precopy() will goto STOP_COPY */
        break;
    default:
        return -EINVAL;
    }

    qemu_put_be64(f, VFIO_MIG_FLAG_END_OF_STATE);
    return qemu_file_get_error(f);
}

static int vfio_save_setup(QEMUFile *f, void *opaque)
{
    VFIODevice *vbasedev = opaque;

    trace_vfio_save_setup(vbasedev->name);

    qemu_put_be64(f, VFIO_MIG_FLAG_DEV_SETUP_STATE);
    qemu_put_be64(f, VFIO_MIG_FLAG_END_OF_STATE);

    return qemu_file_get_error(f);
}

static void vfio_save_cleanup(void *opaque)
{
    VFIODevice *vbasedev = opaque;

    vfio_migration_cleanup(vbasedev);
    trace_vfio_save_cleanup(vbasedev->name);
}

/* Return an indication how much work is required to complete the precopy */
static void vfio_save_precopy_pending(QEMUFile *f, void *opaque,
                                      uint64_t threshold_size,
                                      uint64_t *res_precopy_only,
                                      uint64_t *res_compatible,
                                      uint64_t *res_postcopy_only)
{
    VFIODevice *vbasedev = opaque;
    struct vfio_device_mig_precopy precopy = {
        .argsz = sizeof(precopy),
    };
    int ret;

    ret = ioctl(vbasedev->fd, VFIO_DEVICE_MIG_PRECOPY, &precopy);
    if (ret) {
        return;
    }

    *res_precopy_only += precopy.initial_bytes + precopy.dirty_bytes;

    trace_vfio_save_pending(vbasedev->name, *res_precopy_only,
                            *res_postcopy_only, *res_compatible);
}

/* Returns 1 if end-of-stream is reached, 0 if more data and -1 if error */
static int vfio_save_block(QEMUFile *f, VFIOMigration *migration)
{
    ssize_t data_size;

    data_size = read(migration->data_fd, migration->data_buffer,
                     migration->data_buffer_size);
    if (data_size < 0) {
        /* PRE_COPY emptied all the device state for now */
        if (errno == ENOMSG) {
            return 1;
        }
        return -1;
    }
    if (data_size == 0) {
        return 1;
    }

    qemu_put_be64(f, VFIO_MIG_FLAG_DEV_DATA_STATE);
    qemu_put_be64(f, data_size);
    qemu_put_buffer_async(f, migration->data_buffer, data_size, false);
    qemu_fflush(f);
    bytes_transferred += data_size;
    trace_vfio_save_block(migration->vbasedev->name, data_size);
    return qemu_file_get_error(f);
}

static int vfio_save_iterate(QEMUFile *f, void *opaque)
{
    VFIODevice *vbasedev = opaque;
    VFIOMigration *migration = vbasedev->migration;
    int ret;

    ret = vfio_save_block(f, migration);
    if (ret < 0) {
        return ret;
    }
    if (ret == 1) {
        return 1;
    }
    qemu_put_be64(f, VFIO_MIG_FLAG_END_OF_STATE);
    return 0;
}

static int vfio_save_complete_precopy(QEMUFile *f, void *opaque)
{
    VFIODevice *vbasedev = opaque;
    enum vfio_device_mig_state recover_state;
    int ret;

    /*
     * FIXME: Seems like the state should always be STOP or STOP_COPY by the
     * time we get here, check and confirm
     */
    if (vbasedev->migration->device_state == VFIO_DEVICE_STATE_STOP ||
        vbasedev->migration->device_state == VFIO_DEVICE_STATE_STOP_COPY) {
        recover_state = VFIO_DEVICE_STATE_STOP;
    } else {
        recover_state = VFIO_DEVICE_STATE_RUNNING;
    }

    ret = vfio_migration_set_state(vbasedev, VFIO_DEVICE_STATE_STOP_COPY,
                                   recover_state);
    if (ret) {
        error_report("%s: Failed to set state STOP_COPY", vbasedev->name);
        return ret;
    }

    do {
        ret = vfio_save_block(f, vbasedev->migration);
        if (ret < 0) {
            return ret;
        }
    } while (!ret);
    qemu_put_be64(f, VFIO_MIG_FLAG_END_OF_STATE);

    ret = vfio_migration_set_state(vbasedev, VFIO_DEVICE_STATE_STOP,
                                   recover_state);
    if (ret) {
        /* FIXME: Probably have to reset the device */
        error_report("%s: Failed to set state STOP", vbasedev->name);
        return ret;
    }

    trace_vfio_save_complete_precopy(vbasedev->name);
    return 0;
}

static void vfio_save_state(QEMUFile *f, void *opaque)
{
    VFIODevice *vbasedev = opaque;
    int ret;

    ret = vfio_save_device_config_state(f, opaque);
    if (ret) {
        error_report("%s: Failed to save device config space",
                     vbasedev->name);
        qemu_file_set_error(f, ret);
    }
}

static int vfio_load_setup(QEMUFile *f, void *opaque)
{
    VFIODevice *vbasedev = opaque;
    int ret = 0;

    /* FIXME: Where do we leave resuming and how is that error handled?? */
    ret = vfio_migration_set_state(vbasedev, VFIO_DEVICE_STATE_RESUMING,
                                   vbasedev->migration->device_state);
    if (ret) {
        /* FIXME: This is likely a good place to do device reset */
        error_report("%s: Failed to set state RESUMING", vbasedev->name);
        return ret;
    }
    return 0;
}

static int vfio_load_cleanup(void *opaque)
{
    VFIODevice *vbasedev = opaque;

    vfio_migration_cleanup(vbasedev);
    trace_vfio_load_cleanup(vbasedev->name);
    return 0;
}

static int vfio_load_state(QEMUFile *f, void *opaque, int version_id)
{
    VFIODevice *vbasedev = opaque;
    int ret = 0;
    uint64_t data;

    data = qemu_get_be64(f);
    while (data != VFIO_MIG_FLAG_END_OF_STATE) {

        trace_vfio_load_state(vbasedev->name, data);

        switch (data) {
        case VFIO_MIG_FLAG_DEV_CONFIG_STATE:
        {
            return vfio_load_device_config_state(f, opaque);
        }
        case VFIO_MIG_FLAG_DEV_SETUP_STATE:
        {
            data = qemu_get_be64(f);
            if (data != VFIO_MIG_FLAG_END_OF_STATE) {
                error_report("%s: SETUP STATE: EOS not found 0x%"PRIx64,
                             vbasedev->name, data);
                return -EINVAL;
            }
            return 0;
        }
        case VFIO_MIG_FLAG_DEV_DATA_STATE:
        {
            uint64_t data_size = qemu_get_be64(f);

            if (data_size) {
                ret = vfio_load_buffer(f, vbasedev, data_size);
                if (ret < 0) {
                    return ret;
                }
            }
            break;
        }
        default:
            error_report("%s: Unknown tag 0x%"PRIx64, vbasedev->name, data);
            return -EINVAL;
        }

        data = qemu_get_be64(f);
        ret = qemu_file_get_error(f);
        if (ret) {
            return ret;
        }
    }
    return ret;
}

static const SaveVMHandlers savevm_vfio_precopy_handlers = {
    .save_setup = vfio_save_precopy_setup,
    .save_cleanup = vfio_save_cleanup,
    .save_live_pending = vfio_save_precopy_pending,
    .save_live_iterate = vfio_save_iterate,
    .save_live_complete_precopy = vfio_save_complete_precopy,
    .save_state = vfio_save_state,
    .load_setup = vfio_load_setup,
    .load_cleanup = vfio_load_cleanup,
    .load_state = vfio_load_state,
};

static const SaveVMHandlers savevm_vfio_handlers = {
    .save_setup = vfio_save_setup,
    .save_cleanup = vfio_save_cleanup,
    .save_live_complete_precopy = vfio_save_complete_precopy,
    .save_state = vfio_save_state,
    .load_setup = vfio_load_setup,
    .load_cleanup = vfio_load_cleanup,
    .load_state = vfio_load_state,
};

/* ---------------------------------------------------------------------- */

static void vfio_vmstate_change(void *opaque, bool running, RunState state)
{
    VFIODevice *vbasedev = opaque;
    VFIOMigration *migration = vbasedev->migration;
    enum vfio_device_mig_state orig_state = migration->device_state;
    enum vfio_device_mig_state new_state;
    int ret;

    if (running) {
        new_state = VFIO_DEVICE_STATE_RUNNING;
    } else {
        if (migration->device_state == VFIO_DEVICE_STATE_PRE_COPY &&
            state == RUN_STATE_FINISH_MIGRATE) {
            new_state = VFIO_DEVICE_STATE_STOP_COPY;
        } else {
            new_state = VFIO_DEVICE_STATE_STOP;
        }
    }

    ret =
        vfio_migration_set_state(vbasedev, new_state, VFIO_DEVICE_STATE_ERROR);
    if (ret) {
        /*
         * Migration should be aborted in this case, but vm_state_notify()
         * currently does not support reporting failures.
         */
        error_report("%s: Failed to set device state %u -> %u", vbasedev->name,
                     orig_state, new_state);
        qemu_file_set_error(migrate_get_current()->to_dst_file, ret);
    }
    trace_vfio_vmstate_change(vbasedev->name, running, RunState_str(state),
                              new_state);
}

static void vfio_migration_state_notifier(Notifier *notifier, void *data)
{
    MigrationState *s = data;
    VFIOMigration *migration = container_of(notifier, VFIOMigration,
                                            migration_state);
    VFIODevice *vbasedev = migration->vbasedev;
    int ret;

    trace_vfio_migration_state_notifier(vbasedev->name,
                                        MigrationStatus_str(s->state));

    switch (s->state) {
    case MIGRATION_STATUS_CANCELLING:
    case MIGRATION_STATUS_CANCELLED:
    case MIGRATION_STATUS_FAILED:
        bytes_transferred = 0;
        ret = vfio_migration_set_state(vbasedev, VFIO_DEVICE_STATE_RUNNING,
                                       VFIO_DEVICE_STATE_ERROR);
        if (ret) {
            error_report("%s: Failed to set state RUNNING", vbasedev->name);
        }
    }
}

static void vfio_migration_exit(VFIODevice *vbasedev)
{
    g_free(vbasedev->migration->data_buffer);
    g_free(vbasedev->migration);
    vbasedev->migration = NULL;
}

static int vfio_migration_query_flags(VFIODevice *vbasedev, uint64_t *mig_flags)
{
    uint64_t buf[DIV_ROUND_UP(sizeof(struct vfio_device_feature) +
                                  sizeof(struct vfio_device_feature_migration),
                              sizeof(uint64_t))] = {};
    struct vfio_device_feature *feature = (void *)buf;
    struct vfio_device_feature_migration *mig = (void *)feature->data;

    feature->argsz = sizeof(buf);
    feature->flags = VFIO_DEVICE_FEATURE_GET | VFIO_DEVICE_FEATURE_MIGRATION;
    if (ioctl(vbasedev->fd, VFIO_DEVICE_FEATURE, feature) != 0) {
        return -EOPNOTSUPP;
    }

    /* Basic migration functionality must be supported */
    if (!(mig->flags & VFIO_MIGRATION_STOP_COPY)) {
        return -EOPNOTSUPP;
    }
    *mig_flags = mig->flags;
    return 0;
}

static int vfio_migration_init(VFIODevice *vbasedev)
{
    Object *obj;
    VFIOMigration *migration;
    char id[256] = "";
    g_autofree char *path = NULL, *oid = NULL;
    uint64_t mig_flags;
    int ret;

    if (!vbasedev->ops->vfio_get_object) {
        return -EINVAL;
    }

    ret = vfio_migration_query_flags(vbasedev, &mig_flags);
    if (ret) {
        return ret;
    }

    obj = vbasedev->ops->vfio_get_object(vbasedev);
    if (!obj) {
        return -EINVAL;
    }

    vbasedev->migration = g_new0(VFIOMigration, 1);
    vbasedev->migration->data_buffer_size = 1024 * 1024;
    vbasedev->migration->data_buffer =
        g_malloc0(vbasedev->migration->data_buffer_size);
    migration = vbasedev->migration;
    migration->vbasedev = vbasedev;
    migration->data_fd = -1;

    oid = vmstate_if_get_id(VMSTATE_IF(DEVICE(obj)));
    if (oid) {
        path = g_strdup_printf("%s/vfio", oid);
    } else {
        path = g_strdup("vfio");
    }

    strpadcpy(id, sizeof(id), path, '\0');
    if (mig_flags & VFIO_MIGRATION_PRE_COPY) {
        register_savevm_live(id, VMSTATE_INSTANCE_ID_ANY, 1,
                             &savevm_vfio_precopy_handlers, vbasedev);
    } else {
        register_savevm_live(id, VMSTATE_INSTANCE_ID_ANY, 1,
                             &savevm_vfio_handlers, vbasedev);
    }
    migration->vm_state = qdev_add_vm_change_state_handler(vbasedev->dev,
                                                           vfio_vmstate_change,
                                                           vbasedev);
    migration->migration_state.notify = vfio_migration_state_notifier;
    add_migration_state_change_notifier(&migration->migration_state);
    return 0;
}

/* ---------------------------------------------------------------------- */

int64_t vfio_mig_bytes_transferred(void)
{
    return bytes_transferred;
}

int vfio_migration_probe(VFIODevice *vbasedev, Error **errp)
{
    VFIOContainer *container = vbasedev->group->container;
    int ret = -ENOTSUP;

    if (!vbasedev->enable_migration || !container->dirty_pages_supported) {
        goto add_blocker;
    }

    ret = vfio_migration_init(vbasedev);
    if (ret) {
        goto add_blocker;
    }

    trace_vfio_migration_probe(vbasedev->name);
    return 0;

add_blocker:
    error_setg(&vbasedev->migration_blocker,
               "VFIO device doesn't support migration");

    ret = migrate_add_blocker(vbasedev->migration_blocker, errp);
    if (ret < 0) {
        error_free(vbasedev->migration_blocker);
        vbasedev->migration_blocker = NULL;
    }
    return ret;
}

void vfio_migration_finalize(VFIODevice *vbasedev)
{
    if (vbasedev->migration) {
        VFIOMigration *migration = vbasedev->migration;

        remove_migration_state_change_notifier(&migration->migration_state);
        qemu_del_vm_change_state_handler(migration->vm_state);
        unregister_savevm(VMSTATE_IF(vbasedev->dev), "vfio", vbasedev);
        vfio_migration_exit(vbasedev);
    }

    if (vbasedev->migration_blocker) {
        migrate_del_blocker(vbasedev->migration_blocker);
        error_free(vbasedev->migration_blocker);
        vbasedev->migration_blocker = NULL;
    }
}
