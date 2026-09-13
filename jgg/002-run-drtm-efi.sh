#!/usr/bin/env bash
# Boot the sysarch-acs Drtm.efi application in the QEMU build in this tree.
set -euo pipefail

usage()
{
    cat <<'EOF'
Usage: jgg/002-run-drtm-efi.sh [Drtm.efi] [Drtm.efi arguments ...]

Environment:
  QEMU_BIN          qemu-system-aarch64 executable
  DRTM_EFI          Drtm.efi input file
  DRTM_UEFI_CODE    EDK2 AArch64 code image with the internal shell
  DRTM_TIMEOUT      timeout in seconds; 0 disables it (default: 300)
  DRTM_CPUS         virtual CPU count (default: 4)
  DRTM_MEMORY       guest memory size (default: 2G)
  DRTM_ENABLE       0 omits the QEMU DRTM property (default: 1)
  DRTM_REQUIRE_QEMU_SUPPORT
                    0 permits fallback when QEMU has no property (default: 1)
  DRTM_RUN_ROOT     persistent run directory root (default: jgg/results/runs)
  DRTM_SWTPM_SOCKET socket of an already-running TPM2 swtpm, resolved to a
                    path inside this repository; when unset, the runner
                    starts swtpm inside the run directory
  DRTM_SWTPM_BIN    swtpm executable used for automatic startup
  DRTM_SWTPM_MODE   auto starts swtpm, off disables automatic startup
                    (default: auto); an explicit socket takes precedence
  DRTM_STRICT_HW    1 adds the optional SMMUv3-oriented topology (default: 0)
  DRTM_LOG          cleaned console log (default: RUN-DIR/console.log)

If the first argument does not begin with '-', it selects the Drtm.efi image.
The remaining command-line arguments are passed to the application. Examples:
  jgg/002-run-drtm-efi.sh
  jgg/002-run-drtm-efi.sh -v 3 -t 1

Every invocation creates and preserves a unique directory containing the EFI
media, console logs, QEMU scratch files, and any automatically-created TPM
state.  The path is printed before QEMU starts and again on exit.
EOF
}

die()
{
    echo "error: $*" >&2
    exit 1
}

if [[ ${1-} == --help ]]; then
    usage
    exit 0
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_dir=$(cd -- "$script_dir/.." && pwd)

qemu_bin=${QEMU_BIN:-"$repo_dir/build-arm/qemu-system-aarch64"}
if (( $# > 0 )) && [[ $1 != -* ]]; then
    drtm_efi=$1
    shift
else
    drtm_efi=${DRTM_EFI:-"$script_dir/Drtm.efi"}
fi
uefi_code=${DRTM_UEFI_CODE:-"$repo_dir/build-arm/pc-bios/edk2-aarch64-code.fd"}
run_timeout=${DRTM_TIMEOUT:-300}
cpu_count=${DRTM_CPUS:-4}
memory_size=${DRTM_MEMORY:-2G}
enable_drtm=${DRTM_ENABLE:-1}
require_drtm=${DRTM_REQUIRE_QEMU_SUPPORT:-1}
strict_hw=${DRTM_STRICT_HW:-0}
run_root=${DRTM_RUN_ROOT:-"$script_dir/results/runs"}
swtpm_mode=${DRTM_SWTPM_MODE:-auto}

[[ -x $qemu_bin ]] || die "QEMU executable not found: $qemu_bin"
[[ -f $drtm_efi ]] || die "Drtm.efi not found: $drtm_efi"
[[ -f $uefi_code ]] || die "UEFI code image not found: $uefi_code"
[[ $run_timeout =~ ^[0-9]+$ ]] || die "DRTM_TIMEOUT must be a non-negative integer"
[[ $cpu_count =~ ^[1-9][0-9]*$ ]] || die "DRTM_CPUS must be a positive integer"
[[ $enable_drtm == 0 || $enable_drtm == 1 ]] || die "DRTM_ENABLE must be 0 or 1"
[[ $require_drtm == 0 || $require_drtm == 1 ]] || \
    die "DRTM_REQUIRE_QEMU_SUPPORT must be 0 or 1"
[[ $strict_hw == 0 || $strict_hw == 1 ]] || die "DRTM_STRICT_HW must be 0 or 1"
[[ $swtpm_mode == auto || $swtpm_mode == off ]] || \
    die "DRTM_SWTPM_MODE must be auto or off"
if [[ $strict_hw == 1 && $enable_drtm == 0 ]]; then
    die "DRTM_STRICT_HW=1 requires DRTM_ENABLE=1"
fi
if [[ $enable_drtm == 1 && $swtpm_mode == off && \
      -z ${DRTM_SWTPM_SOCKET:-} ]]; then
    die "DRTM_ENABLE=1 requires a TPM; use automatic swtpm or DRTM_SWTPM_SOCKET"
fi

run_root=$(realpath -m -- "$run_root") || die "could not resolve DRTM_RUN_ROOT"
case $run_root in
    "$repo_dir"|"$repo_dir"/*) ;;
    *) die "DRTM_RUN_ROOT must stay inside the repository: $repo_dir" ;;
esac
mkdir -p -- "$run_root"
run_dir=$(mktemp -d -- "$run_root/run.XXXXXXXX")
qemu_tmp_dir=$run_dir/qemu-tmp
media_dir=$run_dir/media
swtpm_pid=
qemu_pid=
terminate_child()
{
    local pid=$1

    if ! kill -0 "$pid" 2>/dev/null; then
        wait "$pid" 2>/dev/null || true
        return
    fi
    kill "$pid" 2>/dev/null || true
    for (( attempt = 0; attempt < 100; attempt++ )); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.01
    done
    if kill -0 "$pid" 2>/dev/null; then
        kill -KILL "$pid" 2>/dev/null || true
    fi
    wait "$pid" 2>/dev/null || true
}
cleanup()
{
    local status=$?

    # EXIT traps inherit errexit.  Cleanup is deliberately best-effort so a
    # child which has already exited cannot prevent the other child from being
    # stopped and reaped, or suppress the artifact location.
    set +e
    trap '' HUP INT TERM
    if [[ -n $qemu_pid ]]; then
        terminate_child "$qemu_pid"
    fi
    if [[ -n $swtpm_pid ]]; then
        terminate_child "$swtpm_pid"
    fi
    echo "DRTM run artifacts preserved at: $run_dir" >&2
    return "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -- "$qemu_tmp_dir" "$media_dir"
log_path=${DRTM_LOG:-"$run_dir/console.log"}
log_path=$(realpath -m -- "$log_path") || die "could not resolve DRTM_LOG"
case $log_path in
    "$repo_dir"/*) ;;
    *) die "DRTM_LOG must stay inside the repository: $repo_dir" ;;
esac
echo "DRTM run directory: $run_dir"

machine=virt,virtualization=on,gic-version=3
disk_device=virtio-blk-pci,drive=drtm_disk
if [[ $strict_hw == 1 ]]; then
    machine+=,iommu=smmuv3,default-bus-bypass-iommu=off
    machine+=,virtio-mmio-transports=0
    disk_device=virtio-blk-pci-non-transitional,drive=drtm_disk,iommu_platform=on
fi

if [[ $enable_drtm == 1 ]]; then
    machine_help=$("$qemu_bin" -machine virt,help 2>&1 || true)
    if grep -Eq '(^|[[:space:]])x-drtm=<bool>' <<<"$machine_help"; then
        machine+=,x-drtm=on
    elif grep -Eq '(^|[[:space:]])drtm=<bool>' <<<"$machine_help"; then
        machine+=,drtm=on
    elif [[ $require_drtm == 1 ]]; then
        die "this QEMU does not expose a drtm or x-drtm virt-machine property"
    else
        echo "warning: this QEMU has no DRTM property; running a baseline boot" >&2
    fi
fi

cp -- "$drtm_efi" "$media_dir/Drtm.efi"

efi_command=Drtm.efi
for arg in "$@"; do
    case $arg in
        *$'\r'*|*$'\n'*|*'"'*)
            die "Drtm.efi arguments may not contain quotes or newlines"
            ;;
    esac
    efi_command+=" \"$arg\""
done

# The bundled EDK2 image contains the shell. It automatically runs startup.nsh
# from the first filesystem it discovers.
printf 'echo -off\r\nfs0:\r\n%s\r\nreset -s\r\n' "$efi_command" \
    >"$media_dir/startup.nsh"

qemu_args=(
    -machine "$machine"
    -accel tcg
    -cpu max
    -smp "$cpu_count"
    -m "$memory_size"
    -nodefaults
    -display none
    -monitor none
    -serial stdio
    -no-reboot
    -net none
    -drive "if=pflash,format=raw,readonly=on,file=$uefi_code"
    -drive "if=none,id=drtm_disk,format=raw,file=fat:rw:$media_dir"
    -device "$disk_device"
)

if [[ -n ${DRTM_SWTPM_SOCKET:-} ]]; then
    swtpm_socket=$(realpath -m -- "$DRTM_SWTPM_SOCKET") || \
        die "could not resolve DRTM_SWTPM_SOCKET"
    case $swtpm_socket in
        "$repo_dir"/*) ;;
        *) die "DRTM_SWTPM_SOCKET must stay inside the repository: $repo_dir" ;;
    esac
elif [[ $swtpm_mode == auto ]]; then
    swtpm_bin=${DRTM_SWTPM_BIN:-swtpm}
    command -v "$swtpm_bin" >/dev/null || \
        die "swtpm not found; set DRTM_SWTPM_BIN or DRTM_SWTPM_SOCKET"
    swtpm_dir=$run_dir/swtpm
    swtpm_socket=$swtpm_dir/control.sock
    mkdir -- "$swtpm_dir" "$swtpm_dir/state"
    env "TMPDIR=$swtpm_dir" "$swtpm_bin" socket --tpm2 \
        --tpmstate "dir=$swtpm_dir/state" \
        --ctrl "type=unixio,path=$swtpm_socket" \
        --flags not-need-init \
        --log "file=$swtpm_dir/swtpm.log,level=20" &
    swtpm_pid=$!
    for (( attempt = 0; attempt < 200; attempt++ )); do
        [[ -e $swtpm_socket ]] && break
        kill -0 "$swtpm_pid" 2>/dev/null || \
            die "swtpm exited before creating its socket"
        sleep 0.05
    done
    [[ -e $swtpm_socket ]] || die "swtpm did not create its socket"
fi

if [[ -n ${swtpm_socket:-} ]]; then
    qemu_args+=(
        -chardev "socket,id=drtm_tpm_chr,path=$swtpm_socket"
        -tpmdev emulator,id=drtm_tpm,chardev=drtm_tpm_chr
        -device tpm-tis-device,tpmdev=drtm_tpm
    )
fi

runner=()
if [[ $run_timeout != 0 ]]; then
    command -v timeout >/dev/null || die "timeout is required unless DRTM_TIMEOUT=0"
    runner=(timeout --foreground "$run_timeout")
fi

raw_log=$run_dir/console.raw
mkdir -p -- "$(dirname -- "$log_path")"

{
    printf 'Running:'
    printf ' %q' env "TMPDIR=$qemu_tmp_dir" "$qemu_bin" "${qemu_args[@]}"
    printf '\n'
} >"$raw_log"

set +e
"${runner[@]}" env "TMPDIR=$qemu_tmp_dir" \
    "$qemu_bin" "${qemu_args[@]}" >>"$raw_log" 2>&1 &
qemu_pid=$!
wait "$qemu_pid"
qemu_status=$?
qemu_pid=
set -e

tee <"$raw_log"

# Preserve a readable artifact and parse it because Drtm.efi returns EFI
# success even when its internal tests fail.
if ! LC_ALL=C sed -E $'s/\033\\[[0-?]*[ -\\/]*[@-~]//g; s/\r$//' \
        "$raw_log" >"$log_path"; then
    die "could not write cleaned console log: $log_path"
fi

test_total=$(sed -nE \
    's/.*Total Tests run[[:space:]]*=[[:space:]]*([0-9]+).*/\1/p' \
    "$log_path" | tail -n 1)
test_failed=$(sed -nE \
    's/.*Tests Failed[[:space:]]*=[[:space:]]*([0-9]+).*/\1/p' \
    "$log_path" | tail -n 1)

if (( qemu_status != 0 )); then
    die "QEMU/timeout exited with status $qemu_status; log preserved at $log_path"
fi
if ! grep -Fq '*** DRTM tests complete. ***' "$log_path"; then
    die "Drtm.efi completion marker missing; log preserved at $log_path"
fi
if [[ -z $test_total || $test_total == 0 || -z $test_failed ]]; then
    die "Drtm.efi summary is missing or empty; log preserved at $log_path"
fi
if [[ $test_failed != 0 ]]; then
    die "Drtm.efi reports $test_failed failed test(s); log preserved at $log_path"
fi

echo "Drtm.efi passed $test_total test(s); log: $log_path"
