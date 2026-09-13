#!/usr/bin/env bash
# Self-tests for 002-run-drtm-efi.sh using a fake QEMU process.
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
runner=$script_dir/002-run-drtm-efi.sh
test_root=$script_dir/results/runner-tests
mkdir -p -- "$test_root"
test_dir=$(mktemp -d -- "$test_root/test.XXXXXXXX")
echo "Runner self-test artifacts: $test_dir"

spaced_dir=$test_dir/'path with spaces'
mkdir -p -- "$spaced_dir"
fake_qemu=$spaced_dir/'fake qemu'
fake_efi=$spaced_dir/'fake app.efi'
fake_code=$spaced_dir/'fake code.fd'
fake_swtpm=$spaced_dir/'fake swtpm'
cp -- /bin/true "$fake_efi"
cp -- /bin/true "$fake_code"

cat >"$fake_qemu" <<'EOF'
#!/usr/bin/env bash
set -u
if [[ ${1-} == -machine && ${2-} == virt,help ]]; then
    if [[ ${FAKE_PROPERTY:-1} == 1 ]]; then
        echo '  x-drtm=<bool>'
    fi
    exit 0
fi
if [[ -n ${FAKE_QEMU_PID:-} ]]; then
    printf '%s\n' "$$" >"$FAKE_QEMU_PID"
fi

case ${FAKE_MODE:-pass} in
    pass)
        printf '\033[32m     Total Tests run  =    3  Tests Passed  =    3  Tests Failed =    0\033[0m\r\n'
        printf '      *** DRTM tests complete. ***\r\n'
        ;;
    acs-fail)
        echo '     Total Tests run  =    3  Tests Passed  =    2  Tests Failed =    1'
        echo '      *** DRTM tests complete. ***'
        ;;
    no-marker)
        echo '     Total Tests run  =    3  Tests Passed  =    3  Tests Failed =    0'
        ;;
    empty-summary)
        echo '      *** DRTM tests complete. ***'
        ;;
    zero-total)
        echo '     Total Tests run  =    0  Tests Passed  =    0  Tests Failed =    0'
        echo '      *** DRTM tests complete. ***'
        ;;
    qemu-fail)
        exit 7
        ;;
    timeout)
        exec sleep "${FAKE_SLEEP:-2}"
        ;;
    *)
        exit 99
        ;;
esac
EOF
chmod +x "$fake_qemu"

cat >"$fake_swtpm" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
ctrl=
printf '%s\n' "$@" >"$FAKE_SWTPM_ARGS"
if [[ -n ${FAKE_SWTPM_PID:-} ]]; then
    printf '%s\n' "$$" >"$FAKE_SWTPM_PID"
fi
for arg in "$@"; do
    case $arg in
        type=unixio,path=*) ctrl=${arg#type=unixio,path=} ;;
    esac
done
[[ -n $ctrl ]]
if [[ ${FAKE_SWTPM_MODE:-stay} == fail-before-socket ]]; then
    exit 7
fi
: >"$ctrl"
trap 'exit 0' TERM
while :; do
    sleep 1
done
EOF
chmod +x "$fake_swtpm"

fake_tpm_socket=$spaced_dir/'fake swtpm.sock'

common=(
    "QEMU_BIN=$fake_qemu"
    "DRTM_EFI=$fake_efi"
    "DRTM_UEFI_CODE=$fake_code"
    "DRTM_RUN_ROOT=$test_dir/runs"
    "DRTM_SWTPM_SOCKET=$fake_tpm_socket"
    DRTM_TIMEOUT=5
)

expect_success()
{
    local name=$1
    shift
    if ! env "${common[@]}" "$@" >"$test_dir/$name.out" 2>&1; then
        echo "FAIL: $name unexpectedly failed" >&2
        sed -n '1,120p' "$test_dir/$name.out" >&2
        exit 1
    fi
}

expect_failure()
{
    local name=$1
    shift
    if env "${common[@]}" "$@" >"$test_dir/$name.out" 2>&1; then
        echo "FAIL: $name unexpectedly passed" >&2
        exit 1
    fi
}

expect_success pass FAKE_MODE=pass "DRTM_LOG=$test_dir/pass.log" "$runner" -t 1,2,3
grep -Fq 'Running:' "$test_dir/pass.log"
grep -Fq 'Tests Failed =    0' "$test_dir/pass.log"
if ! grep -Fq -- '-tpmdev' "$test_dir/pass.log"; then
    echo 'FAIL: DRTM workflow did not configure its required TPM' >&2
    exit 1
fi
if LC_ALL=C grep -q $'\033\|\r' "$test_dir/pass.log"; then
    echo 'FAIL: cleaned log retains ANSI or CR characters' >&2
    exit 1
fi

expect_success positional-efi FAKE_MODE=pass DRTM_EFI=/does/not/exist \
    "DRTM_LOG=$test_dir/positional-efi.log" "$runner" "$fake_efi" -t 1,2,3

if ! env "QEMU_BIN=$fake_qemu" "DRTM_UEFI_CODE=$fake_code" \
        "DRTM_RUN_ROOT=$test_dir/runs" \
        "DRTM_SWTPM_SOCKET=$fake_tpm_socket" DRTM_TIMEOUT=5 \
        "DRTM_LOG=$test_dir/default-efi.log" FAKE_MODE=pass \
        "$runner" >"$test_dir/default-efi.out" 2>&1; then
    echo 'FAIL: repository-default Drtm.efi run unexpectedly failed' >&2
    exit 1
fi
default_run=$(sed -n 's/^DRTM run directory: //p' \
    "$test_dir/default-efi.out" | tail -n 1)
cmp -- "$script_dir/Drtm.efi" "$default_run/media/Drtm.efi"

expect_failure acs-fail FAKE_MODE=acs-fail "DRTM_LOG=$test_dir/fail.log" "$runner"
grep -Fq 'reports 1 failed test' "$test_dir/acs-fail.out"

expect_failure no-marker FAKE_MODE=no-marker "DRTM_LOG=$test_dir/no-marker.log" "$runner"
grep -Fq 'completion marker missing' "$test_dir/no-marker.out"

expect_failure empty-summary FAKE_MODE=empty-summary \
    "DRTM_LOG=$test_dir/empty-summary.log" "$runner"
grep -Fq 'summary is missing or empty' "$test_dir/empty-summary.out"

expect_failure zero-total FAKE_MODE=zero-total \
    "DRTM_LOG=$test_dir/zero-total.log" "$runner"
grep -Fq 'summary is missing or empty' "$test_dir/zero-total.out"

expect_success external-tpm FAKE_MODE=pass \
    "DRTM_LOG=$test_dir/external-tpm.log" "$runner"
grep -Fq -- '-chardev socket\,id=drtm_tpm_chr\,path=' \
    "$test_dir/external-tpm.log"

expect_success automatic-tpm FAKE_MODE=pass DRTM_SWTPM_SOCKET= \
    "DRTM_SWTPM_BIN=$fake_swtpm" \
    "FAKE_SWTPM_ARGS=$test_dir/automatic-swtpm.args" \
    "DRTM_LOG=$test_dir/automatic-tpm.log" "$runner"
grep -Fxq -- '--tpm2' "$test_dir/automatic-swtpm.args"
grep -Fq -- '-device tpm-tis-device' "$test_dir/automatic-tpm.log"
auto_socket=$(sed -n 's/^type=unixio,path=//p' "$test_dir/automatic-swtpm.args")
case $auto_socket in
    "$test_dir"/runs/*/swtpm/control.sock) ;;
    *) echo "FAIL: automatic swtpm socket escaped run root: $auto_socket" >&2; exit 1 ;;
esac

expect_success strict-hw FAKE_MODE=pass DRTM_STRICT_HW=1 \
    "DRTM_LOG=$test_dir/strict-hw.log" "$runner"
grep -Fq 'iommu=smmuv3' "$test_dir/strict-hw.log"
grep -Fq 'iommu_platform=on' "$test_dir/strict-hw.log"

expect_failure no-property FAKE_PROPERTY=0 FAKE_MODE=pass \
    "DRTM_LOG=$test_dir/no-property.log" "$runner"
grep -Fq 'does not expose a drtm or x-drtm' "$test_dir/no-property.out"

expect_failure outside-run-root \
    "DRTM_RUN_ROOT=$script_dir/../../drtm-runner-outside" "$runner"
grep -Fq 'DRTM_RUN_ROOT must stay inside the repository' \
    "$test_dir/outside-run-root.out"

expect_failure outside-swtpm-socket \
    "DRTM_SWTPM_SOCKET=$script_dir/../../outside-swtpm/control.sock" "$runner"
grep -Fq 'DRTM_SWTPM_SOCKET must stay inside the repository' \
    "$test_dir/outside-swtpm-socket.out"
outside_socket_run=$(sed -n 's/^DRTM run artifacts preserved at: //p' \
    "$test_dir/outside-swtpm-socket.out" | tail -n 1)
if [[ -z $outside_socket_run || ! -d $outside_socket_run ]]; then
    echo 'FAIL: outside socket rejection did not preserve/report artifacts' >&2
    exit 1
fi

expect_success explicit-baseline FAKE_PROPERTY=0 FAKE_MODE=pass DRTM_ENABLE=0 \
    DRTM_SWTPM_SOCKET= DRTM_SWTPM_MODE=off \
    "DRTM_LOG=$test_dir/baseline.log" "$runner"

expect_failure qemu-fail FAKE_MODE=qemu-fail \
    "DRTM_LOG=$test_dir/qemu-fail.log" "$runner"
grep -Fq 'status 7' "$test_dir/qemu-fail.out"

expect_failure timeout FAKE_MODE=timeout DRTM_TIMEOUT=1 \
    "DRTM_LOG=$test_dir/timeout.log" "$runner"
grep -Fq 'status 124' "$test_dir/timeout.out"

failed_swtpm_pid_file=$test_dir/failed-swtpm.pid
expect_failure failed-auto-swtpm FAKE_MODE=timeout DRTM_SWTPM_SOCKET= \
    "DRTM_SWTPM_BIN=$fake_swtpm" \
    "FAKE_SWTPM_ARGS=$test_dir/failed-swtpm.args" \
    "FAKE_SWTPM_PID=$failed_swtpm_pid_file" \
    FAKE_SWTPM_MODE=fail-before-socket "$runner"
grep -Fq 'swtpm exited before creating its socket' \
    "$test_dir/failed-auto-swtpm.out"
failed_swtpm_run=$(sed -n 's/^DRTM run artifacts preserved at: //p' \
    "$test_dir/failed-auto-swtpm.out" | tail -n 1)
if [[ -z $failed_swtpm_run || ! -d $failed_swtpm_run ]]; then
    echo 'FAIL: failed automatic swtpm did not preserve/report artifacts' >&2
    exit 1
fi
failed_swtpm_pid=$(<"$failed_swtpm_pid_file")
if kill -0 "$failed_swtpm_pid" 2>/dev/null; then
    echo "FAIL: failed automatic swtpm $failed_swtpm_pid survived" >&2
    exit 1
fi

# Stop the runner before killing QEMU, making QEMU a zombie which cannot be
# reaped yet while the automatically-started swtpm remains demonstrably live.
# Cleanup must tolerate that dead first child and still stop/reap its live peer.
dead_qemu_pid_file=$test_dir/dead-qemu.pid
peer_swtpm_pid_file=$test_dir/peer-swtpm.pid
dead_child_runner_pid=
dead_qemu_pid=
peer_swtpm_pid=
dead_child_fixture_fail()
{
    local message=$1
    local fixture_pid

    echo "FAIL: $message" >&2
    set +e
    if [[ -n $dead_child_runner_pid ]]; then
        kill -TERM "$dead_child_runner_pid" 2>/dev/null
        kill -CONT "$dead_child_runner_pid" 2>/dev/null
        wait "$dead_child_runner_pid" 2>/dev/null
    fi
    for fixture_pid in "$dead_qemu_pid" "$peer_swtpm_pid"; do
        if [[ -n $fixture_pid ]] && kill -0 "$fixture_pid" 2>/dev/null; then
            kill -TERM "$fixture_pid" 2>/dev/null
            for (( attempt = 0; attempt < 100; attempt++ )); do
                kill -0 "$fixture_pid" 2>/dev/null || break
                sleep 0.01
            done
            kill -KILL "$fixture_pid" 2>/dev/null
        fi
    done
    exit 1
}
env "${common[@]}" FAKE_MODE=timeout FAKE_SLEEP=30 DRTM_TIMEOUT=0 \
    DRTM_SWTPM_SOCKET= "DRTM_SWTPM_BIN=$fake_swtpm" \
    "FAKE_SWTPM_ARGS=$test_dir/peer-swtpm.args" \
    "FAKE_SWTPM_PID=$peer_swtpm_pid_file" \
    "FAKE_QEMU_PID=$dead_qemu_pid_file" "$runner" \
    >"$test_dir/dead-child.out" 2>&1 &
dead_child_runner_pid=$!
for (( attempt = 0; attempt < 200; attempt++ )); do
    [[ -s $dead_qemu_pid_file && -s $peer_swtpm_pid_file ]] && break
    kill -0 "$dead_child_runner_pid" 2>/dev/null || break
    sleep 0.01
done
if [[ ! -s $dead_qemu_pid_file || ! -s $peer_swtpm_pid_file ]]; then
    dead_child_fixture_fail 'dead-child setup did not start both children'
fi
dead_qemu_pid=$(<"$dead_qemu_pid_file")
peer_swtpm_pid=$(<"$peer_swtpm_pid_file")
kill -STOP "$dead_child_runner_pid"
dead_child_runner_state=
for (( attempt = 0; attempt < 200; attempt++ )); do
    if [[ -r /proc/$dead_child_runner_pid/stat ]]; then
        read -r _ _ dead_child_runner_state _ \
            <"/proc/$dead_child_runner_pid/stat"
    else
        dead_child_runner_state=gone
    fi
    [[ $dead_child_runner_state == T ]] && break
    sleep 0.01
done
if [[ $dead_child_runner_state != T ]]; then
    dead_child_fixture_fail \
        "runner did not stop before QEMU termination (state $dead_child_runner_state)"
fi
kill -TERM "$dead_qemu_pid"
dead_qemu_state=
for (( attempt = 0; attempt < 200; attempt++ )); do
    if [[ -r /proc/$dead_qemu_pid/stat ]]; then
        read -r _ _ dead_qemu_state _ <"/proc/$dead_qemu_pid/stat"
    else
        dead_qemu_state=gone
    fi
    [[ $dead_qemu_state == Z ]] && break
    sleep 0.01
done
if [[ $dead_qemu_state != Z ]]; then
    dead_child_fixture_fail \
        "QEMU was not dead before cleanup (state $dead_qemu_state)"
fi
if ! kill -0 "$peer_swtpm_pid" 2>/dev/null; then
    dead_child_fixture_fail 'swtpm peer was not live before cleanup'
fi
kill -TERM "$dead_child_runner_pid"
kill -CONT "$dead_child_runner_pid"
set +e
wait "$dead_child_runner_pid"
dead_child_status=$?
set -e
if (( dead_child_status != 143 )); then
    dead_child_fixture_fail \
        "dead-child cleanup returned $dead_child_status, expected 143"
fi
for peer_pid in "$dead_qemu_pid" "$peer_swtpm_pid"; do
    if kill -0 "$peer_pid" 2>/dev/null; then
        dead_child_fixture_fail \
            "dead-child cleanup left peer $peer_pid running"
    fi
done
dead_child_run=$(sed -n 's/^DRTM run artifacts preserved at: //p' \
    "$test_dir/dead-child.out" | tail -n 1)
if [[ -z $dead_child_run || ! -d $dead_child_run ]]; then
    dead_child_fixture_fail \
        'dead-child cleanup did not preserve/report artifacts'
fi

expect_signal_preservation()
{
    local signal=$1
    local expected=$2
    local signal_name=${signal,,}

    local fake_pid_file=$test_dir/$signal_name-qemu.pid
    set +e
    timeout --foreground --preserve-status --signal="$signal" 0.2 \
        env "${common[@]}" FAKE_MODE=timeout DRTM_TIMEOUT=0 \
        "FAKE_QEMU_PID=$fake_pid_file" \
        "DRTM_LOG=$test_dir/$signal_name.log" "$runner" \
        >"$test_dir/$signal_name.out" 2>&1
    local signal_status=$?
    set -e
    if [[ ! -s $fake_pid_file ]]; then
        echo "FAIL: $signal runner did not start fake QEMU" >&2
        exit 1
    fi
    if (( signal_status != expected )); then
        echo "FAIL: $signal returned $signal_status, expected $expected" >&2
        exit 1
    fi
    local fake_pid
    fake_pid=$(<"$fake_pid_file")
    if kill -0 "$fake_pid" 2>/dev/null; then
        echo "FAIL: $signal left fake QEMU $fake_pid running" >&2
        exit 1
    fi
    local preserved_run
    preserved_run=$(sed -n 's/^DRTM run directory: //p' \
        "$test_dir/$signal_name.out" | tail -n 1)
    if [[ -z $preserved_run || ! -d $preserved_run || \
          ! -f $preserved_run/console.raw ]]; then
        echo "FAIL: $signal did not preserve its run artifacts" >&2
        exit 1
    fi
}

expect_signal_preservation HUP 129
expect_signal_preservation INT 130
expect_signal_preservation TERM 143

if ! compgen -G "$test_dir/runs/run.*" >/dev/null; then
    echo 'FAIL: runner did not retain any run directories' >&2
    exit 1
fi

echo "DRTM runner self-tests passed; artifacts preserved at $test_dir"
