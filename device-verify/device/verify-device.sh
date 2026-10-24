#!/system/bin/sh
# 设备侧验证执行器（仅 root）。所有可写路径固定在 /data/local/tmp/nsp_verify 下。
# 由宿主 device-verify/host/run-verify.py 调用；不要手工执行未审阅的参数。
set -u

VR=/data/local/tmp/nsp_verify
CFG=$VR/config
BIN=$VR/bin
STAGE=$VR/staging
MODCFG=$CFG/modules/ftp_module
PROD_MOD=/data/adb/modules/Namespace-Proxy
DAEMONS="rule_server log_monitor injector fuse_daemon"

die() { echo "VERIFY-FATAL: $*" >&2; exit 1; }
log() { echo "VERIFY: $*"; }

need_root() { [ "$(id -u)" = 0 ] || die "需要 root 执行"; }

pid_of() { pidof "$1" 2>/dev/null; }

wait_gone() {
    _names=$1
    _timeout=$2
    _n=0
    while [ "$_n" -lt "$_timeout" ]; do
        _left=""
        for _p in $_names; do
            _pid=$(pid_of "$_p")
            [ -n "$_pid" ] && _left="$_left $_p:$_pid"
        done
        [ -z "$_left" ] && return 0
        sleep 1
        _n=$((_n + 1))
    done
    echo "$_left"
    return 1
}

stop_all() {
    _names=$1
    _label=$2
    for _p in $_names; do
        _pid=$(pid_of "$_p")
        if [ -n "$_pid" ]; then
            log "停止 $_label $_p ($_pid)"
            kill -TERM $_pid 2>/dev/null
        fi
    done
    if ! _left=$(wait_gone "$_names" 10); then
        log "强制结束 $_label 残留:$_left"
        for _p in $_names; do
            _pid=$(pid_of "$_p")
            [ -n "$_pid" ] && kill -9 $_pid 2>/dev/null
        done
        sleep 1
    fi
    for _p in $_names; do
        _pid=$(pid_of "$_p")
        [ -n "$_pid" ] && die "$_label $_p 仍在运行 ($_pid)"
    done
    return 0
}

case "${1:-}" in
preflight)
    need_root
    echo "api=$(getprop ro.build.version.sdk)"
    echo "boot=$(getprop sys.boot_completed)"
    echo "uid=$(id -u)"
    echo "selinux=$(getenforce 2>/dev/null || echo unknown)"
    [ -e /dev/fuse ] && echo "dev_fuse=1" || echo "dev_fuse=0"
    [ -f "$PROD_MOD/module.prop" ] && echo "module=1" || echo "module=0"
    [ -f "$PROD_MOD/zygisk/arm64-v8a.so" ] && echo "zygisk64=1" || echo "zygisk64=0"
    [ -f "$PROD_MOD/zygisk/armeabi-v7a.so" ] && echo "zygisk32=1" || echo "zygisk32=0"
    echo "prod_injector=$(pid_of injector)"
    echo "prod_fuse=$(pid_of fuse_daemon)"
    echo "prod_logmon=$(pid_of log_monitor)"
    echo "prod_rulesrv=$(pid_of rule_server)"
    [ -f "$PROD_MOD/service.sh" ] && echo "prod_service=1" || echo "prod_service=0"
    echo "prod_cfg_sha=$(sha256sum /data/Namespace-Proxy/injector.conf 2>/dev/null | cut -d' ' -f1)"
    ;;
prepare-dirs)
    need_root
    [ -L "$VR" ] && die "拒绝：$VR 是符号链接"
    mkdir -p "$VR" "$BIN" "$CFG/log" "$MODCFG" "$STAGE/bin" "$STAGE/modules/ftp_module" || die "mkdir 失败"
    chmod 755 "$VR"
    chmod 777 "$STAGE" "$STAGE/bin" "$STAGE/modules" "$STAGE/modules/ftp_module"
    chmod 700 "$CFG"
    echo "PREPARED_DIRS"
    ;;
prepare)
    need_root
    for _f in injector.conf modules/ftp_module/ftp_module.conf \
              modules/ftp_module/ftp_module.rules modules/ftp_module/ftp_module.so; do
        [ -f "$STAGE/$_f" ] || die "缺少 staging/$_f"
    done
    for _b in injector fuse_daemon log_monitor rule_server; do
        [ -f "$STAGE/bin/$_b" ] || die "缺少验证二进制 $_b"
        cp -f "$STAGE/bin/$_b" "$BIN/$_b" || die "复制 $_b 失败"
        chmod 755 "$BIN/$_b"
    done
    cp -f "$STAGE/modules/ftp_module/ftp_module.so" "$MODCFG/ftp_module.so" || die "复制模块 so 失败"
    cp -f "$STAGE/modules/ftp_module/ftp_module.rules" "$MODCFG/ftp_module.rules" || die "复制模块 rules 失败"
    cp -f "$STAGE/modules/ftp_module/ftp_module.conf" "$MODCFG/ftp_module.conf" || die "复制模块配置失败"
    chmod 755 "$MODCFG/ftp_module.so"
    cp -f "$STAGE/injector.conf" "$CFG/injector.conf" || die "复制 injector.conf 失败"
    chmod 600 "$CFG/injector.conf"
    if [ -f "$STAGE/id_rsa" ]; then
        cp -f "$STAGE/id_rsa" "$CFG/id_rsa" || die "复制私钥失败"
        chmod 600 "$CFG/id_rsa"
    fi
    if [ -f "$STAGE/id_rsa.pub" ]; then
        cp -f "$STAGE/id_rsa.pub" "$CFG/id_rsa.pub" || die "复制公钥失败"
        chmod 600 "$CFG/id_rsa.pub"
    fi
    if [ -f "$STAGE/known_hosts" ]; then
        cp -f "$STAGE/known_hosts" "$CFG/known_hosts" || die "复制 known_hosts 失败"
        chmod 600 "$CFG/known_hosts"
    fi
    echo "PREPARED"
    ;;
prepare-app-dirs)
    need_root
    [ -n "${2:-}" ] || die "用法: prepare-app-dirs <pkg>"
    _pkg=$2
    _uid=$(stat -c %u "/data/data/$_pkg" 2>/dev/null)
    [ -n "$_uid" ] || _uid=$(dumpsys package "$_pkg" 2>/dev/null | sed -n 's/.*userId=\([0-9][0-9]*\).*/\1/p' | head -1)
    [ -n "$_uid" ] || die "无法取得 $_pkg 的 uid"
    _base=/data/media/0/Android/data/$_pkg
    mkdir -p "$_base/files" || die "创建 $_base 失败"
    chown -R "$_uid:$_uid" "$_base" || die "chown $_base 失败"
    chmod 0771 "$_base"
    chmod 0770 "$_base/files"
    if command -v chcon >/dev/null 2>&1; then
        chcon -R u:object_r:media_rw_data_file:s0 "$_base" 2>/dev/null || true
    fi
    echo "APP_DIRS_READY $_pkg uid=$_uid"
    ;;
clean-fixtures)
    need_root
    case /data/media/0/nsp_verify in /data/media/0/*) ;; *) die "夹具路径异常" ;; esac
    rm -rf /data/media/0/nsp_verify /data/media/0/ftp_probe /data/media/0/sftp_probe
    rm -rf /data/media/0/nsp_race_b
    rm -f /data/media/0/Download/nsp_probe_sandbox.txt /data/media/0/Pictures/nsp_probe_sandbox.jpg
    rm -f /data/media/0/Download/nsp_race_a*.txt
    echo "FIXTURES_CLEANED"
    ;;
race-fixture)
    need_root
    [ -n "${2:-}" ] || die "用法: race-fixture <pkg>"
    _uid=$(stat -c %u "/data/data/$2" 2>/dev/null)
    [ -n "$_uid" ] || die "无法取得 $2 的 uid"
    _d=/data/media/0/nsp_race_b
    case "$_d" in /data/media/0/*) ;; *) die "夹具路径异常: $_d" ;; esac
    rm -rf "$_d" || die "清理旧竞态夹具失败"
    # 轮次之间必须清掉上一轮的落点文件，否则扫描结果跨轮累积（会把上一轮的
    # 就绪前泄漏算到本轮头上）。
    rm -f /data/media/0/Download/nsp_race_a*.txt
    rm -f "/data/media/0/Android/data/$2/sandbox/Download"/nsp_race_a*.txt
    mkdir -p "$_d" || die "创建竞态夹具目录失败"
    chown "$_uid:$_uid" "$_d" || die "chown 竞态夹具失败"
    chmod 0777 "$_d"
    echo "RACE_FIXTURE_READY uid=$_uid"
    ;;
race-scan)
    need_root
    _pkg=${2:-nsp.probe.race}
    _list_ids() {
        _out=$(ls "$1" 2>/dev/null | grep -E "^$2[0-9]+\.txt\$" | sed -E "s/^$2//; s/\.txt\$//" | tr '\n' ',')
        _out=${_out%,}
        [ -n "$_out" ] && echo "$_out" || echo "-"
    }
    echo "REAL_DL=$(_list_ids /data/media/0/Download nsp_race_a)"
    echo "SB_DL=$(_list_ids "/data/media/0/Android/data/$_pkg/sandbox/Download" nsp_race_a)"
    echo "REAL_HID=$(_list_ids /data/media/0/nsp_race_b nsp_race_b)"
    ;;
make-hide-fixture)
    need_root
    _d=/data/media/0/nsp_verify/hide
    mkdir -p "$_d" || die "创建 HIDE 夹具目录失败"
    printf 'NSP_HIDE_CANARY\n' > "$_d/secret.txt" || die "写 HIDE 夹具失败"
    chmod 755 /data/media/0/nsp_verify "$_d"
    chmod 644 "$_d/secret.txt"
    echo "FIXTURE_READY"
    ;;
unlink-fixture)
    need_root
    # 历史残留夹具：libfuse 的隐藏名文件直接落在磁盘上，应用列举必须看不到
    # （本地路径已改为直删；该夹具验证 readdir 过滤，文件本身不得被删）。
    _d=/data/media/0/nsp_verify/unlink
    mkdir -p "$_d" || die "创建 unlink 夹具目录失败"
    printf 'NSP_LEGACY_HIDDEN
' > "$_d/.fuse_hidden0000000000000001" || die "写隐藏名夹具失败"
    chmod 755 /data/media/0/nsp_verify "$_d"
    chmod 644 "$_d/.fuse_hidden0000000000000001"
    echo "UNLINK_FIXTURE_READY"
    ;;
reload-config)
    need_root
    [ -f "$STAGE/injector.conf" ] || die "缺少 staging/injector.conf"
    cp -f "$STAGE/injector.conf" "$CFG/.injector.conf.new" || die "暂存配置失败"
    chmod 600 "$CFG/.injector.conf.new"
    mv -f "$CFG/.injector.conf.new" "$CFG/injector.conf" || die "替换配置失败"
    echo "CONFIG_RELOADED"
    ;;
stop-prod)
    need_root
    stop_all "$DAEMONS" "生产"
    echo "PROD_STOPPED"
    ;;
start-verify)
    need_root
    [ -x "$BIN/injector" ] || die "缺少 $BIN/injector"
    [ -x "$BIN/fuse_daemon" ] || die "缺少 $BIN/fuse_daemon"
    for _p in $DAEMONS; do
        _pid=$(pid_of "$_p")
        [ -n "$_pid" ] && die "$_p 已在运行（验证前必须为空）"
    done
    cd "$BIN" || die "cd $BIN 失败"
    if [ -x "$BIN/log_monitor" ]; then
        "$BIN/log_monitor" >/dev/null 2>&1 &
    fi
    sleep 1
    "$BIN/injector" --passive --inject-method=v1 debug >"$CFG/log/verify_injector.out" 2>&1 &
    _n=0
    while [ "$_n" -lt 20 ]; do
        if [ -n "$(pid_of injector)" ] && [ -n "$(pid_of fuse_daemon)" ]; then
            echo "VERIFY_STARTED injector=$(pid_of injector) fuse=$(pid_of fuse_daemon)"
            exit 0
        fi
        sleep 1
        _n=$((_n + 1))
    done
    echo "--- verify_injector.out ---" >&2
    tail -40 "$CFG/log/verify_injector.out" 2>/dev/null >&2
    die "验证实例未在 20s 内就绪"
    ;;
stop-verify)
    need_root
    stop_all "$DAEMONS" "验证"
    echo "VERIFY_STOPPED"
    ;;
start-prod)
    need_root
    [ -f "$PROD_MOD/service.sh" ] || die "未找到 $PROD_MOD/service.sh"
    sh "$PROD_MOD/service.sh" >/dev/null 2>&1 &
    _n=0
    while [ "$_n" -lt 40 ]; do
        if [ -n "$(pid_of injector)" ]; then
            echo "PROD_STARTED injector=$(pid_of injector)"
            exit 0
        fi
        sleep 1
        _n=$((_n + 1))
    done
    die "生产服务未在 40s 内启动"
    ;;
keep-awake)
    need_root
    _to=${2:-1800000}
    _so=${3:-7}
    settings put system screen_off_timeout "$_to" || die "设置息屏超时失败"
    settings put global stay_on_while_plugged_in "$_so" || die "设置充电常亮失败"
    input keyevent KEYCODE_WAKEUP >/dev/null 2>&1
    wm dismiss-keyguard >/dev/null 2>&1
    echo "AWAKE_SET timeout=$_to stayon=$_so"
    ;;
restore-awake)
    need_root
    _to=${2:-600000}
    _so=${3:-15}
    settings put system screen_off_timeout "$_to" >/dev/null 2>&1 || true
    settings put global stay_on_while_plugged_in "$_so" >/dev/null 2>&1 || true
    echo "AWAKE_RESTORED timeout=$_to stayon=$_so"
    ;;
force-stop)
    need_root
    [ -n "${2:-}" ] || die "用法: force-stop <pkg>"
    am force-stop "$2"
    echo "FORCE_STOPPED $2"
    ;;
launch)
    need_root
    [ -n "${2:-}" ] || die "用法: launch <pkg>"
    am force-stop "$2" >/dev/null 2>&1
    sleep 1
    # 屏幕休眠时进程会被系统冻结（isFrozen=true），onCreate 停在中途不报错也不继续——
    # 探针因此「只发了 start 就没了下文」。每次启动前唤醒并解锁，保证探针真在跑。
    input keyevent KEYCODE_WAKEUP >/dev/null 2>&1
    wm dismiss-keyguard >/dev/null 2>&1
    _out=$(am start -W -n "$2/nsp.probe.ProbeActivity" 2>&1)
    echo "$_out"
    case "$_out" in
        *"Status: ok"*) echo "LAUNCHED $2" ;;
        *"Status: timeout"*)
            # 预期：v1 两段式补挂载把进程阻塞在 post-specialize（仍早于应用 Java
            # 代码），am start -W 的 10s 等待可能先超时。探针是否跑完由宿主按
            # logcat 的 done 行判定，不以此处为准。
            echo "LAUNCHED_ASYNC $2"
            ;;
        *) die "启动 $2 失败" ;;
    esac
    ;;
get-uid)
    need_root
    [ -n "${2:-}" ] || die "用法: get-uid <pkg>"
    _uid=$(stat -c %u "/data/data/$2" 2>/dev/null)
    [ -n "$_uid" ] || _uid=$(dumpsys package "$2" 2>/dev/null | sed -n 's/.*userId=\([0-9][0-9]*\).*/\1/p' | head -1)
    [ -n "$_uid" ] || die "无法取得 $2 的 uid"
    echo "UID=$_uid"
    ;;
check-file)
    need_root
    [ -n "${2:-}" ] || die "用法: check-file <abs-path>"
    case "$2" in
        /data/local/tmp/nsp_verify/*|/data/media/*|/data/Namespace-Proxy/*) ;;
        *) die "check-file 拒绝越界路径: $2" ;;
    esac
    if [ -e "$2" ]; then
        _sz=$(stat -c %s "$2" 2>/dev/null || echo "?")
        echo "EXISTS=1 SIZE=$_sz"
    else
        echo "EXISTS=0 SIZE=0"
    fi
    ;;
read-file)
    need_root
    [ -n "${2:-}" ] || die "用法: read-file <abs-path>"
    case "$2" in
        /data/local/tmp/nsp_verify/*|/data/media/*|/data/Namespace-Proxy/*) ;;
        *) die "read-file 拒绝越界路径: $2" ;;
    esac
    cat "$2" 2>/dev/null || die "读取失败: $2"
    ;;
hash-file)
    need_root
    [ -n "${2:-}" ] || die "用法: hash-file <abs-path>"
    case "$2" in
        /data/local/tmp/nsp_verify/*|/data/media/*|/data/Namespace-Proxy/*) ;;
        *) die "hash-file 拒绝越界路径: $2" ;;
    esac
    if [ -f "$2" ]; then
        echo "SHA=$(sha256sum "$2" | cut -d' ' -f1)"
    else
        echo "SHA=-"
    fi
    ;;
cleanup)
    need_root
    stop_all "$DAEMONS" "验证" >/dev/null 2>&1 || true
    if [ -d "$VR" ] && [ ! -L "$VR" ]; then
        rm -rf "$VR" || die "清理 $VR 失败"
    fi
    rm -rf /data/media/0/nsp_verify /data/media/0/ftp_probe /data/media/0/sftp_probe
    rm -rf /data/media/0/nsp_race_b
    rm -rf /data/media/0/Android/data/nsp.probe.race/sandbox
    rm -f /data/media/0/Download/nsp_probe_sandbox.txt /data/media/0/Pictures/nsp_probe_sandbox.jpg
    rm -f /data/media/0/Download/nsp_race_a*.txt
    echo "CLEANED"
    ;;
dump-logs)
    need_root
    for _f in "$CFG/log/sys.log" "$CFG/log/io.log" "$CFG/log/module_errors.log" "$CFG/log/error.log" "$CFG/log/fuse_crash.log" "$CFG/log/verify_injector.out"; do
        [ -f "$_f" ] || continue
        echo "===== $_f ====="
        tail -400 "$_f"
    done
    echo "===== logcat-NSP_PROBE ====="
    logcat -d -v threadtime -s NSP_PROBE:I 2>/dev/null | tail -100
    echo "===== logcat-injector ====="
    logcat -d -v threadtime 2>/dev/null | grep -iE 'injector|fuse_daemon|Namespace' | tail -80
    ;;
status)
    echo "injector=$(pid_of injector)"
    echo "fuse_daemon=$(pid_of fuse_daemon)"
    echo "log_monitor=$(pid_of log_monitor)"
    echo "rule_server=$(pid_of rule_server)"
    if [ -d "$VR" ]; then echo "verify_root=1"; else echo "verify_root=0"; fi
    ;;
*)
    echo "用法: $0 {preflight|prepare-dirs|prepare|reload-config|stop-prod|start-verify|stop-verify|start-prod|force-stop <pkg>|launch <pkg>|get-uid <pkg>|check-file <path>|read-file <path>|hash-file <path>|race-fixture <pkg>|race-scan [pkg]|keep-awake [timeout] [stayon]|restore-awake [timeout] [stayon]|cleanup|status}" >&2
    exit 2
    ;;
esac
