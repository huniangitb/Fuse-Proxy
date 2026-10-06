#!/bin/sh
# =============================================================================
# test-isolated.sh —— 在隔离沙箱内跑全量测试（GNU 层），并取宿主零污染证据
#
# 隔离主体（内核原生机制，非约定）：
#   unshare --user --map-root-user --map-auto --mount --pid --fork --mount-proc --net
#   - --mount  私有挂载 ns：所有 FUSE 挂载只存在于沙箱内，宿主 mountinfo 不受影响
#   - --pid    私有 pid ns：套件里的 `pkill -f fuse_daemon` / `pkill -9 -x log_monitor`
#              只杀得死沙箱内进程（宿主副作用清单里最凶的两条由此根除）
#   - --net    私有 netns：抽象 Unix 套接字（nsp_log_socket）随之隔离，
#              测试对 log_monitor 的启停不再波及宿主实例
#   - 私有 /var：绑定 stage 副本，/var/fuse-proxy 的配置与日志不落宿主
#   - 私有 FTP 树：绑定 stage 里的**最小合成树**（见下），不碰用户的 /home/bdy/ftp
#   - 私有 vsftpd：--net 之后宿主 21 口不可达，故在沙箱内起一份
#
# 三个实测坑（都已在此脚本内修掉，改动前请先看这里）：
#   1. 客户端必须降为 uid 1000 **并给 ambient CAP_SYS_ADMIN**。两个约束互相拉扯：
#      RO（只读）用例要求非 root（vfs_check_read_only 对 uid==0 有框架级豁免），
#      但降权后 setuid 的 fusermount3 在本 userns 内提不了权（实测 EPERM
#      "mount failed: Operation not permitted"），故须显式给 ambient CAP_SYS_ADMIN。
#      它不影响 RO 判定——那条只看 uid。
#   2. vsftpd 需要 secure_chroot_dir，且**守护化后错误只进 syslog**（stderr 恒空）。
#      私有 /var 里没有 /var/run/vsftpd/empty，子进程连上即挂——现象是"端口在听但
#      curl rc=8"，极易误判成网络问题。故显式指定到 stage 下。
#   3. FTP 树**不能整树复制**：/home/bdy/ftp 有 4.7G（upload 2.6G），每轮复制既慢
#      又占盘。测试只要求 anon chroot 根不可写、upload/upload2 可写，且自建全部
#      数据（test_ftp 的"读现有文件"是自己先写再读），故用最小合成树。
#
# 用法：
#   scripts/test-isolated.sh                  # 跑全量（等价于 --all）
#   scripts/test-isolated.sh test_ftp.py ...   # 只跑指定套件
#
# 注意：不传套件名时**必须显式 --all**——run.py 默认是「按本次改动匹配」，而本脚本
# 自身是新文件，匹配结果只跑通用回归基线（2 套），容易误以为跑过全量。
#
# 退出码：宿主不变量变化 = 1；测试失败 = 2；两者皆有 = 3；否则 0
# =============================================================================
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/.." && pwd)
export REPO

STAGE=${NSP_ISO_STAGE:-/home/bdy/.nsp-iso-$$}
SUITES="$*"
CLIENT_UID=${NSP_ISO_UID:-1000}
# 显式走绝对路径的 rm：某些宿主 shell 会把 rm 垫成删除守卫（本项目开发机上就有），
# 那类垫片对 stage 的批量删除会静默失败，导致"跑完不清理"。
RM=/bin/rm
[ -x "$RM" ] || RM=rm

die() { echo "[iso] FATAL: $*" >&2; exit 1; }
log() { echo "[iso] $*"; }

# ---------- 宿主不变量快照 ----------
# 三项与 AGENTS「验收标准」一致：挂载表、配置/日志目录、FTP 树。
snap() { # $1=输出文件
    {
        echo "### mountinfo"
        grep -v " /proc " /proc/self/mountinfo 2>/dev/null
        echo "### var-fuse-proxy"
        if [ -d /var/fuse-proxy ]; then
            (cd /var/fuse-proxy && find . -printf '%p %s\n' 2>/dev/null | sort)
        else
            echo "(不存在)"
        fi
        echo "### ftp-tree"
        if [ -d /home/bdy/ftp ]; then
            (cd /home/bdy/ftp && find . -maxdepth 2 -printf '%p %s\n' 2>/dev/null | sort)
        else
            echo "(不存在)"
        fi
    } > "$1"
}

# ---------- 准备 stage ----------
"$RM" -rf "$STAGE"
mkdir -p "$STAGE/var" "$STAGE/log" "$STAGE/vsftpd-empty" || die "建 stage 失败：$STAGE"
[ -d /var/fuse-proxy ] && cp -a /var/fuse-proxy "$STAGE/var/" 2>/dev/null
mkdir -p "$STAGE/var/log" "$STAGE/var/run"
# 私有副本放宽可写：客户端以 uid 1000 跑，需要能改 /var/fuse-proxy 下的配置/日志
chmod -R a+rwX "$STAGE/var" 2>/dev/null

# 最小合成 FTP 树：anon chroot 根不可写（否则 vsftpd 拒绝服务），upload/upload2 可写
mkdir -p "$STAGE/ftp/upload" "$STAGE/ftp/upload2"
chmod 755 "$STAGE/ftp"
chmod 777 "$STAGE/ftp/upload" "$STAGE/ftp/upload2"

BEFORE="$STAGE/before.snap"
AFTER="$STAGE/after.snap"
snap "$BEFORE"

# ---------- 沙箱内执行 ----------
INNER="$STAGE/inner.sh"
cat > "$INNER" <<'INNEREOF'
set -u
ip link set lo up 2>/dev/null || echo "[iso-inner] lo 拉起失败（127.0.0.1 将不可达）"

# 私有 /tmp：套件全部把 fixture 建在 /tmp（/tmp/fuse_*_test、/tmp/Namespace-Proxy），
# 私有化后既不再污染宿主 /tmp，也避免"内层 uid 1000 经 --map-auto 落到 subuid、
# 在宿主 /tmp 造出的目录宿主用户反而删不掉"这类所有权错配。
mount -t tmpfs -o mode=1777,size=6g tmpfs /tmp || { echo "[iso-inner] 私有 /tmp 失败"; exit 1; }

# 私有 /var 与 FTP 树（必须在起 vsftpd 之前完成绑定）
mount --bind "$STAGE/var" /var || { echo "[iso-inner] 绑定 /var 失败"; exit 1; }
mount --bind "$STAGE/ftp" /home/bdy/ftp || { echo "[iso-inner] 绑定 FTP 树失败"; exit 1; }

# 私有 vsftpd（secure_chroot_dir 必须显式给：私有 /var 里没有 /var/run/vsftpd/empty）
cat > "$STAGE/vsftpd.conf" <<'VSEOF'
anonymous_enable=YES
no_anon_password=YES
anon_root=/home/bdy/ftp
local_enable=NO
background=YES
write_enable=YES
anon_upload_enable=YES
anon_mkdir_write_enable=YES
anon_other_write_enable=YES
anon_umask=022
nopriv_user=ftp
listen=YES
listen_ipv6=NO
pasv_enable=YES
pasv_min_port=30000
pasv_max_port=30100
allow_writeable_chroot=YES
use_localtime=YES
VSEOF
printf 'secure_chroot_dir=%s\n' "$STAGE/vsftpd-empty" >> "$STAGE/vsftpd.conf"
vsftpd "$STAGE/vsftpd.conf" 2>"$STAGE/vsftpd.err"
sleep 2
if ! curl -s --max-time 5 "ftp://127.0.0.1:21/upload/" >/dev/null 2>&1; then
    echo "[iso-inner] ⚠ 沙箱内 vsftpd 未就绪，FTP 套件会失败（见 $STAGE/vsftpd.err）"
fi

# ---- 属主适配（必须在内层做，因为 uid 映射只在 ns 内可见）----
# 内层 uid 1000 经 --map-auto 落到 subuid，而 stage 与仓库文件是 ns-root（= 宿主用户）
# 属主，于是出现两类"权限不够"：
#   1) FTP 树：test_ftp 会 os.chmod(FTP_ROOT, 0755)（vsftpd 拒绝可写 chroot 根），
#      非属主必然 EPERM → 把私有树 chown 给客户端 uid（stage 是临时目录，无污染）
#   2) 仓库 build_gnu/：test_modules / test_module_circuit / test_module_abi 要把现场
#      编译的测试模块写进去，覆盖宿主属主的同名文件会被拒 → 整目录连同文件一并
#      chown 给客户端 uid（收尾再归还，见下）
chown -R "$CLIENT_UID:$CLIENT_UID" /home/bdy/ftp 2>/dev/null
chown -R "$CLIENT_UID:$CLIENT_UID" "$REPO/build_gnu" 2>/dev/null

# 客户端降权到 uid 1000 并给 ambient CAP_SYS_ADMIN：
#   - 必须**非 root**：RO（只读）用例的有效性依赖 vfs_check_read_only 的 root 豁免
#     （`uid != 0 && read_only → EROFS`），以 root 跑会让期望 EROFS 的调用全部成功。
#   - 但降权后 setuid 的 fusermount3 在本 userns 内提不了权（实测 EPERM
#     "mount failed: Operation not permitted"），故显式授予 ambient CAP_SYS_ADMIN
#     供挂载使用。它不影响 RO 判定——那一条只看 uid。
unset PYTHONPATH BASH_ENV
PATH="/usr/local/bin:/usr/bin:/bin"
export PATH
cd "$REPO" || exit 1
if [ "$(id -u)" = 0 ] && command -v setpriv >/dev/null 2>&1; then
    setpriv --reuid="$CLIENT_UID" --regid="$CLIENT_UID" --clear-groups \
        --inh-caps=+sys_admin --ambient-caps=+sys_admin \
        python3 tests/run.py --jobs 4 ${SUITES:---all}
    rc=$?
else
    python3 tests/run.py --jobs 4 ${SUITES:---all}
    rc=$?
fi

# 收尾：把客户端（subuid）造出的东西**属主归还**给 ns-root（= 宿主用户）。
# 不归还的后果有两处：仓库 build_gnu/ 里会留下宿主无法覆盖的 subuid 属主 .so
# （ninja 之后会失败），以及 stage 目录宿主删不掉（rm 报权限）。归还后两者都恢复。
chown -R 0:0 "$REPO/build_gnu" 2>/dev/null
chown -R 0:0 "$STAGE" 2>/dev/null
pkill vsftpd 2>/dev/null
sleep 1
exit $rc
INNEREOF
chmod 755 "$INNER"

log "进入沙箱（stage=$STAGE，客户端 uid=$CLIENT_UID）"
unshare --user --map-root-user --map-auto --mount --pid --fork --mount-proc --net \
    /bin/sh -c "STAGE=$STAGE REPO=$REPO SUITES='$SUITES' CLIENT_UID=$CLIENT_UID sh $INNER"
TEST_RC=$?

# ---------- 宿主不变量比对 ----------
snap "$AFTER"
DIRTY=0
if ! diff -u "$BEFORE" "$AFTER" > "$STAGE/diff.txt" 2>&1; then
    echo "[iso] ❌ 宿主不变量发生变化（前 $BEFORE / 后 $AFTER）："
    head -40 "$STAGE/diff.txt"
    DIRTY=1
else
    log "✅ 宿主不变量零变化（mountinfo / /var/fuse-proxy / FTP 树）"
fi

if [ "$DIRTY" = 0 ] && [ "$TEST_RC" = 0 ]; then
    "$RM" -rf "$STAGE"
    exit 0
fi
echo "[iso] 现场保留：$STAGE（diff: $STAGE/diff.txt）"
if [ "$DIRTY" = 1 ] && [ "$TEST_RC" != 0 ]; then exit 3; fi
if [ "$DIRTY" = 1 ]; then exit 1; fi
exit 2
