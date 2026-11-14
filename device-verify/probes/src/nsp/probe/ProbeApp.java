package nsp.probe;

import android.app.Application;
import android.os.Environment;
import android.os.SystemClock;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * NSP 设备验证探针。
 *
 * <p>在 {@link #onCreate()} 里同步执行（主线程，不新起线程）：Application 创建时
 * FUSE 视图已按 v1 注入本进程，探针因此看到的就是模块最终暴露给应用的存储视图。
 *
 * <p>每条结果同时写两处：公共临时目录里的结果文件（主通道）与 logcat（tag =
 * {@code NSP_PROBE}，只作崩溃取证的副本）：
 * <pre>case=&lt;ftp|sftp|hide|iso|plain|unlink&gt;|step=&lt;name&gt;|ok=&lt;0|1&gt;|detail=&lt;...&gt;</pre>
 * {@code detail} 内不会出现 {@code '|'}（会被替换成 {@code '/'}），可含空格与逗号。
 * 最后一行 {@code step=done} 表示探针执行完毕，宿主据此结束等待。
 *
 * <p>结果文件按 {@link #initSink()} 的候选顺序落盘：优先公共临时目录（
 * {@code /data/local/tmp/nsp_verify/probe-logs}），其次应用内部私有目录，最后才是
 * 经 FUSE 的外部私有目录。前两者不在被验证的存储视图内，FUSE 连接断掉时照样写得
 * 进去——logcat 与外部目录都会在那种故障下一起失效，只有它们能留下证据。
 *
 * <p>场景由 {@code getPackageName()} 最后一段决定（nsp.probe.ftp → ftp）。
 *
 * <p>{@code race} 场景是例外：它**刻意不等待 FUSE 就绪**，在 {@code onCreate}
 * 立刻开始写入，用来测量 v1 注入（进程启动后才补挂载）与「应用首次写入」的先后。
 * 每次尝试同时写两个判别路径：
 * <ul>
 *   <li>{@code a} = {@code /sdcard/Download/nsp_race_a<i>.txt}（该应用配 SANDBOX ON：
 *       FUSE 视图下应落本应用沙盒，真实视图下应落真实 Download 或被拒）；</li>
 *   <li>{@code b} = {@code /sdcard/nsp_race_b/nsp_race_b<i>.txt}（配 HIDE：FUSE 视图下
 *       必然 ENOENT，真实视图下父目录由宿主预置，故非 ENOENT 即证明尚未挂载）。</li>
 * </ul>
 * 两条判别互相校验：{@code fuse} 标志、{@code a} 的落点与 {@code b} 的 errno 必须一致。
 * 所有 mkdirs() 的返回值一律忽略：虚拟前缀 / FUSE 合成目录可能返回 false
 * 但随后的写入仍然成功，不能据此判失败。
 */
public final class ProbeApp extends Application {

    /** logcat tag，宿主脚本按此过滤。 */
    public static final String TAG = "NSP_PROBE";

    /** 探针公共根目录（FUSE 视图内的路径）。 */
    public static final String ROOT = "/sdcard/nsp_verify";

    /**
     * 1x1 JPEG（160 字节）：媒体刷新链路只对媒体扩展名的落点发事件，
     * 所以 ftp/sftp 场景除了文本探针还要上传一个真正的图片。
     */
    private static final byte[] JPEG_1PX = {
            (byte)0xFF, (byte)0xD8, (byte)0xFF, (byte)0xE0, (byte)0x00, (byte)0x10, (byte)0x4A, (byte)0x46, (byte)0x49, (byte)0x46, (byte)0x00, (byte)0x01,
            (byte)0x01, (byte)0x01, (byte)0x00, (byte)0x60, (byte)0x00, (byte)0x60, (byte)0x00, (byte)0x00, (byte)0xFF, (byte)0xDB, (byte)0x00, (byte)0x43,
            (byte)0x00, (byte)0x08, (byte)0x06, (byte)0x06, (byte)0x07, (byte)0x06, (byte)0x05, (byte)0x08, (byte)0x07, (byte)0x07, (byte)0x07, (byte)0x09,
            (byte)0x09, (byte)0x08, (byte)0x0A, (byte)0x0C, (byte)0x14, (byte)0x0D, (byte)0x0C, (byte)0x0B, (byte)0x0B, (byte)0x0C, (byte)0x19, (byte)0x12,
            (byte)0x13, (byte)0x0F, (byte)0x14, (byte)0x1D, (byte)0x1A, (byte)0x1F, (byte)0x1E, (byte)0x1D, (byte)0x1A, (byte)0x1C, (byte)0x1C, (byte)0x20,
            (byte)0x24, (byte)0x2E, (byte)0x27, (byte)0x20, (byte)0x22, (byte)0x2C, (byte)0x23, (byte)0x1C, (byte)0x1C, (byte)0x28, (byte)0x37, (byte)0x29,
            (byte)0x2C, (byte)0x30, (byte)0x31, (byte)0x34, (byte)0x34, (byte)0x34, (byte)0x1F, (byte)0x27, (byte)0x39, (byte)0x3D, (byte)0x38, (byte)0x32,
            (byte)0x3C, (byte)0x2E, (byte)0x33, (byte)0x34, (byte)0x32, (byte)0xFF, (byte)0xC0, (byte)0x00, (byte)0x0B, (byte)0x08, (byte)0x00, (byte)0x01,
            (byte)0x00, (byte)0x01, (byte)0x01, (byte)0x01, (byte)0x11, (byte)0x00, (byte)0xFF, (byte)0xC4, (byte)0x00, (byte)0x14, (byte)0x00, (byte)0x01,
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x09, (byte)0xFF, (byte)0xC4, (byte)0x00, (byte)0x14, (byte)0x10, (byte)0x01, (byte)0x00, (byte)0x00,
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
            (byte)0x00, (byte)0x00, (byte)0xFF, (byte)0xDA, (byte)0x00, (byte)0x08, (byte)0x01, (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x3F, (byte)0x00,
            (byte)0x2A, (byte)0x9F, (byte)0xFF, (byte)0xD9,
    };

    private String pkg = "unknown";
    private String caseName = "plain";
    /** 结果文件（见 {@link #initSink()}）：全部成功打开的落点都写一份。 */
    private final java.util.ArrayList<File> sinks = new java.util.ArrayList<>();

    @Override
    public void onCreate() {
        super.onCreate();
        // 计时起点尽量贴近 Application 创建（race 场景的唯一判据就是相对时间）。
        final long t0 = SystemClock.elapsedRealtime();
        try {
            pkg = getPackageName();
        } catch (Throwable t) {
            pkg = "unknown";
        }
        caseName = normalizeCase(lastSegment(pkg));
        initSink();
        emit("start", true, "pkg=" + pkg);
        int steps = 0;
        try {
            if ("race".equals(caseName)) {
                steps = runRaceCase(t0); // 刻意不 waitFuseReady：竞态本身就是被测对象
            } else {
                waitFuseReady(15000);
                if ("ftp".equals(caseName) || "sftp".equals(caseName)) {
                    steps = runRemoteCase(caseName);
                } else if ("hide".equals(caseName)) {
                    steps = runHideCase();
                } else if ("iso".equals(caseName)) {
                    steps = runIsoCase();
                } else if ("unlink".equals(caseName)) {
                    steps = runUnlinkCase();
                } else {
                    steps = runPlainCase();
                }
            }
            emit("done", true, "steps=" + steps);
        } catch (Throwable t) {
            // 任何未预期异常也必须留下 ok=0 的行，宿主不能因缺行而误判。
            emit("exception", false, describe(t));
            emit("done", false, "steps=" + steps);
        }
    }

    // ------------------------------------------------------------------ ftp / sftp

    private int runRemoteCase(String cs) {
        int steps = 0;
        // FTP 规则的虚拟前缀必须与模块配置段名一致（模块按 /<段名> 匹配后端），
        // 故探针路径固定为 /sdcard/<case>_probe（如 /sdcard/ftp_probe）。
        File dir = new File("/sdcard/" + cs + "_probe");
        File probe = new File(dir, "probe_" + cs + ".txt");
        File canary = new File(dir, "REAL_CANARY.txt");

        // mkdirs 返回值不可信（见类注释），只作诊断信息记录，ok 恒为 1。
        boolean mkdirs = dir.mkdirs();
        emit("mkdir", true, "path=" + dir.getAbsolutePath() + " mkdirs=" + (mkdirs ? 1 : 0));
        steps++;

        String content = "NSP_PROBE:" + pkg + ":" + System.currentTimeMillis();
        byte[] expected = content.getBytes(StandardCharsets.UTF_8);

        boolean ok = false;
        String detail;
        try {
            writeBytes(probe, expected);
            ok = true;
            detail = "path=" + probe.getAbsolutePath() + " bytes=" + expected.length;
        } catch (Throwable t) {
            detail = "path=" + probe.getAbsolutePath() + " error=" + describe(t);
        }
        emit("write", ok, detail);
        steps++;

        ok = false;
        try {
            byte[] actual = readAll(probe);
            ok = Arrays.equals(expected, actual);
            detail = "path=" + probe.getAbsolutePath()
                    + " expected_bytes=" + expected.length
                    + " actual_bytes=" + actual.length
                    + " match=" + (ok ? 1 : 0);
        } catch (Throwable t) {
            detail = "path=" + probe.getAbsolutePath() + " error=" + describe(t);
        }
        emit("read", ok, detail);
        steps++;

        // 媒体落点：daemon 只在扩展名是媒体时发 media_refresh，文本文件不会触发
        // （见 fw_events.c 里「落点不是媒体…整条不发」），所以这里必须真写一张图。
        File media = new File(dir, "probe_" + cs + ".jpg");
        ok = false;
        try {
            writeBytes(media, JPEG_1PX);
            ok = true;
            detail = "path=" + media.getAbsolutePath() + " bytes=" + JPEG_1PX.length;
        } catch (Throwable t) {
            detail = "path=" + media.getAbsolutePath() + " error=" + describe(t);
        }
        emit("media", ok, detail);
        steps++;

        steps += listDirStep(dir);

        ok = false;
        try {
            boolean exists = canary.exists();
            ok = !exists; // 期望 REAL_CANARY.txt 不可见（HIDE 生效）
            detail = "exists=" + (exists ? 1 : 0);
        } catch (Throwable t) {
            detail = describe(t);
        }
        emit("canary", ok, detail);
        steps++;

        return steps;
    }

    // ---------------------------------------------------------------------- hide

    private int runHideCase() {
        int steps = 0;
        // 夹具由宿主以 root 预置在真实存储（/data/media/0/nsp_verify/hide/secret.txt），
        // 该路径位于项目 FUSE 树内（非 Android/data 原生子挂载），HIDE 才能生效。
        File fixture = new File(ROOT, "hide/secret.txt");
        File parent = new File(ROOT);
        String own = fixture.getAbsolutePath();

        boolean statOk = false;
        int statErrno = 0;
        try {
            Os.stat(own);
            statOk = true;
        } catch (ErrnoException e) {
            statErrno = e.errno;
        } catch (Throwable t) {
            emit("phase", false, describe(t));
            steps++;
            steps += listDirStep(parent);
            return steps;
        }

        if (statOk) {
            boolean ok = false;
            String detail;
            try {
                String text = new String(readAll(fixture), StandardCharsets.UTF_8);
                ok = text.contains("NSP_HIDE_CANARY");
                detail = "path=" + own + " content_match=" + (ok ? 1 : 0);
            } catch (Throwable t) {
                detail = "path=" + own + " error=" + describe(t);
            }
            emit("phase_a", ok, detail);
            steps++;
        } else if (statErrno == OsConstants.ENOENT) {
            emit("phase_b", true, "enoent");
            steps++;

            boolean ok = false;
            String detail;
            try {
                FileOutputStream out = new FileOutputStream(own);
                try {
                    out.write("canary".getBytes(StandardCharsets.UTF_8));
                    out.flush();
                } finally {
                    out.close();
                }
                detail = "unexpected_success";
            } catch (IOException e) {
                int errno = errnoOf(e);
                ok = (errno == OsConstants.ENOENT);
                detail = "errno=" + errno;
            } catch (Throwable t) {
                detail = describe(t);
            }
            emit("write_denied", ok, detail);
            steps++;
        } else {
            emit("phase", false, "errno=" + statErrno);
            steps++;
        }

        steps += listDirStep(parent);
        return steps;
    }

    // ----------------------------------------------------------------------- iso

    private int runIsoCase() {
        File ext;
        try {
            ext = Environment.getExternalStorageDirectory();
        } catch (Throwable t) {
            ext = null;
        }
        if (ext == null) {
            emit("download", false, "external_storage_dir=null");
            emit("pictures", false, "external_storage_dir=null");
            return 2;
        }
        String base = ext.getAbsolutePath();
        String stamp = pkg + ":" + System.currentTimeMillis();
        int steps = 0;
        steps += isoFileStep("download", new File(base, "Download/nsp_probe_sandbox.txt"),
                "NSP_PROBE_ISO_DOWNLOAD:" + stamp);
        steps += isoFileStep("pictures", new File(base, "Pictures/nsp_probe_sandbox.jpg"),
                "NSP_PROBE_ISO_PICTURES:" + stamp);
        // /Android 本身也在镜像内：应用在它下面新建的条目必须落镜像，并且能在
        // 自己的列举里看到——写完就丢的条目等于没写成功。
        File androidDir = new File(base, "Android");
        steps += isoFileStep("android_root", new File(androidDir, "nsp_probe_sandbox.txt"),
                "NSP_PROBE_ISO_ANDROID:" + stamp);
        steps += listDirStep(androidDir, "android_list");
        // 容器条目本身也由框架合成（镜像里没有真实目录）：三条都要是目录、
        // 时间戳不能是 1970，否则文件管理器会把它们画成文件或未知条目。
        steps += statContainerStep(new File(androidDir, "data"), "android_skel_data");
        steps += statContainerStep(new File(androidDir, "obb"), "android_skel_obb");
        steps += statContainerStep(new File(androidDir, "media"), "android_skel_media");
        // 三处私有目录让位到真实目录（宿主预建并 chown 给本应用）。
        steps += isoFileStep("android_obb_own",
                new File(base, "Android/obb/" + pkg + "/nsp_probe_obb.txt"),
                "NSP_PROBE_ISO_OBB:" + stamp);
        steps += isoFileStep("android_media_own",
                new File(base, "Android/media/" + pkg + "/nsp_probe_media.txt"),
                "NSP_PROBE_ISO_MEDIA:" + stamp);
        // ALLOW 豁免：宿主预建 /Android/nsp_probe_allow 并 chown 给本应用。
        steps += isoFileStep("android_allow",
                new File(base, "Android/nsp_probe_allow/nsp_probe_allow.txt"),
                "NSP_PROBE_ISO_ALLOW:" + stamp);
        return steps;
    }

    private int isoFileStep(String step, File file, String content) {
        File parent = file.getParentFile();
        if (parent != null) {
            parent.mkdirs(); // 忽略返回值
        }
        String path = file.getAbsolutePath();
        byte[] expected = content.getBytes(StandardCharsets.UTF_8);
        boolean ok = false;
        String detail;
        try {
            writeBytes(file, expected);
            byte[] actual = readAll(file);
            ok = Arrays.equals(expected, actual);
            detail = "path=" + path
                    + " bytes=" + expected.length
                    + " actual_bytes=" + actual.length
                    + " match=" + (ok ? 1 : 0);
        } catch (Throwable t) {
            detail = "path=" + path + " error=" + describe(t);
        }
        emit(step, ok, detail);
        return 1;
    }

    // --------------------------------------------------------------------- plain

    private int runPlainCase() {
        int steps = 0;
        File file = new File("/sdcard/Android/data/" + pkg + "/files/plain.txt");
        File parent = file.getParentFile();
        if (parent != null) {
            parent.mkdirs(); // 忽略返回值
        }
        String path = file.getAbsolutePath();
        String content = "NSP_PROBE_PLAIN:" + pkg + ":" + System.currentTimeMillis();
        byte[] expected = content.getBytes(StandardCharsets.UTF_8);

        boolean ok = false;
        String detail;
        try {
            writeBytes(file, expected);
            ok = true;
            detail = "path=" + path + " bytes=" + expected.length;
        } catch (Throwable t) {
            detail = "path=" + path + " error=" + describe(t);
        }
        emit("write", ok, detail);
        steps++;

        ok = false;
        try {
            byte[] actual = readAll(file);
            ok = Arrays.equals(expected, actual);
            detail = "path=" + path
                    + " expected_bytes=" + expected.length
                    + " actual_bytes=" + actual.length
                    + " match=" + (ok ? 1 : 0);
        } catch (Throwable t) {
            detail = "path=" + path + " error=" + describe(t);
        }
        emit("read", ok, detail);
        steps++;

        return steps;
    }

    // ------------------------------------------------------------------ unlink

    /**
     * 打开中删除：本地路径不得留下 .fuse_hidden。
     *
     * <p>与文件管理器「压缩后删除原文件」同一形态：先写文件并保持读句柄，
     * 再删除名字。FUSE 默认实现会把名字改成 .fuse_hidden 等最后一个句柄关闭，
     * 本地 backing 完全支持「先删名、后关句柄」，因此应立刻消失。
     * 同时验证删除后仍可 fstat（getChannel().size()）与读取。
     */
    private int runUnlinkCase() {
        int steps = 0;
        File dir = new File("/sdcard/nsp_verify/unlink");
        dir.mkdirs(); // 忽略返回值
        File file = new File(dir, "nsp_probe_unlink.txt");
        String content = "NSP_PROBE_UNLINK:" + pkg + ":" + System.currentTimeMillis();
        byte[] expected = content.getBytes(StandardCharsets.UTF_8);
        FileInputStream in = null;
        try {
            try (FileOutputStream out = new FileOutputStream(file)) {
                out.write(expected);
                out.getFD().sync();
            }
            in = new FileInputStream(file);
            boolean deleted = file.delete();
            emit("delete", deleted,
                    "path=" + file.getAbsolutePath() + " exists=" + file.exists());
            steps++;

            int hiddenOpen = countHidden(dir, false);
            emit("hidden_open", hiddenOpen == 0, "new_hidden=" + hiddenOpen);
            steps++;

            long size = -1;
            String fstatDetail;
            try {
                size = in.getChannel().size();
                fstatDetail = "size=" + size + " expected=" + expected.length;
            } catch (Throwable t) {
                fstatDetail = "error=" + describe(t);
            }
            emit("fstat", size == expected.length, fstatDetail);
            steps++;

            byte[] actual = new byte[expected.length];
            int off = 0;
            int n;
            while (off < actual.length && (n = in.read(actual, off, actual.length - off)) > 0) {
                off += n;
            }
            boolean match = off == expected.length && Arrays.equals(expected, actual);
            emit("read", match, "bytes=" + off + " match=" + (match ? 1 : 0));
            steps++;
        } catch (Throwable t) {
            emit("exception", false, describe(t));
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ignored) {
                    // 关闭失败已由后续 hidden_closed 计数暴露
                }
            }
        }
        int hiddenClosed = countHidden(dir, false);
        emit("hidden_closed", hiddenClosed == 0, "new_hidden=" + hiddenClosed);
        steps++;
        emit("exists_closed", !file.exists(), "exists=" + file.exists());
        steps++;
        // 预置的历史残留夹具：不做列举过滤，必须可见、可取证，
        // 且不得被本层自动清理（清理会抬高取证难度）。
        boolean legacyExists = new File(dir, LEGACY_HIDDEN_NAME).exists();
        boolean legacyListed = countHidden(dir, true) > 0;
        emit("hidden_legacy", !legacyExists || legacyListed,
                "fixture_exists=" + (legacyExists ? 1 : 0) + " listed=" + (legacyListed ? 1 : 0));
        steps++;
        return steps;
    }

    /** 预置的历史残留夹具名（与 device/verify-device.sh 的 unlink-fixture 一致）。 */
    private static final String LEGACY_HIDDEN_NAME = ".fuse_hidden0000000000000001";

    /**
     * 数 .fuse_hidden* 条目。{@code legacyOnly=true} 只数预置夹具，{@code false} 只数
     * 新增（排除夹具）——夹具用来验证「可见可取证、不被自动清理」，不属于残留判定，
     * 混在一起会让两个断言互相矛盾。
     */
    private static int countHidden(File dir, boolean legacyOnly) {
        int n = 0;
        String[] names = dir.list();
        if (names != null) {
            for (String name : names) {
                if (!name.startsWith(".fuse_hidden")) {
                    continue;
                }
                if (LEGACY_HIDDEN_NAME.equals(name) == legacyOnly) {
                    n++;
                }
            }
        }
        return n;
    }

    // --------------------------------------------------------------------- race

    /** 就绪后继续采样的毫秒数（拿到足够「挂载后」样本即收尾）。 */
    private static final long RACE_TAIL_MS = 300;

    /** 相邻两次尝试的间隔（ms）：决定窗口的采样密度。 */
    private static final long RACE_INTERVAL_MS = 20;

    /** 总时长上限（ms）：v1 就绪门控约 1s + 重试，留足余量。 */
    private static final long RACE_MAX_MS = 6000;

    /**
     * 竞态场景：从 {@code onCreate} 起立即、反复地写两个判别路径，记录每次尝试的
     * 相对时间、当时的 FUSE 就绪标志与写入结果。宿主据「落点扫描 + 结果」交叉判定
     * 每次尝试究竟落在 FUSE 视图还是真实视图，从而量出 v1 的覆盖窗口。
     *
     * <p>本方法**不**等待就绪：等待会把被测对象（就绪与首写的先后）抹掉。
     */
    private int runRaceCase(long t0) {
        int attempts = 0;
        long firstFuseMs = -1;
        File dl = new File("/sdcard/Download");
        dl.mkdirs(); // 忽略返回值：已存在时返回 false
        File hid = new File("/sdcard/nsp_race_b");
        for (int i = 0; ; i++) {
            long ms = SystemClock.elapsedRealtime() - t0;
            boolean fuse = false;
            try {
                fuse = mountHasFuseDaemon();
            } catch (Throwable ignored) {
                // 读不到 mountinfo 按未就绪计，与真实判定口径一致
            }
            if (fuse && firstFuseMs < 0) {
                firstFuseMs = ms;
            }
            // 每轮都补建父目录：就绪前它是真实 Download（已存在），就绪后它是沙盒
            // 里的 Download（首轮不存在）——不补建会让「就绪后写入」以 ENOENT 失败，
            // 把探针自身的疏漏伪装成模块缺陷。
            dl.mkdirs();
            String a = raceWrite(new File(dl, "nsp_race_a" + i + ".txt"),
                    "NSP_RACE_A:i=" + i + " ms=" + ms + " fuse=" + (fuse ? 1 : 0));
            String b = raceWrite(new File(hid, "nsp_race_b" + i + ".txt"), "NSP_RACE_B:i=" + i);
            emit("attempt", true, "i=" + i + " ms=" + ms
                    + " fuse=" + (fuse ? 1 : 0) + " a=" + a + " b=" + b);
            attempts++;
            if (firstFuseMs >= 0 && ms - firstFuseMs >= RACE_TAIL_MS) {
                break;
            }
            if (ms >= RACE_MAX_MS) {
                break;
            }
            try {
                Thread.sleep(RACE_INTERVAL_MS);
            } catch (InterruptedException ignored) {
                // 被中断就按当前样本收尾
                break;
            }
        }
        emit("summary", true, "attempts=" + attempts + " first_fuse_ms=" + firstFuseMs);
        return attempts > 0 ? 1 : 0;
    }

    /** 一次写入尝试：成功返回 {@code ok}，失败返回 errno 名，未知异常返回类名。 */
    private static String raceWrite(File file, String content) {
        try {
            writeBytes(file, content.getBytes(StandardCharsets.UTF_8));
            return "ok";
        } catch (Throwable t) {
            String name = errnoName(t);
            return name != null ? name : describe(t);
        }
    }

    /** IOException 的 errno 名（供 race 场景的 detail 使用）；非 errno 类异常返回 null。 */
    private static String errnoName(Throwable t) {
        if (!(t instanceof IOException)) {
            return null;
        }
        // OsConstants 的 errno 是静态初始化赋值，不是编译期常量，故用 if 链而非 switch。
        int errno = errnoOf((IOException) t);
        if (errno == OsConstants.ENOENT) {
            return "ENOENT";
        }
        if (errno == OsConstants.EACCES) {
            return "EACCES";
        }
        if (errno == OsConstants.EPERM) {
            return "EPERM";
        }
        if (errno == OsConstants.EROFS) {
            return "EROFS";
        }
        if (errno == OsConstants.EISDIR) {
            return "EISDIR";
        }
        if (errno == OsConstants.ENOTDIR) {
            return "ENOTDIR";
        }
        return null;
    }

    // ------------------------------------------------------------------- helpers

    /** 列目录并输出 step=list：detail 为逗号分隔条目，空目录为 "-"。 */
    /** 容器条目自身：必须是目录（不是文件），时间戳不得落到 1970。 */
    private int statContainerStep(File dir, String step) {
        boolean ok = false;
        String detail;
        try {
            boolean isDir = dir.isDirectory();
            long mtime = dir.lastModified();
            ok = isDir && mtime > 0;
            detail = "isDir=" + (isDir ? 1 : 0) + " mtime=" + mtime;
        } catch (Throwable t) {
            detail = describe(t);
        }
        emit(step, ok, detail);
        return 1;
    }

    private int listDirStep(File dir) {
        return listDirStep(dir, "list");
    }

    /** 同上，step 名可指定（同一场景里要列两个目录时装机侧才好区分）。 */
    private int listDirStep(File dir, String step) {
        boolean ok = false;
        String detail;
        try {
            String[] names = dir.list();
            if (names == null) {
                detail = "list_returned_null path=" + dir.getAbsolutePath();
            } else {
                Arrays.sort(names);
                ok = true;
                detail = names.length == 0 ? "-" : join(names, ",");
            }
        } catch (Throwable t) {
            detail = "error=" + describe(t);
        }
        emit(step, ok, detail);
        return 1;
    }

    /** 等待本进程命名空间里出现项目 FUSE 挂载（fsname fuse_daemon）。 */
    private void waitFuseReady(long timeoutMs) {
        long start = System.currentTimeMillis();
        long deadline = start + timeoutMs;
        while (true) {
            try {
                if (mountHasFuseDaemon()) {
                    emit("ready", true, "ms=" + (System.currentTimeMillis() - start));
                    return;
                }
            } catch (Throwable ignored) {
                // 读不到 mountinfo 时按未就绪处理，继续轮询到超时
            }
            if (System.currentTimeMillis() >= deadline) {
                emit("ready", false, "timeout_ms=" + timeoutMs);
                return;
            }
            try {
                Thread.sleep(50);
            } catch (InterruptedException ignored) {
            }
        }
    }

    private boolean mountHasFuseDaemon() throws IOException {
        String info = new String(readAll(new File("/proc/self/mountinfo")), StandardCharsets.UTF_8);
        for (String line : info.split("\n")) {
            int sep = line.indexOf(" - ");
            if (sep < 0) {
                continue;
            }
            String[] pre = line.substring(0, sep).split(" ");
            if (pre.length < 5 || !"/storage/emulated".equals(pre[4])) {
                continue;
            }
            // 只有挂载点本身被替换成项目 FUSE 才算就绪；/mnt/nsp_global 可能
            // 先出现在命名空间里（共享传播），不能作为判据。
            if (line.substring(sep).contains("fuse_daemon")) {
                return true;
            }
        }
        return false;
    }

    private void emit(String step, boolean ok, String detail) {
        String line = "case=" + caseName + "|step=" + sanitize(step)
                + "|ok=" + (ok ? 1 : 0) + "|detail=" + sanitize(detail);
        Log.i(TAG, line);
        appendSink(line);
    }

    /**
     * 结果同时落文件：一行 logcat 一对一一行文件，宿主可直接 cat 取回，不必再
     * dump 整份 logcat 过滤。每行独立 open/append，进程中途被杀也能留下已经产出
     * 的行；所有打开成功的落点都写一份，任一通道坏掉都还有别的能取回。
     */
    private void appendSink(String line) {
        for (File f : sinks) {
            try (FileOutputStream out = new FileOutputStream(f, true)) {
                out.write((line + "\n").getBytes(StandardCharsets.UTF_8));
            } catch (IOException ignored) {
                // 结果文件只是取回通道，写失败不影响检查本身。
            }
        }
    }

    /**
     * 结果文件的位置，按优先级：
     * <ol>
     *   <li>{@code /data/local/tmp/nsp_verify/probe-logs/<pkg>.log}：公共临时目录，
     *       由设备脚本预建并交给本应用 uid；不在被验证的存储视图内。</li>
     *   <li>应用内部私有目录：不经 FUSE，FUSE 连接断掉时照样写得进去。</li>
     *   <li>外部私有目录：经 FUSE，视图故障时写不进去，只作兼容兜底。</li>
     * </ol>
     * 每个落点的成败都会记进 {@code step=sink} 那一行：SELinux 允许写到哪里是设备
     * 的事实，不能靠猜。全部失败时宿主只能退到 logcat（本进程仍会打一份）。
     */
    private void initSink() {
        java.util.ArrayList<File> candidates = new java.util.ArrayList<>();
        candidates.add(new File("/data/local/tmp/nsp_verify/probe-logs/" + pkg + ".log"));
        try {
            File dir = getFilesDir();
            if (dir != null) {
                //noinspection ResultOfMethodCallIgnored
                dir.mkdirs();
                candidates.add(new File(dir, "nsp_probe.log"));
            }
        } catch (Throwable ignored) {
            // 取不到内部目录就少一个落点，不影响其余候选
        }
        try {
            File dir = getExternalFilesDir(null);
            if (dir != null) {
                //noinspection ResultOfMethodCallIgnored
                dir.mkdirs();
                candidates.add(new File(dir, "nsp_probe.log"));
            }
        } catch (Throwable ignored) {
            // 同上
        }
        java.util.ArrayList<String> status = new java.util.ArrayList<>();
        for (File f : candidates) {
            File parent = f.getParentFile();
            if (parent != null) {
                //noinspection ResultOfMethodCallIgnored
                parent.mkdirs();
            }
            try (FileOutputStream out = new FileOutputStream(f, true)) {
                out.write(new byte[0]);
                sinks.add(f);
                status.add(f.getAbsolutePath() + "=ok");
            } catch (Throwable t) {
                status.add(f.getAbsolutePath() + "=" + describe(t));
            }
        }
        emit("sink", !sinks.isEmpty(), join(status.toArray(new String[0]), "; "));
    }

    /** detail/step 内不得含 '|'；换行折成空格，超长截断。 */
    private static String sanitize(String s) {
        if (s == null || s.isEmpty()) {
            return "-";
        }
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '|') {
                sb.append('/');
            } else if (c == '\n' || c == '\r') {
                sb.append(' ');
            } else {
                sb.append(c);
            }
        }
        String out = sb.toString();
        if (out.length() > 480) {
            out = out.substring(0, 480) + "...";
        }
        return out;
    }

    private static String describe(Throwable t) {
        if (t == null) {
            return "unknown";
        }
        String message = t.getMessage();
        return t.getClass().getSimpleName() + (message == null ? "" : ":" + message);
    }

    /**
     * FileOutputStream/FileInputStream 抛出的 IOException 不带 errno，
     * 从 Android 的错误串里还原常见 errno（隐藏写探测用）。
     */
    private static int errnoOf(IOException e) {
        String message = e.getMessage();
        if (message == null) {
            return -1;
        }
        if (message.contains("ENOENT") || message.contains("No such file")) {
            return OsConstants.ENOENT;
        }
        if (message.contains("EACCES") || message.contains("Permission denied")) {
            return OsConstants.EACCES;
        }
        if (message.contains("EROFS") || message.contains("Read-only file system")) {
            return OsConstants.EROFS;
        }
        if (message.contains("EISDIR") || message.contains("Is a directory")) {
            return OsConstants.EISDIR;
        }
        if (message.contains("ENOTDIR") || message.contains("Not a directory")) {
            return OsConstants.ENOTDIR;
        }
        if (message.contains("EPERM") || message.contains("Operation not permitted")) {
            return OsConstants.EPERM;
        }
        return -1;
    }

    private static void writeBytes(File file, byte[] data) throws IOException {
        FileOutputStream out = new FileOutputStream(file);
        try {
            out.write(data);
            out.flush();
        } finally {
            out.close();
        }
    }

    private static byte[] readAll(File file) throws IOException {
        FileInputStream in = new FileInputStream(file);
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int n;
            while ((n = in.read(buffer)) != -1) {
                out.write(buffer, 0, n);
            }
            return out.toByteArray();
        } finally {
            in.close();
        }
    }

    private static String join(String[] values, String separator) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < values.length; i++) {
            if (i > 0) {
                sb.append(separator);
            }
            sb.append(values[i]);
        }
        return sb.toString();
    }

    private static String normalizeCase(String name) {
        if ("ftp".equals(name) || "sftp".equals(name) || "hide".equals(name)
                || "iso".equals(name) || "plain".equals(name) || "race".equals(name)
                || "unlink".equals(name)) {
            return name;
        }
        return "plain";
    }

    private static String lastSegment(String name) {
        if (name == null) {
            return "";
        }
        int dot = name.lastIndexOf('.');
        return dot >= 0 ? name.substring(dot + 1) : name;
    }
}
