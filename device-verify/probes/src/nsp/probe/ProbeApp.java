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
 * <p>每条结果是一行 logcat（tag = {@code NSP_PROBE}）：
 * <pre>case=&lt;ftp|sftp|hide|iso|plain&gt;|step=&lt;name&gt;|ok=&lt;0|1&gt;|detail=&lt;...&gt;</pre>
 * {@code detail} 内不会出现 {@code '|'}（会被替换成 {@code '/'}），可含空格与逗号。
 * 最后一行 {@code step=done} 表示探针执行完毕，宿主可据此结束等待。
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

    private String pkg = "unknown";
    private String caseName = "plain";

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
    private int listDirStep(File dir) {
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
        emit("list", ok, detail);
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
        Log.i(TAG, "case=" + caseName + "|step=" + sanitize(step)
                + "|ok=" + (ok ? 1 : 0) + "|detail=" + sanitize(detail));
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
                || "iso".equals(name) || "plain".equals(name) || "race".equals(name)) {
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
