package nsp.probe;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

/**
 * 广播触发入口。
 *
 * <p>探针全部检查在 {@link ProbeApp#onCreate()} 里同步跑完，所以拉起进程就够：
 * 一条 {@code am broadcast -a nsp.probe.RUN -n <pkg>/nsp.probe.ProbeReceiver}
 * 就能取到与启动界面完全相同的结果（结果同时写 logcat 与
 * {@code <外部私有目录>/nsp_probe.log}）。
 */
public final class ProbeReceiver extends BroadcastReceiver {

    @Override
    public void onReceive(Context context, Intent intent) {
        Log.i(ProbeApp.TAG, "case=trigger|step=broadcast|ok=1|detail=" + context.getPackageName());
    }
}
