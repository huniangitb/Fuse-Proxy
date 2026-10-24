package nsp.probe;

import android.app.Activity;
import android.os.Bundle;
import android.view.Gravity;
import android.widget.TextView;

/**
 * 最小启动入口：探针本身在 {@link ProbeApp#onCreate()} 中同步执行，
 * 本 Activity 只显示一行提示，不做业务。
 */
public final class ProbeActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        TextView view = new TextView(this);
        view.setText("NSP probe: " + getPackageName() + "\nsee logcat tag NSP_PROBE");
        view.setGravity(Gravity.CENTER);
        view.setTextSize(16f);
        setContentView(view);
    }
}
