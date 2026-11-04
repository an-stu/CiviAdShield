package cn.civi.adshield.fixture;

import android.app.Activity;
import android.content.ClipboardManager;
import android.os.Bundle;
import android.widget.TextView;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

/** Developer-only, foreground clipboard capture after explicitly copying a public test link. */
public final class ClipboardProbeActivity extends Activity {
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);TextView text=new TextView(this);text.setText("Public link test");setContentView(text);
        text.postDelayed(() -> {
            try {
                ClipboardManager manager=getSystemService(ClipboardManager.class);
                String value=manager.hasPrimaryClip()&&manager.getPrimaryClip()!=null?manager.getPrimaryClip().getItemAt(0).coerceToText(this).toString():"";
                Files.write(new File(getFilesDir(),"public-link.txt").toPath(),value.getBytes(StandardCharsets.UTF_8));
                text.setText("Public test link saved locally");
            } catch(Exception e) {text.setText("Link test failed");}
        },700);
    }
}
