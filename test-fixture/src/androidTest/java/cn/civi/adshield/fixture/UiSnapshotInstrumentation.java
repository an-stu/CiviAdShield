package cn.civi.adshield.fixture;

import android.app.Instrumentation;
import android.app.UiAutomation;
import android.graphics.Rect;
import android.os.Bundle;
import android.util.Xml;
import android.view.accessibility.AccessibilityNodeInfo;
import org.xmlpull.v1.XmlSerializer;
import java.io.File;
import java.io.FileOutputStream;

/** Developer-only snapshot of the current foreground UI, without an idle wait or any action. */
public final class UiSnapshotInstrumentation extends Instrumentation {
    private int visited;
    @Override public void onCreate(Bundle args) { super.onCreate(args);start(); }
    @Override public void onStart() {
        Bundle result=new Bundle();int code=-1;
        AccessibilityNodeInfo root=null;
        try {
            UiAutomation automation=getUiAutomation(UiAutomation.FLAG_DONT_SUPPRESS_ACCESSIBILITY_SERVICES);
            for(int attempt=0;attempt<30 && root==null;attempt++) {
                root=automation.getRootInActiveWindow();
                if(root==null) for(android.view.accessibility.AccessibilityWindowInfo window:automation.getWindows()) {
                    if(window.isActive() || window.isFocused()) {root=window.getRoot();if(root!=null)break;}
                }
                if(root==null)android.os.SystemClock.sleep(100);
            }
            if(root==null)throw new IllegalStateException("No active UI root");
            File file=new File(getTargetContext().getFilesDir(),"ui-snapshot.xml");
            try(FileOutputStream out=new FileOutputStream(file)) {
                XmlSerializer xml=Xml.newSerializer();xml.setOutput(out,"UTF-8");xml.startDocument("UTF-8",true);
                xml.startTag(null,"hierarchy");write(xml,root,0);xml.endTag(null,"hierarchy");xml.endDocument();
            }
            result.putString("stream","Snapshot saved: files/ui-snapshot.xml; nodes="+visited+"\n");
        } catch(Exception e) {code=0;result.putString("stream","Snapshot failed: "+e.getClass().getSimpleName()+": "+e.getMessage()+"\n");}
        finally {if(root!=null)root.recycle();}
        finish(code,result);
    }
    private void write(XmlSerializer xml,AccessibilityNodeInfo node,int depth)throws Exception {
        if(visited>=5000 || depth>50)return;visited++;
        Rect b=new Rect();node.getBoundsInScreen(b);
        xml.startTag(null,"node");
        attr(xml,"text",node.getText());attr(xml,"content-desc",node.getContentDescription());
        attr(xml,"resource-id",node.getViewIdResourceName());attr(xml,"class",node.getClassName());attr(xml,"package",node.getPackageName());
        attr(xml,"bounds","["+b.left+","+b.top+"]["+b.right+","+b.bottom+"]");
        attr(xml,"clickable",Boolean.toString(node.isClickable()));attr(xml,"enabled",Boolean.toString(node.isEnabled()));
        attr(xml,"checked",Boolean.toString(node.isChecked()));attr(xml,"checkable",Boolean.toString(node.isCheckable()));
        for(int i=0;i<node.getChildCount() && visited<5000;i++) {
            AccessibilityNodeInfo child=node.getChild(i);if(child==null)continue;
            try {write(xml,child,depth+1);}finally {child.recycle();}
        }
        xml.endTag(null,"node");
    }
    private void attr(XmlSerializer xml,String name,CharSequence input)throws Exception {
        String s=input==null?"":input.toString();StringBuilder safe=new StringBuilder();
        for(int i=0;i<s.length();) {int c=s.codePointAt(i);i+=Character.charCount(c);
            if(c==9||c==10||c==13||(c>=32&&c<=0xd7ff)||(c>=0xe000&&c<=0xfffd)||(c>=0x10000&&c<=0x10ffff))safe.appendCodePoint(c);
        }
        xml.attribute(null,name,safe.toString());
    }
}
