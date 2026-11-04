package cn.civi.adshield;

import android.content.Context;
import cn.civi.adshield.core.AdGuardDnsRules;
import javax.net.ssl.HttpsURLConnection;
import java.io.*;
import java.net.URL;

/** Explicit, user-started HTTPS update of the official DNS subscription. */
public final class AdGuardSubscription {
    public static final String URL_TEXT="https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt";
    private AdGuardSubscription() {}
    public static AdGuardDnsRules update(Context c)throws IOException {
        HttpsURLConnection connection=(HttpsURLConnection)new URL(URL_TEXT).openConnection();
        connection.setConnectTimeout(10000);connection.setReadTimeout(20000);
        connection.setInstanceFollowRedirects(false);connection.setRequestProperty("User-Agent","CiviAdShield-DNS-rules");
        try {
            if(connection.getResponseCode()!=200)throw new IOException("官方订阅返回 HTTP "+connection.getResponseCode()+"，保留当前规则");
            if(connection.getContentLengthLong()>RulesStore.MAX_BYTES)throw new IOException("订阅超过 8 MB，保留当前规则");
            String text;try(InputStream in=connection.getInputStream()){text=RulesStore.readLimited(in);}
            if(!text.contains("! Title: AdGuard DNS filter"))throw new IOException("订阅标题不符，保留当前规则");
            return RulesStore.installAdGuard(c,text,"official-update");
        } finally {connection.disconnect();}
    }
}
