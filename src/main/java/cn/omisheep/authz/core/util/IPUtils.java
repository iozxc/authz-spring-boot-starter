package cn.omisheep.authz.core.util;

import cn.omisheep.authz.core.config.Constants;

import javax.servlet.http.HttpServletRequest;

public class IPUtils {

    private IPUtils() {
        throw new UnsupportedOperationException();
    }

    public static String getIp(HttpServletRequest request) {
        String ip = null;
        for (String ipHeader : IP_HEADERS) {
            ip = request.getHeader(ipHeader);
            if (!check(ip)) break;
        }
        if (check(ip)) ip = request.getRemoteAddr();
        if (ip.length() > 15 && !ip.contains(":")) {
            String[] ips = ip.split(Constants.COMMA);
            for (int i = ips.length - 1; i >= 0; i--) {
                if (!UNKNOWN.equalsIgnoreCase(ips[i].trim())) {
                    ip = ips[i].trim();
                    break;
                }
            }
        }
        return LOCAL_V6.equals(ip) ? LOCAL : ip;
    }

    private static boolean check(String ip) {
        return ip == null || ip.length() == 0 || UNKNOWN.equalsIgnoreCase(ip);
    }

    private static final String   UNKNOWN    = "unknown";
    private static final String   LOCAL      = "127.0.0.1";
    private static final String   LOCAL_V6   = "0:0:0:0:0:0:0:1";
    private static final String[] IP_HEADERS = {"x-forwarded-for", "Proxy-Client-IP", "WL-Proxy-Client-IP", "HTTP_CLIENT_IP", "HTTP_X_FORWARDED_FOR", "X-Real-IP"};

}