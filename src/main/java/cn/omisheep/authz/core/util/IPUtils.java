package cn.omisheep.authz.core.util;

import cn.omisheep.authz.core.config.Constants;

import javax.servlet.http.HttpServletRequest;

public class IPUtils {
    public static String getIp(HttpServletRequest request) {
        String ip = request.getHeader(X_FORWARDED_FOR);
        if (ip == null || ip.length() == 0 || UNKNOWN.equalsIgnoreCase(ip)) {
            if (ip == null || ip.length() == 0 || UNKNOWN.equalsIgnoreCase(ip)) {
                ip = request.getHeader(PROXY_CLIENT_IP);
            }
            if (ip == null || ip.length() == 0 || UNKNOWN.equalsIgnoreCase(ip)) {
                ip = request.getHeader(WL_PROXY_CLIENT_IP);
            }
            if (ip == null || ip.length() == 0 || UNKNOWN.equalsIgnoreCase(ip)) {
                ip = request.getHeader(HTTP_CLIENT_IP);
            }
            if (ip == null || ip.length() == 0 || UNKNOWN.equalsIgnoreCase(ip)) {
                ip = request.getHeader(HTTP_X_FORWARDED_FOR);
            }
            if (ip == null || ip.length() == 0 || UNKNOWN.equalsIgnoreCase(ip)) {
                ip = request.getHeader(X_REAL_IP);
            }
            if (ip == null || ip.length() == 0 || UNKNOWN.equalsIgnoreCase(ip)) {
                ip = request.getRemoteAddr();
            }
        }
        if (ip.length() > 15) {
            String[] ips = ip.split(Constants.COMMA);
            for (int i = ips.length - 1; i >= 0; i--) {
                if (!UNKNOWN.equalsIgnoreCase(ips[i].trim())) {
                    ip = ips[i].trim();
                    break;
                }
            }
        }
        return ip.equals("0:0:0:0:0:0:0:1") ? "127.0.0.1" : ip;
    }

    private static final String UNKNOWN              = "unknown";
    private static final String CMMOa              = ",";
    private static final String X_FORWARDED_FOR      = "x-forwarded-for";
    private static final String PROXY_CLIENT_IP      = "Proxy-Client-IP";
    private static final String WL_PROXY_CLIENT_IP   = "WL-Proxy-Client-IP";
    private static final String HTTP_CLIENT_IP       = "HTTP_CLIENT_IP";
    private static final String HTTP_X_FORWARDED_FOR = "HTTP_X_FORWARDED_FOR";
    private static final String X_REAL_IP            = "X-Real-IP";
}