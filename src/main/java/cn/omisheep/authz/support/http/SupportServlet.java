package cn.omisheep.authz.support.http;

import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.cache.Cache;
import cn.omisheep.authz.core.config.Constants;
import cn.omisheep.authz.core.util.IPUtils;
import cn.omisheep.authz.core.util.Utils;
import cn.omisheep.authz.support.entity.Docs;
import cn.omisheep.authz.support.entity.User;
import cn.omisheep.authz.support.http.handler.ApiHandler;
import cn.omisheep.authz.support.util.IPAddress;
import cn.omisheep.authz.support.util.IPRange;
import cn.omisheep.authz.support.util.IPRangeMeta;
import cn.omisheep.authz.support.util.SupportUtils;
import cn.omisheep.commons.util.UUIDBits;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@SuppressWarnings("serial")
@Slf4j
public class SupportServlet extends HttpServlet {

    private static final String        resourceRootPath = "support/http/dist";
    private static final String        resourcePath     = "support/http/dist" + Constants.DASHBOARD_STATIC_PREFIX;
    private static final String        nopermit         = "support/http/nopermit.html";
    private final        List<IPRange> allowList        = new ArrayList<>();
    private final        List<IPRange> denyList         = new ArrayList<>();
    private final        ApiHandler    apiHandler       = new ApiHandler();
    private final        boolean       requireLogin;
    private final        Cache         cache;
    private static final String        UUID             = "uuid";
    private static final String        USERNAME         = "username";
    private static final String        PASSWORD         = "password";
    private static final Set<User>     users            = new HashSet<>();

    public static boolean requireLogin() {
        return !users.isEmpty();
    }

    public SupportServlet(AuthzProperties.DashboardConfig dashboardConfig,
                          Cache cache) {
        this.cache = cache;

        this.requireLogin = !StringUtils.isEmpty(dashboardConfig.getUsername()) && !StringUtils.isEmpty(
                dashboardConfig.getPassword()) || !dashboardConfig.getUsers().isEmpty();

        try {
            allowList.addAll(IPRangeMeta.parse(dashboardConfig.getAllow()));
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }

        try {
            denyList.addAll(IPRangeMeta.parse(dashboardConfig.getDeny()));
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }

        users.addAll(dashboardConfig.getUsers().stream().map(User::new).collect(Collectors.toList()));
        String username = dashboardConfig.getUsername();
        String password = dashboardConfig.getPassword();
        String ip       = dashboardConfig.getIp();
        if (!StringUtils.isEmpty(username) && !StringUtils.isEmpty(password)) {
            users.add(new User(username, password, ip));
        }
    }

    @SuppressWarnings("all")
    public static User login(String username,
                             String password,
                             String ip,
                             Cache cache) {
        if (users.isEmpty()) {return null;}
        if (username == null || password == null) {return null;}

        try {
            if (users.stream().anyMatch(u -> StringUtils.equals(u.getUsername(), username)
                    && StringUtils.equals(u.getPassword(), password))) {
                User user = new User().setUsername(username)
                        .setPassword(password)
                        .setIp(HttpMeta.currentHttpMeta().getIp());
                user.setUuid(UUIDBits.getUUIDBits(16));
                HashMap<String, String> map = new HashMap<>();
                map.put("username", user.getUsername());
                map.put("ip", ip);
                cache.set(Constants.DASHBOARD_KEY_PREFIX.get() + user.getUuid(), map, 1, TimeUnit.HOURS);
                return user;
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    @SuppressWarnings("all")
    public static User auth(HttpServletRequest request,
                            Cache cache) {
        String ip;
        try {
            ip = HttpMeta.currentHttpMeta().getIp();
            if (ip == null) return null;
        } catch (Exception e) {
            return null;
        }
        String uuid1 = request.getHeader(UUID);
        String uuid  = uuid1 != null ? uuid1 : request.getParameter(UUID);
        HashMap<String, String> map = (HashMap<String, String>) cache.get(
                Constants.DASHBOARD_KEY_PREFIX.get() + uuid);
        if (map == null) return null;
        String username = map.get("username");
        if (username == null) {
            return login(request.getParameter(USERNAME),
                         request.getParameter(PASSWORD), ip, cache);
        } else {
            if (StringUtils.equals(ip, map.get("ip"))) {
                return new User().setUsername(username).setUuid(uuid);
            } else {
                cache.del(Constants.DASHBOARD_KEY_PREFIX.get() + uuid);
                return null;
            }
        }
    }

    @Override
    public void service(HttpServletRequest request,
                        HttpServletResponse response) throws ServletException, IOException {
        String contextPath = request.getContextPath();
        String servletPath = request.getServletPath();
        String requestURI  = request.getRequestURI();
        if (contextPath == null) {contextPath = Constants.EMPTY;}
        String uri = contextPath + servletPath;
        String path;
        if (Objects.equals(servletPath, Constants.DASHBOARD_HTML) || Objects.equals(servletPath,
                                                                                    Constants.DASHBOARD_LOGO)) {
            path = servletPath;
        } else {
            path = requestURI.substring(contextPath.length() + servletPath.length());
        }

        response.setCharacterEncoding("utf-8");

        if (!checkIp(request, response)) {
            return; // 检查ip
        }
        if (gotoIndex(contextPath, path, request, response)) {
            return; // 跳转匹配
        }

        if (Constants.DASHBOARD_API_PREFIX.equals(servletPath) && path.startsWith(Docs.VERSION_PATH)) {
            apiHandler.process(request, response, path, !requireLogin || auth(request, cache) != null);
            return;
        }

        returnResourceFile(path, uri, request, response);
    }

    private boolean checkIp(HttpServletRequest request,
                            HttpServletResponse response) throws IOException {
        try {
            if (!isPermittedRequest(request)) {
                nopermit(response);
                return false;
            }
        } catch (Exception e) {
            nopermit(response);
            return false;
        }
        return true;
    }

    private boolean gotoIndex(String contextPath,
                              String path,
                              HttpServletRequest request,
                              HttpServletResponse response) throws IOException {
        if ("".equals(path)) {
            if (contextPath.equals(Constants.EMPTY) || contextPath.equals(Constants.SLASH)) {
                sendRedirect(request, response, Constants.DASHBOARD_HTML);
            } else {
                sendRedirect(request, response, Constants.DASHBOARD_HTML);
            }
            return true;
        }
        if ("/".equals(path)) {
            sendRedirect(request, response, "authz.html");
            return true;
        }
        return false;
    }

    private void nopermit(HttpServletResponse response) throws IOException {
        response.setContentType("text/html; charset=utf-8");
        String text = SupportUtils.readFromResource(nopermit);
        if (text == null) {
            response.getWriter().write("");
            response.setStatus(404);
        } else {response.getWriter().write(text);}
    }

    private void returnResourceFile(String fileName,
                                    String uri,
                                    HttpServletRequest request,
                                    HttpServletResponse response) throws IOException {
        String filePath;
        if (Objects.equals(fileName, Constants.DASHBOARD_HTML)) {
            filePath = resourceRootPath + "/index.html";
        } else if (Objects.equals(fileName, Constants.DASHBOARD_LOGO)) {
            filePath = resourceRootPath + Constants.DASHBOARD_LOGO;
        } else {
            filePath = resourcePath + fileName;
        }

        if (filePath.endsWith(".html")) {
            response.setContentType("text/html; charset=utf-8");
        }

        if (Utils.isIgnoreSuffix(fileName, Constants.SUFFIX)) {
            byte[] bytes = SupportUtils.readByteArrayFromResource(filePath);
            if (bytes != null) {
                response.getOutputStream().write(bytes);
            }
            return;
        }

        String text = SupportUtils.readFromResource(filePath);
        if (text == null) {
            sendRedirect(request, response, uri + Constants.DASHBOARD_HTML);
            return;
        }
        if (fileName.endsWith(".css")) {
            response.setContentType("text/css;charset=utf-8");
        } else if (fileName.endsWith(".js")) {
            response.setContentType("text/javascript;charset=utf-8");
        } else if (fileName.endsWith(".svg")) {
            response.setContentType("image/svg+xml");
        }

        response.getWriter().write(text);
    }

    private boolean isPermittedRequest(HttpServletRequest request) {
        String ip = IPUtils.getIp(request);
        return isPermittedRequest(ip);
    }

    private boolean isPermittedRequest(String remoteAddress) {
        boolean ipV6 = remoteAddress != null && remoteAddress.indexOf(':') != -1;
        if (ipV6) {
            return "0:0:0:0:0:0:0:1".equals(remoteAddress) || (denyList.size() == 0 && allowList.size() == 0);
        }
        IPAddress ipAddress = new IPAddress(remoteAddress);
        for (IPRange range : denyList) {
            if (range.isIPAddressInRange(ipAddress)) {
                return false;
            }
        }
        if (allowList.size() > 0) {
            for (IPRange range : allowList) {
                if (range.isIPAddressInRange(ipAddress)) {
                    return true;
                }
            }
            return false;
        }
        return true;
    }

    private void sendRedirect(HttpServletRequest request,
                              HttpServletResponse response,
                              String path) throws IOException {
        Map<String, String[]> parameterMap = request.getParameterMap();
        if (parameterMap.isEmpty()) {
            response.sendRedirect(path);
            return;
        }
        StringBuilder                         builder  = new StringBuilder(path).append("?");
        Iterator<Map.Entry<String, String[]>> iterator = parameterMap.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<String, String[]> next = iterator.next();
            builder.append(next.getKey()).append("=").append(next.getValue()[0]);
            if (iterator.hasNext()) {
                builder.append("&");
            }
        }
        response.sendRedirect(builder.toString());
    }
}
