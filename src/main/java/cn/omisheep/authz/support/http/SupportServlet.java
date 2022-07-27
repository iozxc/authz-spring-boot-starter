package cn.omisheep.authz.support.http;

import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.cache.Cache;
import cn.omisheep.authz.core.config.Constants;
import cn.omisheep.authz.core.util.IPUtils;
import cn.omisheep.authz.core.util.Utils;
import cn.omisheep.authz.support.entity.User;
import cn.omisheep.authz.support.http.handler.ApiHandler;
import cn.omisheep.authz.support.util.IPAddress;
import cn.omisheep.authz.support.util.IPRange;
import cn.omisheep.authz.support.util.IPRangeMeta;
import cn.omisheep.authz.support.util.SupportUtils;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@SuppressWarnings("serial")
@Slf4j
public class SupportServlet extends HttpServlet {

    private static final String        resourceRootPath = "support/http/dist";
    private static final String        resourcePath     = "support/http/dist/authz-dashboard";
    private final        List<IPRange> allowList        = new ArrayList<>();
    private final        List<IPRange> denyList         = new ArrayList<>();
    private final        ApiHandler    apiHandler       = new ApiHandler();
    private final        boolean       requireLogin;
    private final        Cache         cache;

    private final static Set<User> users = new HashSet<>();

    public static boolean requireLogin() {
        return !users.isEmpty();
    }

    public SupportServlet(AuthzProperties.DashboardConfig dashboardConfig, Cache cache) {
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

        users.addAll(dashboardConfig.getUsers());
        String username = dashboardConfig.getUsername();
        String password = dashboardConfig.getPassword();
        if (!StringUtils.isEmpty(username) && !StringUtils.isEmpty(password)) {
            users.add(new User().setUsername(username).setPassword(password));
        }
    }

    public static User login(String username, String password) {
        if (users.isEmpty()) return null;
        if (username == null || password == null) return null;
        if (users.stream().anyMatch(
                u -> StringUtils.equals(u.getUsername(), username) && StringUtils.equals(u.getPassword(), password))) {
            return new User().setUsername(username).setPassword(password);
        }
        return null;
    }

    public static User auth(HttpServletRequest request, Cache cache) {
        String uuid1    = request.getHeader("uuid");
        String uuid     = uuid1 != null ? uuid1 : request.getParameter("uuid");
        Object username = cache.get(Constants.DASHBOARD_KEY_PREFIX.get() + uuid);
        if (username == null) {
            String username1 = request.getParameter("username");
            String password1 = request.getParameter("password");
            return login(username1, password1);
        } else {
            return new User().setUsername((String) username).setUuid(uuid);
        }
    }

    @Override
    public void service(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String contextPath = request.getContextPath();
        String servletPath = request.getServletPath();
        String requestURI  = request.getRequestURI();
        if (contextPath == null) contextPath = "";
        String uri = contextPath + servletPath;
        String path;
        if (Objects.equals(servletPath, "/authz.html")) {
            path = servletPath;
        } else {
            path = requestURI.substring(contextPath.length() + servletPath.length());
        }

        response.setCharacterEncoding("utf-8");

        if (!checkIp(request, response)) return; // 检查ip
        if (gotoIndex(contextPath, path, request, response)) return; // 跳转匹配

        if ("/authz-api".equals(servletPath) && path.startsWith("/v1")) {
            apiHandler.process(request, response, path, !requireLogin || auth(request, cache) != null);
            return;
        }

        returnResourceFile(path, uri, request, response);
    }

    private boolean checkIp(HttpServletRequest request, HttpServletResponse response) throws IOException {
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

    private boolean gotoIndex(String contextPath, String path, HttpServletRequest request,
                              HttpServletResponse response) throws IOException {
        if ("".equals(path)) {
            if (contextPath.equals("") || contextPath.equals("/")) {
                sendRedirect(request, response, "/authz.html");
            } else {
                sendRedirect(request, response, "/authz.html");
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
        String text = SupportUtils.readFromResource("support/http/nopermit.html");
        if (text == null) {
            response.getWriter().write("");
            response.setStatus(404);
        } else response.getWriter().write(text);
    }

    private void returnResourceFile(String fileName, String uri, HttpServletRequest request,
                                    HttpServletResponse response) throws IOException {
        String filePath;
        if (Objects.equals(fileName, "/authz.html")) {
            filePath = resourceRootPath + "/index.html";
        } else if (Objects.equals(fileName, "/favicon.ico")) {
            filePath = resourceRootPath + "/favicon.ico";
        } else {
            filePath = resourcePath + fileName;
        }


        if (filePath.endsWith(".html")) {
            response.setContentType("text/html; charset=utf-8");
        }

        if (Utils.isIgnoreSuffix(fileName, ".ico", ".jpg", ".png", ".gif")) {
            byte[] bytes = SupportUtils.readByteArrayFromResource(filePath);
            if (bytes != null) {
                response.getOutputStream().write(bytes);
            }
            return;
        }

        String text = SupportUtils.readFromResource(filePath);
        if (text == null) {
            sendRedirect(request, response, uri + "/authz.html");
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

    private void sendRedirect(HttpServletRequest request, HttpServletResponse response,
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
