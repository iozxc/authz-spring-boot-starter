package cn.omisheep.authz.support.http;

import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.cache.Cache;
import cn.omisheep.authz.core.config.Constants;
import cn.omisheep.authz.core.util.IPUtils;
import cn.omisheep.authz.core.util.ScanUtils;
import cn.omisheep.authz.core.util.Utils;
import cn.omisheep.authz.support.http.handler.WebHandler;
import cn.omisheep.authz.support.util.IPAddress;
import cn.omisheep.authz.support.util.IPRange;
import cn.omisheep.authz.support.util.IPRangeMeta;
import cn.omisheep.authz.support.util.SupportUtils;
import io.jsonwebtoken.lang.Classes;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@SuppressWarnings("serial")
@Slf4j
public class SupportServlet extends HttpServlet {

    private static final String                resourcePath = "support/http/dist";
    private final        List<IPRange>         allowList    = new ArrayList<>();
    private final        List<IPRange>         denyList     = new ArrayList<>();
    private final        ArrayList<WebHandler> webHandlers  = new ArrayList<>();
    private final        boolean               requireLogin;
    private final        String                baseMapping;
    private final        Cache                 cache;

    public SupportServlet(AuthzProperties.DashboardConfig dashboardConfig, Cache cache) {
        String mappings = dashboardConfig.getMappings();
        this.cache = cache;

        this.requireLogin = !StringUtils.isEmpty(dashboardConfig.getUsername()) && !StringUtils.isEmpty(dashboardConfig.getPassword()) || !dashboardConfig.getUsers().isEmpty();

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

        String val = mappings.substring(0, mappings.indexOf("/*"));
        if (!mappings.startsWith("/")) {
            baseMapping = val;
        } else {
            baseMapping = val.substring(1);
        }

        for (String name : ScanUtils.scan(WebHandler.class, "cn.omisheep.authz.support.http")) {
            webHandlers.add(Classes.newInstance(name));
        }
    }

    @Override
    public void service(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String contextPath = request.getContextPath();
        String servletPath = request.getServletPath();
        String requestURI  = request.getRequestURI();
        if (contextPath == null) contextPath = "";
        String uri  = contextPath + servletPath;
        String path = requestURI.substring(contextPath.length() + servletPath.length());

        response.setCharacterEncoding("utf-8");

        if (!checkIp(request, response)) return; // 检查ip
        if (gotoIndex(contextPath, path, response)) return; // 跳转匹配

        if (path.startsWith("/v1")) {
            String uuid1    = request.getHeader("uuid");
            String uuid     = uuid1 != null ? uuid1 : request.getParameter("uuid");
            Object username = cache.get(Constants.DASHBOARD_KEY_PREFIX.get() + uuid);
            process(request, response, path, !requireLogin || username != null);
            return;
        }

        returnResourceFile(path, uri, response);
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

    private boolean gotoIndex(String contextPath, String path, HttpServletResponse response) throws IOException {
        if ("".equals(path)) {
            if (contextPath.equals("") || contextPath.equals("/")) {
                response.sendRedirect("/" + baseMapping + "/index.html");
            } else {
                response.sendRedirect(baseMapping + "/index.html");
            }
            return true;
        }
        if ("/".equals(path)) {
            response.sendRedirect("index.html");
            return true;
        }
        return false;
    }

    private void process(HttpServletRequest request, HttpServletResponse response, String path, boolean auth) {
        webHandlers.stream().filter(v -> v.requireLogin() && auth && v.match(path) || !v.requireLogin() && v.match(path)).forEach(v -> v.process(request, response, (HttpMeta) request.getAttribute(Constants.HTTP_META), path, auth));
    }

    private void nopermit(HttpServletResponse response) throws IOException {
        response.setContentType("text/html; charset=utf-8");
        String text = SupportUtils.readFromResource("support/http/nopermit.html");
        if (text == null) {
            response.getWriter().write("");
            response.setStatus(404);
        } else response.getWriter().write(text);
    }

    private void returnResourceFile(String fileName, String uri, HttpServletResponse response) throws IOException {
        String filePath = resourcePath + fileName;

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
            response.sendRedirect(uri + "/index.html");
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

}
