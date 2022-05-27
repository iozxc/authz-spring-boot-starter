package cn.omisheep.authz.support.http;

import cn.omisheep.authz.core.Authz;
import cn.omisheep.authz.core.Constants;
import cn.omisheep.authz.core.VersionInfo;
import cn.omisheep.authz.core.auth.AuthzModifier;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.util.Utils;
import cn.omisheep.authz.support.util.IPAddress;
import cn.omisheep.authz.support.util.IPRange;
import cn.omisheep.authz.support.util.IPRangeMeta;
import cn.omisheep.authz.support.util.SupportUtils;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
@SuppressWarnings("serial")
@Slf4j
public class SupportServlet extends HttpServlet {

    public static final String SESSION_USER_KEY = "authz-dashboard-user";

    public static final String PARAM_NAME_USERNAME = "username";
    public static final String PARAM_NAME_PASSWORD = "password";
    public static final String PARAM_NAME_ALLOW    = "allow";
    public static final String PARAM_NAME_DENY     = "deny";
    public static final String PARAM_REMOTE_ADDR   = "remoteAddress";

    protected String username = null;
    protected String password = null;

    protected List<IPRange> allowList = new ArrayList<>();
    protected List<IPRange> denyList  = new ArrayList<>();

    protected final String resourcePath;

    protected String mappings;
    protected String remoteAddressHeader = null;
    protected String baseMapping         = "";

    public SupportServlet(String resourcePath, String mappings) {
        this.resourcePath = resourcePath;
        this.mappings     = mappings;
    }

    public void init() throws ServletException {
        initAuthEnv();

        String val = mappings.substring(0, mappings.indexOf("/*"));
        if (!mappings.startsWith("/")) {
            baseMapping = val;
        } else {
            baseMapping = val.substring(1);
        }
    }

    private void initAuthEnv() {
        String paramUserName = getInitParameter(PARAM_NAME_USERNAME);
        if (!StringUtils.isEmpty(paramUserName)) {
            this.username = paramUserName;
        }

        String paramPassword = getInitParameter(PARAM_NAME_PASSWORD);
        if (!StringUtils.isEmpty(paramPassword)) {
            this.password = paramPassword;
        }

        String paramRemoteAddressHeader = getInitParameter(PARAM_REMOTE_ADDR);
        if (!StringUtils.isEmpty(paramRemoteAddressHeader)) {
            this.remoteAddressHeader = paramRemoteAddressHeader;
        }

        try {
            allowList.addAll(IPRangeMeta.parse(getInitParameter(PARAM_NAME_ALLOW)));
        } catch (Exception e) {
            String msg = "initParameter config error, allow : " + getInitParameter(PARAM_NAME_ALLOW);
            log.error(msg, e);
        }

        try {
            denyList.addAll(IPRangeMeta.parse(getInitParameter(PARAM_NAME_DENY)));
        } catch (Exception e) {
            String msg = "initParameter config error, deny : " + getInitParameter(PARAM_NAME_DENY);
            log.error(msg, e);
        }
    }

    public void service(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String contextPath = request.getContextPath();
        String servletPath = request.getServletPath();
        String requestURI  = request.getRequestURI();

        response.setCharacterEncoding("utf-8");

        if (contextPath == null) { // root context
            contextPath = "";
        }

        String uri  = contextPath + servletPath;
        String path = requestURI.substring(contextPath.length() + servletPath.length());

        // ip权限检查
        if (!isPermittedRequest(request)) {
            path = "/nopermit.html";
            returnResourceFile(path, uri, response);
            return;
        }

        // 登录判断
        if ("/submitLogin".equals(path)) {
            HttpMeta httpMeta = (HttpMeta) request.getAttribute(Constants.HTTP_META);
            try {
                JSONObject object = JSON.parseObject(httpMeta.getBody());
                if (object == null) {
                    response.getWriter().print("error");
                    return;
                }
                String usernameParam = object.getString(PARAM_NAME_USERNAME);
                String passwordParam = object.getString(PARAM_NAME_PASSWORD);

                if (username.equals(usernameParam) && password.equals(passwordParam)) {
                    request.getSession().setAttribute(SESSION_USER_KEY, username);
                    response.getWriter().print("success");
                } else {
                    response.getWriter().print("error");
                }
                return;
            } catch (Exception e) {
                response.getWriter().print("error");
                return;
            }
        }

        // 权限判断
        if (isRequireAuth() // 如果不需要验证
                && !ContainsUser(request)//
                && !("/login.html".equals(path)
                || path.startsWith("/css")
                || path.startsWith("/js")
                || path.startsWith("/img") || path.equals("/favicon.ico"))
        ) {
            if (path.startsWith("/api")) {
                response.getWriter().println("error");
                return;
            }
            if (contextPath.equals("") || contextPath.equals("/")) {
                response.sendRedirect("/" + baseMapping + "/login.html");
            } else {
                if ("".equals(path)) {
                    response.sendRedirect(baseMapping + "/login.html");
                } else {
                    response.sendRedirect("login.html");
                }
            }
            return;
        }

        if ("".equals(path)) {
            if (contextPath.equals("") || contextPath.equals("/")) {
                response.sendRedirect("/" + baseMapping + "/index.html");
            } else {
                response.sendRedirect(baseMapping + "/index.html");
            }
            return;
        }

        if ("/".equals(path)) {
            response.sendRedirect("index.html");
            return;
        }

        if (path.startsWith("/api")) {
            interpretation(path.substring(4), request, response);
            return;
        }

        returnResourceFile(path, uri, response);
    }

    protected String getFilePath(String fileName) {
        return resourcePath + fileName;
    }

    // 是否需要登录
    public boolean isRequireAuth() {
        return this.username != null;
    }

    // 是否有用户
    public boolean ContainsUser(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        return session != null && session.getAttribute(SESSION_USER_KEY) != null;
    }

    protected void interpretation(String api, HttpServletRequest request, HttpServletResponse response) throws IOException {
        HttpMeta httpMeta = (HttpMeta) request.getAttribute(Constants.HTTP_META);
        response.setContentType("application/json;charset=utf-8");

        if ("/modify".equals(api)) {
            AuthzModifier authzModifier = JSON.parseObject(httpMeta.getBody(), AuthzModifier.class);
            response.getWriter().println(JSON.toJSONString(Authz.operate(authzModifier)));
        } else if ("/info".equals(api)) {
            response.getWriter().println(JSON.toJSONString(VersionInfo.getVersion()));
        }

    }

    protected void returnResourceFile(String fileName, String uri, HttpServletResponse response)
            throws IOException {

        String filePath = getFilePath(fileName);

        if (filePath.endsWith(".html")) {
            response.setContentType("text/html; charset=utf-8");
        }


        if (Utils.isIgnoreSuffix(fileName, ".jpg", ".png", ".gif")) {
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

    public boolean isPermittedRequest(String remoteAddress) {
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

    public boolean isPermittedRequest(HttpServletRequest request) {
        String remoteAddress = getRemoteAddress(request);
        return isPermittedRequest(remoteAddress);
    }

    protected String getRemoteAddress(HttpServletRequest request) {
        String remoteAddress = null;

        if (remoteAddressHeader != null) {
            remoteAddress = request.getHeader(remoteAddressHeader);
        }

        if (remoteAddress == null) {
            remoteAddress = request.getRemoteAddr();
        }

        return remoteAddress;
    }

}
