package cn.omisheep.authz.core.auth.ipf;

import cn.omisheep.authz.core.AuthzException;
import cn.omisheep.authz.core.ExceptionStatus;
import cn.omisheep.authz.core.auth.rpd.PermRolesMeta;
import cn.omisheep.authz.core.config.Constants;
import cn.omisheep.authz.core.tk.Token;
import cn.omisheep.authz.core.util.LogUtils;
import cn.omisheep.web.utils.HttpUtils;
import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;
import org.springframework.boot.logging.LogLevel;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Date;
import java.util.LinkedList;
import java.util.Set;
import java.util.stream.Collectors;

import static cn.omisheep.authz.core.util.LogUtils.export;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@Data
@SuppressWarnings("all")
public class HttpMeta {

    @JsonIgnore
    private final HttpServletRequest          request;
    private final String                      ip;
    private final String                      uri;
    private final String                      api;
    private       String                      servletPath;
    private final String                      method;
    private final String                      userAgent;
    private final String                      refer;
    private       String                      body;
    private final Date                        now;
    private       Token                       token;
    private       Object                      userId;
    private       boolean                     hasToken;
    private       Set<String>                 roles;
    private       Set<String>                 permissions;
    private       boolean                     requireProtect;
    private       boolean                     requireLogin;
    private       PermRolesMeta               permRolesMeta;
    private       boolean                     ignore              = false;
    @JsonIgnore
    private       LinkedList<Object>          exceptionObjectList = new LinkedList<>();
    @JsonIgnore
    private       LinkedList<ExceptionStatus> exceptionStatusList = new LinkedList<>();

    public HttpMeta setRoles(Set<String> roles) {
        if (roles == null) return this;
        this.roles = roles;
        return this;
    }

    public HttpMeta setPermissions(Set<String> permissions) {
        if (permissions == null) return this;
        this.permissions = permissions;
        return this;
    }

    public static Token currentToken() {
        try {
            return ((HttpMeta) HttpUtils.getCurrentRequest().getAttribute(Constants.HTTP_META)).token;
        } catch (Exception e) {
            return null;
        }
    }

    public static Object currentUserId() {
        try {
            return currentToken().getUserId();
        } catch (Exception e) {
            return null;
        }
    }

    public HttpMeta error(AuthzException authzException) {
        if (authzException == null) return this;
        return error(authzException.getExceptionStatus());
    }

    public HttpMeta error(ExceptionStatus exceptionStatus) {
        if (exceptionStatus != null) this.exceptionStatusList.add(exceptionStatus);
        return this;
    }

    public HttpMeta clearError() {
        this.exceptionStatusList.clear();
        return this;
    }

    public void log(String formatMsg, Object... args) {
        LogUtils.push(LogLevel.INFO, formatMsg, args);
    }

    public void log(LogLevel logLevel, String formatMsg, Object... args) {
        LogUtils.push(logLevel, formatMsg, args);
    }

    public void exportLog() {
        export();
    }

    public boolean setHasToken(boolean hasToken) {
        this.hasToken = hasToken;
        return hasToken;
    }

    /**
     * post?????????
     * ???????????????httpRequest??????????????????body?????????????????????????????????????????????body
     *
     * @return ?????????
     */
    public String getBody() {
        if (!"POST".equals(method) || StringUtils.startsWithIgnoreCase(request.getContentType(), "multipart/")) {
            return null;
        }
        if (body == null) {
            try {
                body = new BufferedReader(new InputStreamReader(request.getInputStream()))
                        .lines().collect(Collectors.joining(System.lineSeparator()));
            } catch (IOException e) {
                LogUtils.error("read body error");
                return null;
            }
        }
        return body;
    }

    public void setToken(Token token) {
        if (this.token == null) {
            this.token  = token;
            this.userId = token.getUserId();
        }
    }

    public HttpMeta(HttpServletRequest request, String ip, String uri, String api,
                    String method, Date now) {
        this.request   = request;
        this.refer     = request.getHeader("Referer");
        this.ip        = ip;
        this.uri       = uri;
        this.api       = api;
        this.method    = method.toUpperCase();
        this.userAgent = request.getHeader("user-agent");
        this.now      = now;
    }

    public boolean isMethod(String method) {
        if (method != null) {
            return this.method.equals(method.toUpperCase());
        }
        return false;
    }

}