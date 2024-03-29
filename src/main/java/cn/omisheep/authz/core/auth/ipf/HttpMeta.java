package cn.omisheep.authz.core.auth.ipf;

import cn.omisheep.authz.annotation.ArgResource;
import cn.omisheep.authz.core.AuthzException;
import cn.omisheep.authz.core.ExceptionStatus;
import cn.omisheep.authz.core.LogLevel;
import cn.omisheep.authz.core.auth.deviced.UserDevicesDict;
import cn.omisheep.authz.core.auth.rpd.ParamMetadata;
import cn.omisheep.authz.core.auth.rpd.PermRolesMeta;
import cn.omisheep.authz.core.auth.rpd.PermissionDict;
import cn.omisheep.authz.core.config.AuthzAppVersion;
import cn.omisheep.authz.core.config.Constants;
import cn.omisheep.authz.core.helper.BaseHelper;
import cn.omisheep.authz.core.tk.AccessToken;
import cn.omisheep.authz.core.util.HttpUtils;
import cn.omisheep.authz.core.util.IPUtils;
import cn.omisheep.authz.core.util.LogUtils;
import cn.omisheep.commons.util.CollectionUtils;
import cn.omisheep.commons.util.web.ua.UserAgent;
import cn.omisheep.commons.util.web.ua.UserAgentParser;
import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.*;
import java.util.stream.Collectors;

import static cn.omisheep.authz.core.util.LogUtils.export;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@EqualsAndHashCode(callSuper = false)
@Data
@NoArgsConstructor
public class HttpMeta extends BaseHelper {

    private Date      now = new Date();
    private String    ip;
    private String    api;
    private String    path;
    private String    body;
    private UserAgent userAgent;

    private AccessToken token;
    private Object      userId;
    private Set<String> roles;
    private Set<String> permissions;
    private Set<String> scope;

    private String        controller;
    private PermRolesMeta permRolesMeta;
    private Boolean       hasApiAuth;
    private Boolean       hasParamAuth;
    private Boolean       requireLogin;

    @JsonIgnore
    private HttpServletRequest          request;
    @JsonIgnore
    private boolean                     clearCookie         = true;
    @JsonIgnore
    private UserDevicesDict.UserStatus  userStatus;
    @JsonIgnore
    private LinkedList<Object>          exceptionObjectList = new LinkedList<>();
    @JsonIgnore
    private LinkedList<ExceptionStatus> exceptionStatusList = new LinkedList<>();

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

    @NonNull
    @SuppressWarnings("unchecked")
    public Set<String> getRoles() {
        if (userId == null) return new HashSet<>();
        if (roles == null) {
            Collection<String> r = permLibrary.getRolesByUserId(userId);
            if (r instanceof Set) {roles = (Set<String>) r;} else roles = new HashSet<>(r);
        }
        return roles;
    }

    @NonNull
    @SuppressWarnings("unchecked")
    public Set<String> getPermissions() {
        if (userId == null) return new HashSet<>();
        permissions = Optional.ofNullable(permissions).orElseGet(() -> {
            HashSet<String> perms = new HashSet<>();
            for (String role : Optional.of(getRoles()).orElse(new HashSet<>())) {
                Collection<String> permissionsByRole = permLibrary.getPermissionsByRole(role);
                if (permissionsByRole != null) perms.addAll(permissionsByRole);
            }
            return perms;
        });
        return permissions;
    }

    @NonNull
    public Set<String> getScope() {
        if (token == null) return new HashSet<>();
        scope = Optional.ofNullable(scope).orElseGet(() -> {
            String s = token.getScope();
            if (s == null || s.equals("")) return new HashSet<>();
            return CollectionUtils.ofSet(s.split(AuthzAppVersion.SCOPE_SEPARATOR.get()));
        });
        return scope;
    }

    @ArgResource(value = "httpMeta", description = "当前请求的HttpMeta")
    public static HttpMeta currentHttpMeta() {
        try {
            return ((HttpMeta) HttpUtils.getCurrentRequest().getAttribute(Constants.HTTP_META));
        } catch (Exception e) {
            return null;
        }
    }

    @ArgResource(value = "token", description = "当前请求的Token")
    public static AccessToken currentToken() {
        try {
            return currentHttpMeta().token;
        } catch (Exception e) {
            return null;
        }
    }

    @ArgResource(value = "userId", description = "当前请求的userId")
    public static Object currentUserId() {
        try {
            return currentToken().getUserId();
        } catch (NullPointerException e) {
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

    public void log(String formatMsg,
                    Object... args) {
        LogUtils.push(LogLevel.INFO, formatMsg, args);
    }

    public void log(LogLevel logLevel,
                    String formatMsg,
                    Object... args) {
        LogUtils.push(logLevel, formatMsg, args);
    }

    public void exportLog() {
        export();
    }

    /**
     * post时生效
     * 从包装过的httpRequest中读取，读取body行为只进行一次，读取之后会备份body
     *
     * @return 请求体
     */
    public String getBody() {
        if (!"POST".equals(getMethod()) || StringUtils.startsWithIgnoreCase(request.getContentType(), "multipart/")) {
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

    public void setToken(AccessToken token) {
        if (this.token == null && token != null) {
            this.token  = token;
            this.userId = token.getUserId();
        }
    }

    public boolean hasToken() {
        return this.token != null;
    }

    public HttpMeta(HttpServletRequest request,
                    String api,
                    String path) {
        this.request = request;
        this.ip      = IPUtils.getIp(request);
        this.api     = api;
        this.path    = path;
    }

    public boolean isMethod(String method) {
        if (method != null) {
            return getMethod().equals(method.toUpperCase());
        }
        return false;
    }

    public boolean isHasApiAuth() {
        if (hasApiAuth != null) return hasApiAuth;
        Map<String, PermRolesMeta> map            = PermissionDict.getRolePermission().get(api);
        PermRolesMeta              cPermRolesMeta = PermissionDict.getControllerRolePermission().get(controller);
        if (map == null && cPermRolesMeta == null) {
            hasApiAuth = false;
            return false;
        }

        if (map != null) {
            PermRolesMeta permRolesMeta = map.get(getMethod());
            hasApiAuth = (permRolesMeta != null && !permRolesMeta.non()) || (cPermRolesMeta != null && !cPermRolesMeta.non());
        } else {
            hasApiAuth = !cPermRolesMeta.non();
        }

        return hasApiAuth;
    }

    public boolean isHasParamAuth() {
        if (hasParamAuth != null) return requireLogin;
        Map<String, Map<String, ParamMetadata>> map = PermissionDict.getParamPermission()
                .get(api);
        if (map == null || map.get(getMethod()) == null) {
            hasParamAuth = false;
            return false;
        }
        hasParamAuth = map.get(getMethod()).values().stream().anyMatch(ParamMetadata::hasParamAuth);
        return hasParamAuth;
    }

    public boolean isRequireLogin() {
        if (requireLogin != null) return requireLogin;
        Set<String> list     = PermissionDict.getCertificatedMetadata().get(api);
        boolean     contains = PermissionDict.getControllerCertificatedMetadata().contains(controller);
        if (list == null || list.isEmpty()) {
            requireLogin = isHasApiAuth() || isHasParamAuth() || contains;
            return requireLogin;
        }
        requireLogin = contains || list.contains(getMethod()) || isHasApiAuth() || isHasParamAuth();
        return requireLogin;
    }

    public String getUri() {
        return request.getRequestURI();
    }

    public String getMethod() {
        return request.getMethod();
    }

    public String getServletPath() {
        return request.getServletPath();
    }

    public UserAgent getUserAgent() {
        if (userAgent == null) {
            userAgent = UserAgentParser.parse(request.getHeader("user-agent"));
        }
        return userAgent;
    }

    public String getReferer() {
        return request.getHeader("Referer");
    }

}