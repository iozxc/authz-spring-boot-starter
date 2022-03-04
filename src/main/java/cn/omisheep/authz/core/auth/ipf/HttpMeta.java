package cn.omisheep.authz.core.auth.ipf;

import cn.omisheep.authz.core.AuthzException;
import cn.omisheep.authz.core.Constants;
import cn.omisheep.authz.core.ExceptionStatus;
import cn.omisheep.authz.core.tk.Token;
import cn.omisheep.authz.core.util.LogUtils;
import cn.omisheep.commons.util.HttpUtils;
import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;

import javax.servlet.http.HttpServletRequest;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Date;
import java.util.stream.Collectors;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
@Data
@SuppressWarnings("all")
public class HttpMeta {

    @JsonIgnore
    private final HttpServletRequest request;
    private final String ip;
    private final String uri;
    private final String api;
    private final String method;
    private final String userAgent;
    private final String refer;
    private String body;
    private final Date date;
    private Token token;
    private Object userId;
    private TokenException tokenException;
    private boolean hasTokenCookie;
    private AuthzException authzException;

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
        this.authzException = authzException;
        return this;
    }

    public HttpMeta error(ExceptionStatus exceptionStatus) {
        return error(new AuthzException(null, exceptionStatus));
    }

    public HttpMeta error(ExceptionStatus exceptionStatus, Throwable e) {
        return error(new AuthzException(e, exceptionStatus));
    }

    public enum TokenException {
        ExpiredJwtException,
        MalformedJwtException,
        SignatureException
    }

    public boolean setHasTokenCookie(boolean hasTokenCookie) {
        this.hasTokenCookie = hasTokenCookie;
        return hasTokenCookie;
    }

    /**
     * post时生效
     * 从包装过的httpRequest中读取，读取body行为只进行一次，读取之后会备份body
     *
     * @return 请求体
     */
    public String getBody() {
        if (!"POST".equals(method)) {
            return null;
        }
        if (body == null) {
            try {
                body = new BufferedReader(new InputStreamReader(request.getInputStream()))
                        .lines().collect(Collectors.joining(System.lineSeparator()));
            } catch (IOException e) {
                LogUtils.logError("read body error");
                return null;
            }
        }
        return body;
    }

    public void setToken(Token token) {
        if (this.token == null) {
            this.token = token;
            this.userId = token.getUserId();
        }
    }

    public HttpMeta(HttpServletRequest request, String ip, String uri, String api,
                    String method, Date date) {
        this.request = request;
        this.refer = request.getHeader("Referer");
        this.ip = ip;
        this.uri = uri;
        this.api = api;
        this.method = method.toUpperCase();
        this.userAgent = request.getHeader("user-agent");
        this.date = date;
    }

    public boolean isMethod(String method) {
        if (method != null) {
            return this.method.equals(method.toUpperCase());
        }
        return false;
    }

}