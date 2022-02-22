package cn.omisheep.authz.core.auth.ipf;

import cn.omisheep.authz.core.tk.Token;
import cn.omisheep.authz.core.util.LogUtils;
import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;

import javax.servlet.http.HttpServletRequest;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Date;
import java.util.stream.Collectors;

/**
 * @author zhou xin chen
 */
@Data
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
    private TokenException tokenException;
    private boolean hasTokenCookie;

    public enum TokenException {
        ExpiredJwtException,
        MalformedJwtException,
        SignatureException
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