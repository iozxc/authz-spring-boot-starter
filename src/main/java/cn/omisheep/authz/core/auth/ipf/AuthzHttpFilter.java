package cn.omisheep.authz.core.auth.ipf;

import cn.omisheep.authz.core.ExceptionStatus;
import cn.omisheep.authz.core.util.IPUtils;
import cn.omisheep.web.utils.BufferedServletRequestWrapper;
import cn.omisheep.web.utils.HttpUtils;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

import static cn.omisheep.authz.core.config.Constants.HTTP_META;
import static cn.omisheep.authz.core.util.Utils.isIgnoreSuffix;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@Slf4j
@SuppressWarnings("all")
public class AuthzHttpFilter extends OncePerRequestFilter {

    private final Httpd   httpd;
    private final boolean isDashboard;
    private final String  mappings;

    public AuthzHttpFilter(Httpd httpd, boolean isDashboard, String mappings) {
        this.httpd       = httpd;
        this.isDashboard = isDashboard;
        String val = mappings.substring(0, mappings.indexOf("/*"));
        if (!mappings.startsWith("/")) {
            this.mappings = "/" + val;
        } else {
            this.mappings = val;
        }
    }

    @Override
    public void doFilterInternal(HttpServletRequest rrequest,
                                 HttpServletResponse response,
                                 FilterChain filterChain) throws ServletException, IOException {
        HttpServletRequest request;
        if (StringUtils.startsWithIgnoreCase(rrequest.getContentType(), "multipart/")) {
            request = rrequest;
        } else {
            request = new BufferedServletRequestWrapper(rrequest);
        }

        String ip          = IPUtils.getIp(request);
        String uri         = request.getRequestURI();
        String method      = request.getMethod();
        String contextPath = request.getContextPath();
        long   now         = new Date().getTime();
        String servletPath = request.getServletPath();

        HttpUtils.request.set(request);

        if (isIgnoreSuffix(uri, httpd.getIgnoreSuffix()) || (isDashboard && uri.startsWith(mappings))) {
            HttpMeta httpMeta = new HttpMeta(
                    request,
                    ip, uri, servletPath, method, new Date());
            httpMeta.setIgnore(true);
            request.setAttribute(HTTP_META, httpMeta);
            httpMeta.setServletPath(servletPath);
            httpMeta.setPath(servletPath);
            filterChain.doFilter(request, response);
            return;
        }

        String api = httpd.getPattern(method, servletPath);
        HttpMeta httpMeta = new HttpMeta(
                request, ip, uri,
                api == null ? servletPath : api, method, new Date());
        if (api == null) {
            httpMeta.error(ExceptionStatus.MISMATCHED_URL);
        }

        httpMeta.setServletPath(servletPath);
        httpMeta.setPath(servletPath);
        request.setAttribute(HTTP_META, httpMeta);
        filterChain.doFilter(request, response);
    }

}

