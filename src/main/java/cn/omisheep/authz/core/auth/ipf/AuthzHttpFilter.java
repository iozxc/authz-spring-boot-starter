package cn.omisheep.authz.core.auth.ipf;

import cn.omisheep.authz.core.ExceptionStatus;
import cn.omisheep.authz.core.AuthzContext;
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

import static cn.omisheep.authz.core.config.Constants.*;
import static cn.omisheep.authz.core.util.Utils.isIgnoreSuffix;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@Slf4j
@SuppressWarnings("all")
public class AuthzHttpFilter extends OncePerRequestFilter {

    private final boolean isDashboard;

    public AuthzHttpFilter(boolean isDashboard) {
        this.isDashboard = isDashboard;
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

        String uri         = request.getRequestURI();
        String method      = request.getMethod();
        String contextPath = request.getContextPath();
        String servletPath = request.getServletPath();

        HttpUtils.request.set(request);

        if (isIgnoreSuffix(uri, Httpd.getIgnoreSuffix()) || (isDashboard && (servletPath.equals(
                DASHBOARD_LOGO) || servletPath.startsWith(DASHBOARD_API_PREFIX) || servletPath.startsWith(
                DASHBOARD_STATIC_PREFIX) || servletPath.startsWith(DASHBOARD_HTML)))) {
            HttpMeta httpMeta = new HttpMeta(request, uri, null, method, uri);
            request.setAttribute(HTTP_META, httpMeta);
            filterChain.doFilter(request, response);
            AuthzContext.httpMeta.set(httpMeta);
            return;
        }

        String   api      = Httpd.getPattern(method, servletPath);
        HttpMeta httpMeta = new HttpMeta(request, uri, api == null ? servletPath : api, method, servletPath);
        if (api == null) {
            httpMeta.error(ExceptionStatus.MISMATCHED_URL);
        }
        AuthzContext.httpMeta.set(httpMeta);
        request.setAttribute(HTTP_META, httpMeta);
        filterChain.doFilter(request, response);
    }

}

