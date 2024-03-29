package cn.omisheep.authz.core.auth.ipf;

import cn.omisheep.authz.core.AuthzContext;
import cn.omisheep.authz.core.ExceptionStatus;
import cn.omisheep.authz.core.util.HttpUtils;
import cn.omisheep.web.utils.BufferedServletRequestWrapper;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static cn.omisheep.authz.core.config.Constants.*;
import static cn.omisheep.authz.core.util.FormatUtils.isIgnoreSuffix;

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
        String servletPath = request.getServletPath();

        HttpUtils.currentRequest.set(request);
        HttpUtils.currentResponse.set(response);

        if (isIgnoreSuffix(uri, SUFFIX) || (isDashboard && (servletPath.equals(
                DASHBOARD_LOGO) || servletPath.startsWith(DASHBOARD_API_PREFIX) || servletPath.startsWith(
                DASHBOARD_STATIC_PREFIX) || servletPath.startsWith(DASHBOARD_HTML)))) {
            HttpMeta httpMeta = new HttpMeta(request, null, uri);
            request.setAttribute(HTTP_META, httpMeta);
            filterChain.doFilter(request, response);
            AuthzContext.currentHttpMeta.set(httpMeta);
            return;
        }

        String   api      = Httpd.getPattern(request.getMethod(), servletPath);
        HttpMeta httpMeta = new HttpMeta(request, api == null ? servletPath : api, servletPath);
        if (api == null) {
            httpMeta.error(ExceptionStatus.MISMATCHED_URL);
        }
        AuthzContext.currentHttpMeta.set(httpMeta);
        request.setAttribute(HTTP_META, httpMeta);
        filterChain.doFilter(request, response);
    }

}

