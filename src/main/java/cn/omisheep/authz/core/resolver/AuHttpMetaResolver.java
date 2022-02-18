package cn.omisheep.authz.core.resolver;

import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import org.springframework.core.MethodParameter;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

import javax.servlet.http.HttpServletRequest;

/**
 * qq: 1269670415
 *
 * @author zhou xin chen
 */
public class AuHttpMetaResolver implements HandlerMethodArgumentResolver {
    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return parameter.getParameterType().equals(HttpMeta.class);
    }

    @Override
    public Object resolveArgument(MethodParameter methodParameter, ModelAndViewContainer modelAndViewContainer, NativeWebRequest nativeWebRequest, WebDataBinderFactory webDataBinderFactory) {
        HttpServletRequest request = (HttpServletRequest) nativeWebRequest.getNativeRequest();
        return request.getAttribute("http_meta");
    }
}
