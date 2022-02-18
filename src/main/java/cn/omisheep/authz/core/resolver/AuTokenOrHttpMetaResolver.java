package cn.omisheep.authz.core.resolver;

import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.tk.Token;
import org.springframework.core.MethodParameter;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

import javax.servlet.http.HttpServletRequest;
import java.util.Optional;

/**
 * qq: 1269670415
 *
 * @author zhou xin chen
 */
public class AuTokenOrHttpMetaResolver implements HandlerMethodArgumentResolver {
    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return parameter.getParameterType().equals(Token.class) || parameter.getParameterType().equals(HttpMeta.class);
    }

    @Override
    public Object resolveArgument(MethodParameter methodParameter, ModelAndViewContainer modelAndViewContainer, NativeWebRequest nativeWebRequest, WebDataBinderFactory webDataBinderFactory) {
        HttpMeta httpMeta = (HttpMeta) ((HttpServletRequest) nativeWebRequest.getNativeRequest()).getAttribute("AU_HTTP_META");
        if (httpMeta == null) return null;
        if (methodParameter.getParameterType().equals(Token.class)) {
            return Optional.ofNullable(httpMeta.getToken()).orElse(null);
        } else {
            return httpMeta;
        }
    }
}
