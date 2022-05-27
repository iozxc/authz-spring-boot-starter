package cn.omisheep.authz.core.resolver;

import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.tk.Token;
import org.springframework.core.MethodParameter;
import org.springframework.lang.Nullable;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

import javax.servlet.http.HttpServletRequest;

import static cn.omisheep.authz.core.Constants.HTTP_META;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
public class AuTokenOrHttpMetaResolver implements HandlerMethodArgumentResolver {
    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return parameter.getParameterType().equals(Token.class) || parameter.getParameterType().equals(HttpMeta.class);
    }

    @Override
    public Object resolveArgument(MethodParameter methodParameter, @Nullable ModelAndViewContainer modelAndViewContainer, NativeWebRequest nativeWebRequest, @Nullable WebDataBinderFactory webDataBinderFactory) {
        HttpMeta httpMeta = (HttpMeta) ((HttpServletRequest) nativeWebRequest.getNativeRequest()).getAttribute(HTTP_META);
        if (httpMeta == null) return null;
        if (methodParameter.getParameterType().equals(Token.class)) {
            return httpMeta.getToken();
        } else {
            return httpMeta;
        }
    }
}
