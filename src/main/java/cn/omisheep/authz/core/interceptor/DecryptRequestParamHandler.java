package cn.omisheep.authz.core.interceptor;

import cn.omisheep.authz.annotation.Decrypt;
import cn.omisheep.authz.core.tk.AuKey;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.MethodParameter;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

import javax.servlet.http.HttpServletRequest;
import java.lang.reflect.Constructor;

/**
 * 请求参数的拦截器。用于rsa解密
 *
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@Slf4j
@SuppressWarnings("all")
public class DecryptRequestParamHandler implements HandlerMethodArgumentResolver {

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return (parameter.hasParameterAnnotation(Decrypt.class) || parameter.hasMethodAnnotation(Decrypt.class));
    }

    public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer modelAndViewContainer, NativeWebRequest nativeWebRequest, WebDataBinderFactory webDataBinderFactory) throws Exception {
        HttpServletRequest request = nativeWebRequest.getNativeRequest(HttpServletRequest.class);
        if (request != null) {
            Constructor<?> constructor = parameter.getParameterType().getConstructor(String.class);
            String         text        = request.getParameter(parameter.getParameterName());
            String         decrypt     = AuKey.decrypt(text);
            return constructor.newInstance(decrypt);
        }
        return null;
    }
}

