package cn.omisheep.authz.core.resolver;

import cn.omisheep.authz.annotation.Decrypt;
import cn.omisheep.authz.core.codec.DecryptHandler;
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


    private final DecryptHandler decryptHandler;

    public DecryptRequestParamHandler(DecryptHandler decryptHandler) {
        this.decryptHandler = decryptHandler;
    }

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return (parameter.hasParameterAnnotation(Decrypt.class) || parameter.hasMethodAnnotation(Decrypt.class));
    }

    public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer modelAndViewContainer, NativeWebRequest nativeWebRequest, WebDataBinderFactory webDataBinderFactory) throws Exception {
        HttpServletRequest request = nativeWebRequest.getNativeRequest(HttpServletRequest.class);
        if (request != null) {
            Constructor<?> constructor = parameter.getParameterType().getConstructor(String.class);
            String         text        = request.getParameter(parameter.getParameterName());
            Decrypt        decrypt     = parameter.getParameterAnnotation(Decrypt.class);
            return constructor.newInstance(decryptHandler.decrypt(text, decrypt));
        }
        return null;
    }
}

