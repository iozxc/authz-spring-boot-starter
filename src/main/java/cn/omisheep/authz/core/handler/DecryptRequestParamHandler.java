package cn.omisheep.authz.core.handler;

import cn.omisheep.authz.annotation.Decrypt;
import cn.omisheep.authz.core.auth.AuKey;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.MethodParameter;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

import javax.servlet.http.HttpServletRequest;
import java.lang.reflect.Constructor;

/**
 * qq: 1269670415
 *
 * @author zhou xin chen
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
            String text = request.getParameter(parameter.getParameterName());
            String decrypt = AuKey.decrypt(text);
            return constructor.newInstance(decrypt);
        }
        return null;
    }
}

