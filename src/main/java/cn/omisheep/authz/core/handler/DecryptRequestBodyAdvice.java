package cn.omisheep.authz.core.handler;


import cn.omisheep.authz.annotation.Decrypt;
import cn.omisheep.authz.core.auth.AuKey;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.RequestBodyAdvice;

import java.io.IOException;
import java.lang.reflect.Type;

/**
 * qq: 1269670415
 *
 * @author zhou xin chen
 */
@ControllerAdvice
@Slf4j
@SuppressWarnings("all")
public class DecryptRequestBodyAdvice implements RequestBodyAdvice {

    /**
     * 1、请求方法中有Decrypt注解，不论在参数还是在方法上，都会将@ReqeusetBody里的东西给解密。
     * 2、Decrypt注解在参数上，只会给指定的参数解密，如果但是如果Decrypt注解在方法上，会给所有的参数解密。
     * 3、注意的是，如果这个方法，不论在方法上还是在参数上、只要有Decrypt注解，都会给@ReqeusetBody的内容解密
     */
    @Override
    public boolean supports(MethodParameter parameter, Type targetType, Class<? extends HttpMessageConverter<?>> converterType) {
        return parameter.hasMethodAnnotation(Decrypt.class) || parameter.hasParameterAnnotation(Decrypt.class);
    }

    @Override
    public Object handleEmptyBody(Object body, HttpInputMessage inputMessage, MethodParameter parameter, Type targetType, Class<? extends HttpMessageConverter<?>> converterType) {
        return body;
    }

    @Override
    public HttpInputMessage beforeBodyRead(HttpInputMessage inputMessage, MethodParameter parameter, Type targetType,
                                           Class<? extends HttpMessageConverter<?>> converterType) throws IOException {
        return new DecryptRequestBodyHandler(inputMessage, AuKey.getPrivateKeyString());
    }

    @Override
    public Object afterBodyRead(Object body, HttpInputMessage inputMessage, MethodParameter parameter, Type targetType,
                                Class<? extends HttpMessageConverter<?>> converterType) {
        return body;
    }


}
