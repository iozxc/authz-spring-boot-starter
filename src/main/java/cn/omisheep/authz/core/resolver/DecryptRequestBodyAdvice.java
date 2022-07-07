package cn.omisheep.authz.core.resolver;


import cn.omisheep.authz.annotation.Decrypt;
import cn.omisheep.authz.core.tk.AuKey;
import cn.omisheep.authz.core.util.JSONDecryptUtils;
import cn.omisheep.authz.core.util.Utils;
import cn.omisheep.commons.util.RSAHelper;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.MethodParameter;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.RequestBodyAdvice;

import java.io.*;
import java.lang.reflect.Type;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * 请求体的拦截器，用于rsa解码
 *
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
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
        Decrypt decrypt = AnnotationUtils.getAnnotation(parameter.getParameter(), Decrypt.class);
        if (decrypt.fields().length != 0) {
            return new DecryptRequestBodyHandler(inputMessage, AuKey.getPrivateKeyString(), Arrays.asList(decrypt.fields()));
        } else {
            return new DecryptRequestBodyHandler(inputMessage, AuKey.getPrivateKeyString());
        }

    }

    @Override
    public Object afterBodyRead(Object body, HttpInputMessage inputMessage, MethodParameter parameter, Type targetType,
                                Class<? extends HttpMessageConverter<?>> converterType) {
        return body;
    }

    public class DecryptRequestBodyHandler implements HttpInputMessage {

        private final HttpHeaders headers;
        private final InputStream body;

        public DecryptRequestBodyHandler(HttpInputMessage inputMessage, String privateKey, List<String> fields) throws IOException {
            this.headers = inputMessage.getHeaders();
            String content = new BufferedReader(new InputStreamReader(inputMessage.getBody()))
                    .lines().collect(Collectors.joining(System.lineSeparator()));
            JSONObject object = JSON.parseObject(content);
            for (String field : fields) {
                JSONDecryptUtils.decrypt(field, object, privateKey);
            }
            // 将原本的json整个加密，然后再放到一个空对象中，请勿直接传递加密的数据
            String decrypt = JSON.toJSONString(object);
            if (decrypt == null) {
                decrypt = "{}";
            }
            this.body = new ByteArrayInputStream(decrypt.getBytes());
        }


        public DecryptRequestBodyHandler(HttpInputMessage inputMessage, String privateKey) throws IOException {
            this.headers = inputMessage.getHeaders();
            String content = new BufferedReader(new InputStreamReader(inputMessage.getBody()))
                    .lines().collect(Collectors.joining(System.lineSeparator()));
            // 将原本的json整个加密，然后再放到一个空对象中，请勿直接传递加密的数据
            String decrypt = RSAHelper.decrypt(Utils.parse_RSA_JSON(content), privateKey);
            if (decrypt == null) {
                decrypt = "{}";
            }
            this.body = new ByteArrayInputStream(decrypt.getBytes());
        }

        @Override
        public InputStream getBody() {
            return body;
        }

        @Override
        public HttpHeaders getHeaders() {
            return headers;
        }
    }

}
