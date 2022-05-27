package cn.omisheep.authz.core.interceptor;

import cn.omisheep.web.utils.HttpUtils;
import feign.RequestInterceptor;
import feign.RequestTemplate;

/**
 * 适配Feign
 *
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
public class AuthzFeignRequestInterceptor implements RequestInterceptor {
    @Override
    public void apply(RequestTemplate template) {
        HttpUtils.getCurrentRequestHeaders().forEach(template::header);
    }
}