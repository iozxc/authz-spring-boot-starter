package cn.omisheep.authz.core.handler;

import cn.omisheep.commons.util.HttpUtils;
import feign.RequestInterceptor;
import feign.RequestTemplate;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
public class AuthzFeignRequestInterceptor implements RequestInterceptor {
    @Override
    public void apply(RequestTemplate template) {
        HttpUtils.getCurrentRequestHeaders().forEach(template::header);
    }
}