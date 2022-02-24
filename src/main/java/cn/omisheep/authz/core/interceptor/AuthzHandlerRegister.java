package cn.omisheep.authz.core.interceptor;

import cn.omisheep.authz.core.auth.AuthzDefender;
import cn.omisheep.authz.core.resolver.AuHttpMetaResolver;
import cn.omisheep.authz.core.resolver.AuTokenOrHttpMetaResolver;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.List;

/**
 * 拦截器注册
 *
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
@Slf4j
public class AuthzHandlerRegister implements WebMvcConfigurer {

    private final AuthzDefender auDefender;
    private final AuthzExceptionHandler authzExceptionHandler;

    public AuthzHandlerRegister(AuthzDefender auDefender, AuthzExceptionHandler authzExceptionHandler) {
        this.auDefender = auDefender;
        this.authzExceptionHandler = authzExceptionHandler;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new AuthzCoreInterceptor(auDefender))
                .excludePathPatterns("/error").order(1);
        registry.addInterceptor(new AuthzFinalInterceptor(authzExceptionHandler))
                .excludePathPatterns("/error").order(2);
    }

    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
        resolvers.add(new AuTokenOrHttpMetaResolver());
        resolvers.add(new AuHttpMetaResolver());
        resolvers.add(new DecryptRequestParamHandler());
    }

}
