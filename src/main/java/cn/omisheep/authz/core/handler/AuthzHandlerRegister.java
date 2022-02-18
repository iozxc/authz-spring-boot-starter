package cn.omisheep.authz.core.handler;

import cn.omisheep.authz.core.auth.AuthzDefender;
import cn.omisheep.authz.core.resolver.AuHttpMetaResolver;
import cn.omisheep.authz.core.resolver.AuTokenOrHttpMetaResolver;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.List;

/**
 * qq: 1269670415
 *
 * @author zhou xin chen
 */
@Slf4j
public class AuthzHandlerRegister implements WebMvcConfigurer {

    private final AuthzDefender auDefender;

    public AuthzHandlerRegister(AuthzDefender auDefender) {
        this.auDefender = auDefender;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new AuthzInterceptor(auDefender))
                .excludePathPatterns("/error").order(1);
        registry.addInterceptor(new ErrorHandlerInterceptor())
                .excludePathPatterns("/error").order(2);
    }

    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
        resolvers.add(new AuTokenOrHttpMetaResolver());
        resolvers.add(new AuHttpMetaResolver());
        resolvers.add(new DecryptRequestParamHandler());
    }

}
