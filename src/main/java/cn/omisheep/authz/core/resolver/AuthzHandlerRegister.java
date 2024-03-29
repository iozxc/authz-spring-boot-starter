package cn.omisheep.authz.core.resolver;

import cn.omisheep.authz.core.codec.DecryptHandler;
import cn.omisheep.authz.core.interceptor.AuthzExceptionHandler;
import cn.omisheep.authz.core.interceptor.AuthzSlotCoreInterceptor;
import cn.omisheep.authz.core.slot.Slot;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * 拦截器注册
 *
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@Slf4j
public class AuthzHandlerRegister implements WebMvcConfigurer, ApplicationContextAware {

    private final AuthzExceptionHandler authzExceptionHandler;
    private final DecryptHandler        decryptHandler;

    public AuthzHandlerRegister(AuthzExceptionHandler authzExceptionHandler,
                                DecryptHandler decryptHandler) {
        this.authzExceptionHandler = authzExceptionHandler;
        this.decryptHandler        = decryptHandler;
    }

    private Collection<Slot> slots = new ArrayList<>();

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new AuthzSlotCoreInterceptor(authzExceptionHandler, slots))
                .excludePathPatterns("/error").order(1);
    }

    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
        resolvers.add(new AuTokenOrHttpMetaResolver());
        resolvers.add(new AuHttpMetaResolver());
        resolvers.add(new DecryptRequestParamHandler(decryptHandler));
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        Map<String, Slot> result = applicationContext.getBeansOfType(Slot.class);
        this.slots = result.values();
    }
}
