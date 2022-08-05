package cn.omisheep.authz;


import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.auth.DefaultPermLibrary;
import cn.omisheep.authz.core.auth.PermLibrary;
import cn.omisheep.authz.core.auth.deviced.UserDevicesDict;
import cn.omisheep.authz.core.auth.deviced.UserDevicesDictByCache;
import cn.omisheep.authz.core.auth.ipf.AuthzHttpFilter;
import cn.omisheep.authz.core.cache.Cache;
import cn.omisheep.authz.core.cache.L1Cache;
import cn.omisheep.authz.core.cache.L2Cache;
import cn.omisheep.authz.core.cache.library.OpenAuthLibraryCache;
import cn.omisheep.authz.core.cache.library.PermLibraryCache;
import cn.omisheep.authz.core.codec.DecryptHandler;
import cn.omisheep.authz.core.codec.RSADecryptor;
import cn.omisheep.authz.core.config.AuCoreInitialization;
import cn.omisheep.authz.core.config.AuInit;
import cn.omisheep.authz.core.config.AuthzAppVersion;
import cn.omisheep.authz.core.interceptor.*;
import cn.omisheep.authz.core.interceptor.mybatis.DataSecurityInterceptorForMybatis;
import cn.omisheep.authz.core.msg.CacheMessage;
import cn.omisheep.authz.core.msg.MessageReceive;
import cn.omisheep.authz.core.msg.RequestMessage;
import cn.omisheep.authz.core.msg.VersionMessage;
import cn.omisheep.authz.core.oauth.DefaultOpenAuthLibrary;
import cn.omisheep.authz.core.oauth.OpenAuthLibrary;
import cn.omisheep.authz.core.resolver.AuthzHandlerRegister;
import cn.omisheep.authz.core.resolver.DecryptRequestBodyAdvice;
import cn.omisheep.authz.core.util.LogUtils;
import cn.omisheep.authz.support.entity.Cloud;
import cn.omisheep.authz.support.entity.Docs;
import cn.omisheep.authz.support.entity.Info;
import cn.omisheep.authz.support.http.SupportServlet;
import cn.omisheep.authz.support.http.annotation.ApiSupportScan;
import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.jsontype.impl.LaissezFaireSubTypeValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.condition.*;
import org.springframework.boot.autoconfigure.data.redis.RedisProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.data.redis.connection.RedisConnectionCommands;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.listener.PatternTopic;
import org.springframework.data.redis.listener.RedisMessageListenerContainer;
import org.springframework.data.redis.listener.adapter.MessageListenerAdapter;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;

import static cn.omisheep.authz.core.config.Constants.DASHBOARD;


/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@Configuration
@EnableConfigurationProperties({AuthzProperties.class})
@ConditionalOnClass(AuInit.class)
@Import({AuInit.class})
@SuppressWarnings("rawtypes")
public class AuthzAutoConfiguration {

    @Autowired
    private void init(ConfigurableEnvironment environment,
                      ApplicationContext ctx,
                      AuthzProperties properties) {
        ctx.getBeansWithAnnotation(SpringBootApplication.class)
                .values().stream().findAny()
                .ifPresent(value -> AuthzAppVersion.mainClass = value.getClass());

        AuthzAppVersion.environment = environment;
        AuthzAppVersion.properties  = properties;

        LogUtils.setLogLevel(properties.getLog());

        VersionMessage.CHANNEL = "AU:" + properties.getApp() + ":MODIFY_ID:" + AuthzAppVersion.APPLICATION_NAME.get();
        CacheMessage.CHANNEL   = "AU:" + properties.getApp() + ":CACHE_DATA_UPDATE";
        RequestMessage.CHANNEL = "AU:" + properties.getApp() + ":CONTEXT_CLOUD_APP_ID:" + AuthzAppVersion.APPLICATION_NAME.get();
        LogUtils.debug("Version channel: 【 {} 】, Cache channel: 【 {} 】, Request channel: 【 {} 】",
                       VersionMessage.CHANNEL, CacheMessage.CHANNEL, RequestMessage.CHANNEL);
    }

    @Primary
    @Bean("authzCache")
    public Cache cache(AuthzProperties properties) {
        if (properties.getCache().isEnableRedis()) {
            return new L2Cache(properties);
        } else {
            return new L1Cache(properties.getCache().getCacheMaximumSize(),
                               properties.getCache().getExpireAfterCreateTime(),
                               properties.getCache().getExpireAfterUpdateTime(),
                               properties.getCache().getExpireAfterReadTime());
        }
    }

    @Configuration
    @EnableConfigurationProperties(RedisProperties.class)
    @SuppressWarnings({"rawtypes", "unchecked"})
    public static class CacheAutoConfiguration {

        public static Jackson2JsonRedisSerializer jackson2JsonRedisSerializer;
        public static StringRedisSerializer       stringRedisSerializer = new StringRedisSerializer();

        static {
            jackson2JsonRedisSerializer = new Jackson2JsonRedisSerializer(Object.class);
            jackson2JsonRedisSerializer.setObjectMapper(
                    new ObjectMapper().setVisibility(PropertyAccessor.ALL, JsonAutoDetect.Visibility.ANY)
                            .activateDefaultTyping(LaissezFaireSubTypeValidator.instance,
                                                   ObjectMapper.DefaultTyping.NON_FINAL));
        }

        @Bean(name = "redisHealthIndicator")
        @ConditionalOnProperty(name = "authz.cache.enable-redis-actuator", havingValue = "false", matchIfMissing = true)
        public Object nonRedisActuator() {
            return new Object();
        }

        @Bean("authzRedisTemplate")
        @ConditionalOnMissingBean(name = "authzRedisTemplate")
        @ConditionalOnProperty(prefix = "authz.cache", name = "enable-redis", havingValue = "true")
        public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory redisConnectionFactory) {
            RedisTemplate<String, Object> template = new RedisTemplate<>();
            template.setConnectionFactory(redisConnectionFactory);
            template.setKeySerializer(stringRedisSerializer);
            template.setHashKeySerializer(stringRedisSerializer);
            template.setValueSerializer(jackson2JsonRedisSerializer);
            template.setHashKeySerializer(jackson2JsonRedisSerializer);
            template.afterPropertiesSet();
            return template;
        }

        @Bean("authzCacheMessageReceive")
        @ConditionalOnProperty(prefix = "authz.cache", name = "enable-redis", havingValue = "true")
        public MessageReceive messageReceive(Cache cache) {
            return new MessageReceive(cache);
        }

        @Bean("authzCacheMessageListenerAdapter")
        @ConditionalOnBean(value = MessageReceive.class, name = "authzCacheMessageReceive")
        public MessageListenerAdapter authzCacheMessageListenerAdapter(
                @Qualifier("authzCacheMessageReceive") MessageReceive receiver) {
            return new MessageListenerAdapter(receiver);
        }

        @Bean("authzRequestCacheMessageListenerAdapter")
        @ConditionalOnBean(value = MessageReceive.class, name = "authzCacheMessageReceive")
        public MessageListenerAdapter authzRequestCacheMessageListenerAdapter(
                @Qualifier("authzCacheMessageReceive") MessageReceive receiver) {
            return new MessageListenerAdapter(receiver);
        }

        @Bean("authzVersionMessageListenerAdapter")
        @ConditionalOnBean(value = MessageReceive.class, name = "authzCacheMessageReceive")
        public MessageListenerAdapter authzVersionMessageListenerAdapter(
                @Qualifier("authzCacheMessageReceive") MessageReceive receiver) {
            return new MessageListenerAdapter(receiver);
        }

        @Bean("auCacheRedisMessageListenerContainer")
        @ConditionalOnBean(value = MessageReceive.class, name = "authzCacheMessageReceive")
        public RedisMessageListenerContainer container(@Qualifier("authzRedisTemplate") RedisTemplate redisTemplate,
                                                       RedisConnectionFactory connectionFactory,
                                                       @Qualifier("authzCacheMessageListenerAdapter") MessageListenerAdapter listenerAdapter1,
                                                       @Qualifier("authzRequestCacheMessageListenerAdapter") MessageListenerAdapter listenerAdapter2,
                                                       @Qualifier("authzVersionMessageListenerAdapter") MessageListenerAdapter listenerAdapter3) {
            try {
                redisTemplate.execute((RedisCallback<Object>) RedisConnectionCommands::ping);
            } catch (Exception e) {
                throw new IllegalStateException("redis异常，检查redis配置是否有效");
            }
            RedisMessageListenerContainer container = new RedisMessageListenerContainer();
            container.setMaxSubscriptionRegistrationWaitingTime(6000L);
            container.setRecoveryInterval(15000L);
            container.setConnectionFactory(connectionFactory);
            container.addMessageListener(listenerAdapter1, new PatternTopic(CacheMessage.CHANNEL));
            container.addMessageListener(listenerAdapter2, new PatternTopic(RequestMessage.CHANNEL)); //  request 同步
            container.addMessageListener(listenerAdapter3, new PatternTopic(VersionMessage.CHANNEL)); //  version 同步
            container.setTopicSerializer(jackson2JsonRedisSerializer);
            return container;
        }

    }

    @Configuration
    public static class AuthzCloudAutoConfiguration {

        @Bean
        @ConditionalOnClass(name = "org.springframework.cloud.openfeign.FeignContext")
        public AuthzFeignRequestInterceptor authzFeignRequestInterceptor() {
            return new AuthzFeignRequestInterceptor();
        }

        @Autowired(required = false)
        @ConditionalOnBean(RestTemplate.class)
        public void authzRestTemplateInterceptor(RestTemplate restTemplate) {
            restTemplate.getInterceptors().add(new AuthzRestTemplateInterceptor());
        }

    }

    @Bean
    public DecryptRequestBodyAdvice auDecryptRequestBodyAdvice(DecryptHandler decryptHandler) {
        return new DecryptRequestBodyAdvice(decryptHandler);
    }

    @Bean
    public PermLibraryCache permLibraryCache(Cache cache) {
        return new PermLibraryCache(cache);
    }

    @Bean
    public OpenAuthLibraryCache openAuthLibraryCache(Cache cache) {
        return new OpenAuthLibraryCache(cache);
    }

    @Bean
    public AuthzMethodPermissionChecker authzMethodPermissionChecker(PermLibrary permLibrary,
                                                                     AuthzProperties properties) {
        return new AuthzMethodPermissionChecker(permLibrary, properties);
    }

    @Primary
    @Bean
    public UserDevicesDict userDevicesDict(AuthzProperties properties,
                                           Cache cache) {
        return new UserDevicesDictByCache(properties, cache);
    }

    @Bean
    @ConditionalOnMissingBean
    public PermLibrary permLibrary() {
        return new DefaultPermLibrary();
    }

    @Bean
    @ConditionalOnMissingBean
    public OpenAuthLibrary openAuthLibrary() {
        return new DefaultOpenAuthLibrary();
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthzExceptionHandler authzExceptionHandler(AuthzProperties properties) {
        return new DefaultAuthzExceptionHandler(properties.getResponse());
    }

    @Bean
    @ConditionalOnMissingBean
    public RSADecryptor rsaDecryptor() {
        return new RSADecryptor();
    }

    @Bean
    @ConditionalOnMissingBean
    public DecryptHandler decryptHandler(AuthzProperties properties) {
        return new DecryptHandler(properties.getDefaultDecryptor());
    }

    @Bean
    public AuthzHandlerRegister authzHandlerRegister(AuthzExceptionHandler authzExceptionHandler,
                                                     DecryptHandler decryptHandler) {
        return new AuthzHandlerRegister(authzExceptionHandler, decryptHandler);
    }

    @Bean("AuthzHttpFilter")
    public FilterRegistrationBean<AuthzHttpFilter> filterRegistrationBean(AuthzProperties properties) {
        FilterRegistrationBean<AuthzHttpFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new AuthzHttpFilter(properties.getDashboard().isEnabled()));
        registration.addUrlPatterns("/*");
        registration.setName("authzFilter");
        registration.setOrder(1);
        return registration;
    }

    @Bean
    public AuCoreInitialization auCoreInitialization(AuthzProperties properties,
                                                     UserDevicesDict userDevicesDict,
                                                     PermLibrary permLibrary,
                                                     OpenAuthLibrary openAuthLibrary,
                                                     Cache cache) {
        return new AuCoreInitialization(properties, userDevicesDict, permLibrary,
                                        openAuthLibrary, cache);
    }

    @Configuration
    @ConditionalOnExpression("T(org.apache.commons.lang.StringUtils).isNotEmpty('${authz.orm}')")
    public static class DataFilterAutoConfiguration {
        @Bean
        @Primary
        @ConditionalOnProperty(name = "authz.orm", havingValue = "MYBATIS")
        public DataSecurityInterceptorForMybatis dataSecurityInterceptorForMybatis(PermLibrary permLibrary,
                                                                                   DataFinderSecurityInterceptor dataFinderSecurityInterceptor) {
            return new DataSecurityInterceptorForMybatis(permLibrary, dataFinderSecurityInterceptor);
        }

        @Bean
        @ConditionalOnMissingBean
        public DataFinderSecurityInterceptor dataFinderSecurityInterceptor() {
            return new DefaultDataSecurityInterceptor();
        }
    }

    @ConditionalOnProperty(name = "authz.dashboard.enabled", havingValue = "true")
    @ApiSupportScan("cn.omisheep.authz.support.http.api")
    public static class AuthzDashboardAutoConfiguration {

        @Bean
        @ConditionalOnMissingBean
        private Info info() {
            return new Info()
                    .setDescription("Authz Documentation")
                    .setTitle("Authz Documentation")
                    .setVersion("1.0");
        }

        @Primary
        @Bean("authz-docs")
        private Docs docs(Info info) {
            return new Docs(info);
        }

        @Bean("authz-cloud")
        private Cloud cloud() {
            return new Cloud();
        }

        @Bean
        public ServletRegistrationBean DashboardServlet(AuthzProperties properties,
                                                        Cache cache) {
            AuthzProperties.DashboardConfig dashboard = properties.getDashboard();
            ServletRegistrationBean<SupportServlet> bean =
                    new ServletRegistrationBean<>(new SupportServlet(dashboard, cache), DASHBOARD);

            HashMap<String, String> initParameters = new HashMap<>();

            initParameters.put("allow", dashboard.getAllow());
            initParameters.put("deny", dashboard.getDeny());
            initParameters.entrySet().removeIf(e -> e.getValue() == null);

            bean.setInitParameters(initParameters);
            return bean;
        }

    }

}
