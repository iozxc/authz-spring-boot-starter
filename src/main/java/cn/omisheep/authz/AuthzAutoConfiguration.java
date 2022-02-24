package cn.omisheep.authz;


import cn.omisheep.authz.core.AuCoreInitialization;
import cn.omisheep.authz.core.AuInit;
import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.aggregate.AggregateManager;
import cn.omisheep.authz.core.auth.AuthzDefender;
import cn.omisheep.authz.core.auth.DefaultPermLibrary;
import cn.omisheep.authz.core.auth.PermLibrary;
import cn.omisheep.authz.core.auth.deviced.UserDevicesDict;
import cn.omisheep.authz.core.auth.deviced.UserDevicesDictByCache;
import cn.omisheep.authz.core.auth.deviced.UserDevicesDictByHashMap;
import cn.omisheep.authz.core.auth.ipf.AuthzCookieFilter;
import cn.omisheep.authz.core.auth.ipf.AuthzHttpFilter;
import cn.omisheep.authz.core.auth.ipf.Httpd;
import cn.omisheep.authz.core.auth.rpd.PermissionDict;
import cn.omisheep.authz.core.cache.*;
import cn.omisheep.authz.core.interceptor.*;
import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.jsontype.impl.LaissezFaireSubTypeValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.data.redis.RedisProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
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


/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
@Configuration
@EnableConfigurationProperties({AuthzProperties.class})
@ConditionalOnClass(AuInit.class)
@Import({AuInit.class})
public class AuthzAutoConfiguration {

    @Configuration
    @EnableConfigurationProperties(RedisProperties.class)
    @SuppressWarnings({"rawtypes", "unchecked"})
    public static class CacheAutoConfiguration {

        public static Jackson2JsonRedisSerializer jackson2JsonRedisSerializer;
        public static StringRedisSerializer stringRedisSerializer = new StringRedisSerializer();

        static {
            jackson2JsonRedisSerializer = new Jackson2JsonRedisSerializer(Object.class);
            jackson2JsonRedisSerializer
                    .setObjectMapper(new ObjectMapper()
                            .setVisibility(PropertyAccessor.ALL, JsonAutoDetect.Visibility.ANY)
                            .activateDefaultTyping(LaissezFaireSubTypeValidator.instance, ObjectMapper.DefaultTyping.NON_FINAL)
                    );
        }

        @Bean(name = "redisHealthIndicator")
        @ConditionalOnProperty(name = "spring.authz.cache.enable-redis-actuator", havingValue = "false", matchIfMissing = true)
        public Object nonRedisActuator() {
            return new Object();
        }

        @Bean("authzRedisTemplate")
        @ConditionalOnMissingBean(name = "authzRedisTemplate")
        @ConditionalOnProperty(prefix = "spring.authz.cache", name = "enable-redis", havingValue = "true")
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

        @Bean
        public Cache cache(AuthzProperties properties) {
            if (properties.getCache().isEnableRedis()) {
                return new L2Cache(properties);
            } else {
                return new DefaultCache(properties.getCache().getCacheMaximumSize(), properties.getCache().getExpireAfterReadOrUpdateTime());
            }
        }

        @Bean("authzCacheMessageReceive")
        @ConditionalOnProperty(prefix = "spring.authz.cache", name = "enable-redis", havingValue = "true")
        public MessageReceive messageReceive(Cache cache) {
            return new MessageReceive(cache);
        }

        @Bean("authzCacheMessageListenerAdapter")
        @ConditionalOnBean(value = MessageReceive.class, name = "authzCacheMessageReceive")
        public MessageListenerAdapter listenerAdapter(@Qualifier("authzCacheMessageReceive") MessageReceive receiver) {
            return new MessageListenerAdapter(receiver);
        }

        @Bean("auCacheRedisMessageListenerContainer")
        @ConditionalOnBean(value = MessageReceive.class, name = "authzCacheMessageReceive")
        public RedisMessageListenerContainer container(@Qualifier("authzRedisTemplate") RedisTemplate redisTemplate, RedisConnectionFactory connectionFactory, @Qualifier("authzCacheMessageListenerAdapter") MessageListenerAdapter listenerAdapter) {
            try {
                redisTemplate.execute((RedisCallback<Object>) RedisConnectionCommands::ping);
            } catch (Exception e) {
                throw new IllegalStateException("redis异常，检查redis配置是否有效");
            }
            RedisMessageListenerContainer container = new RedisMessageListenerContainer();
            container.setConnectionFactory(connectionFactory);
            container.addMessageListener(listenerAdapter, new PatternTopic(Cache.CHANNEL));
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

        @Bean
        @ConditionalOnMissingBean(PermLibrary.class)
        public PermLibrary<Object> permLibrary() {
            return new AuthzDefaultPermLibrary();
        }

    }

    @Bean
    public DecryptRequestBodyAdvice auDecryptRequestBodyAdvice() {
        return new DecryptRequestBodyAdvice();
    }

    @Bean
    public AggregateManager aggregateManager() {
        return new AggregateManager();
    }

    @Bean
    public PermLibraryCache permLibraryCache(Cache cache) {
        return new PermLibraryCache(cache);
    }

    @Bean
    public UserDevicesDict userDevicesDict(AuthzProperties properties, Cache cache) {
        if (properties.getCache().isEnableRedis()) {
            return new UserDevicesDictByCache(properties, cache);
        } else {
            return new UserDevicesDictByHashMap(properties);
        }
    }

    @Bean
    @ConditionalOnMissingBean
    @SuppressWarnings("rawtypes")
    public PermLibrary permLibrary() {
        return new DefaultPermLibrary();
    }

    @Bean
    @SuppressWarnings("rawtypes")
    public AuthzDefender auDefender(UserDevicesDict userDevicesDict, PermissionDict permissionDict, PermLibrary permLibrary) {
        return new AuthzDefender(userDevicesDict, permissionDict, permLibrary);
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthzExceptionHandler authzExceptionHandler() {
        return new DefaultAuthzExceptionHandler();
    }

    @Bean
    public AuthzHandlerRegister authzHandlerRegister(AuthzDefender auDefender, AuthzExceptionHandler authzExceptionHandler) {
        return new AuthzHandlerRegister(auDefender, authzExceptionHandler);
    }

    @Bean("AuthzHttpFilter")
    public FilterRegistrationBean<AuthzHttpFilter> filterRegistrationBean(Httpd httpd) {
        FilterRegistrationBean<AuthzHttpFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new AuthzHttpFilter(httpd));
        registration.addUrlPatterns("/*");
        registration.setName("authzFilter");
        registration.setOrder(1);
        return registration;
    }

    @Bean("AuthzCookieFilter")
    public FilterRegistrationBean<AuthzCookieFilter> filterRegistrationBean(UserDevicesDict userDevicesDict, AuthzProperties properties) {
        FilterRegistrationBean<AuthzCookieFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new AuthzCookieFilter(userDevicesDict, properties));
        registration.addUrlPatterns("/*");
        registration.setName("authzCookieFilter");
        registration.setOrder(2);
        return registration;
    }

    @Bean
    public AuCoreInitialization auCoreInitialization(AuthzProperties properties, Httpd httpd, UserDevicesDict userDevicesDict, PermissionDict permissionDict) {
        return new AuCoreInitialization(properties, httpd, userDevicesDict, permissionDict);
    }

}
