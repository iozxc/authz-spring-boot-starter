package cn.omisheep.authz;


import cn.omisheep.authz.core.AuCoreInitialization;
import cn.omisheep.authz.core.AuInit;
import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.aggregate.AggregateManager;
import cn.omisheep.authz.core.auth.AuthzDefender;
import cn.omisheep.authz.core.auth.PermFact;
import cn.omisheep.authz.core.auth.deviced.UserDevicesDict;
import cn.omisheep.authz.core.auth.deviced.UserDevicesDictByCache;
import cn.omisheep.authz.core.auth.deviced.UserDevicesDictByHashMap;
import cn.omisheep.authz.core.auth.ipf.AuthzHttpFilter;
import cn.omisheep.authz.core.auth.ipf.Httpd;
import cn.omisheep.authz.core.auth.rpd.PermissionDict;
import cn.omisheep.authz.core.cache.*;
import cn.omisheep.authz.core.handler.AuthzFeignRequestInterceptor;
import cn.omisheep.authz.core.handler.AuthzHandlerRegister;
import cn.omisheep.authz.core.handler.AuthzRestTemplateInterceptor;
import cn.omisheep.authz.core.handler.DecryptRequestBodyAdvice;
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
        @ConditionalOnProperty(name = "authz.cache.enabled-redis-actuator", havingValue = "false", matchIfMissing = true)
        public Object nonRedisActuator() {
            return new Object();
        }

        @Bean("authzRedisTemplate")
        @ConditionalOnMissingBean(name = "authzRedisTemplate")
        @ConditionalOnProperty(prefix = "authz.cache", name = "enabled-redis", havingValue = "true")
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
            if (properties.getCache().isEnabledRedis()) {
                return new DoubleDeckCache(properties);
            } else {
                return new DefaultCache(properties.getCache().getCacheMaximumSize(), properties.getCache().getExpireAfterReadOrUpdateTime());
            }
        }

        @Bean("authzCacheMessageReceive")
        @ConditionalOnProperty(prefix = "authz.cache", name = "enabled-redis", havingValue = "true")
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
        if (properties.getCache().isEnabledRedis()) {
            return new UserDevicesDictByCache(properties, cache);
        } else {
            return new UserDevicesDictByHashMap(properties);
        }
    }

    @Bean
    public AuthzDefender auDefender(UserDevicesDict userDevicesDict, PermissionDict permissionDict, PermFact permFact) {
        return new AuthzDefender(userDevicesDict, permissionDict, permFact);
    }

    @Bean
    public AuthzHandlerRegister authzHandlerRegister(AuthzDefender auDefender) {
        return new AuthzHandlerRegister(auDefender);
    }

    @Bean
    public FilterRegistrationBean<AuthzHttpFilter> filterRegistrationBean(Httpd httpd, UserDevicesDict userDevicesDict, AuthzProperties properties) {
        FilterRegistrationBean<AuthzHttpFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new AuthzHttpFilter(httpd, userDevicesDict, properties));
        registration.addUrlPatterns("/*");
        registration.setName("authzFilter");
        registration.setOrder(1);
        return registration;
    }

    @Bean
    public AuCoreInitialization auCoreInitialization(AuthzProperties properties, Httpd httpd, UserDevicesDict userDevicesDict, PermissionDict permissionDict) {
        return new AuCoreInitialization(properties, httpd, userDevicesDict, permissionDict);
    }

}
