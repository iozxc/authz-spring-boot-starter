package cn.omisheep.authz;


import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.config.AuthzModifierVersion;
import cn.omisheep.authz.core.auth.DefaultPermLibrary;
import cn.omisheep.authz.core.auth.PermLibrary;
import cn.omisheep.authz.core.auth.deviced.UserDevicesDict;
import cn.omisheep.authz.core.auth.deviced.UserDevicesDictByCache;
import cn.omisheep.authz.core.auth.deviced.UserDevicesDictByHashMap;
import cn.omisheep.authz.core.auth.ipf.AuthzHttpFilter;
import cn.omisheep.authz.core.auth.ipf.Httpd;
import cn.omisheep.authz.core.auth.rpd.PermissionDict;
import cn.omisheep.authz.core.cache.Cache;
import cn.omisheep.authz.core.cache.DefaultCache;
import cn.omisheep.authz.core.cache.L2Cache;
import cn.omisheep.authz.core.cache.PermLibraryCache;
import cn.omisheep.authz.core.codec.DecryptHandler;
import cn.omisheep.authz.core.codec.RSADecryptor;
import cn.omisheep.authz.core.config.AuCoreInitialization;
import cn.omisheep.authz.core.config.AuInit;
import cn.omisheep.authz.core.interceptor.*;
import cn.omisheep.authz.core.interceptor.mybatis.DataSecurityInterceptorForMybatis;
import cn.omisheep.authz.core.msg.*;
import cn.omisheep.authz.core.resolver.AuthzHandlerRegister;
import cn.omisheep.authz.core.resolver.DecryptRequestBodyAdvice;
import cn.omisheep.authz.core.util.LogUtils;
import cn.omisheep.authz.core.util.Utils;
import cn.omisheep.authz.support.http.SupportServlet;
import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.jsontype.impl.LaissezFaireSubTypeValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.*;
import org.springframework.boot.autoconfigure.data.redis.RedisProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
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
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashMap;


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
    private void init(ConfigurableEnvironment environment, AuthzProperties properties) {
        String name = environment.getProperty("spring.application.name");

        String applicationName = StringUtils.hasText(name) ? name : "application";
        AuthzModifierVersion.APPLICATION_NAME = applicationName;
        AuthzModifierVersion.APP_NAME         = properties.getApp();

        VersionMessage.CHANNEL = "AU:" + properties.getApp() + ":MODIFY_ID:" + applicationName;
        CacheMessage.CHANNEL   = "AU:" + properties.getApp() + ":CACHE_DATA_UPDATE";
        RequestMessage.CHANNEL = "AU:" + properties.getApp() + ":CONTEXT_CLOUD_APP_ID:" + applicationName;
        LogUtils.debug("Version channel: 【 {} 】, Cache channel: 【 {} 】, Request channel: 【 {} 】",
                VersionMessage.CHANNEL, CacheMessage.CHANNEL, RequestMessage.CHANNEL);

        String host;
        try {
            host = InetAddress.getLocalHost().getHostAddress();
        } catch (UnknownHostException e) {
            host = "localhost";
        }
        String port = environment.getProperty("server.port");
        String path = environment.getProperty("server.servlet.context-path");
        if (!StringUtils.hasText(path)) {
            path = "";
        }
        String prefix = Utils.format("http://{}:{}{}", host, port, path);

        AuthzModifierVersion.host   = host;
        AuthzModifierVersion.port   = port;
        AuthzModifierVersion.path   = path;
        AuthzModifierVersion.prefix = prefix;
    }

    @Bean("authzCache")
    public Cache cache(AuthzProperties properties) {
        if (properties.getCache().isEnableRedis()) {
            return new L2Cache(properties);
        } else {
            return new DefaultCache(properties.getCache().getCacheMaximumSize(), properties.getCache().getExpireAfterReadOrUpdateTime());
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
            jackson2JsonRedisSerializer.setObjectMapper(new ObjectMapper().setVisibility(PropertyAccessor.ALL, JsonAutoDetect.Visibility.ANY).activateDefaultTyping(LaissezFaireSubTypeValidator.instance, ObjectMapper.DefaultTyping.NON_FINAL));
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
        public MessageReceive messageReceive(Cache cache, Httpd httpd) {
            return new MessageReceive(cache, httpd);
        }

        @Bean("authzCacheMessageListenerAdapter")
        @ConditionalOnBean(value = MessageReceive.class, name = "authzCacheMessageReceive")
        public MessageListenerAdapter authzCacheMessageListenerAdapter(@Qualifier("authzCacheMessageReceive") MessageReceive receiver) {
            return new MessageListenerAdapter(receiver);
        }

        @Bean("authzRequestCacheMessageListenerAdapter")
        @ConditionalOnBean(value = MessageReceive.class, name = "authzCacheMessageReceive")
        public MessageListenerAdapter authzRequestCacheMessageListenerAdapter(@Qualifier("authzCacheMessageReceive") MessageReceive receiver) {
            return new MessageListenerAdapter(receiver);
        }

        @Bean("authzVersionMessageListenerAdapter")
        @ConditionalOnBean(value = MessageReceive.class, name = "authzCacheMessageReceive")
        public MessageListenerAdapter authzVersionMessageListenerAdapter(@Qualifier("authzCacheMessageReceive") MessageReceive receiver) {
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
    public AuthzMethodPermissionChecker authzMethodPermissionChecker(PermLibrary permLibrary) {
        return new AuthzMethodPermissionChecker(permLibrary);
    }

    @Bean
    public UserDevicesDict userDevicesDict(AuthzProperties properties) {
        if (properties.getCache().isEnableRedis()) {
            return new UserDevicesDictByCache(properties);
        } else {
            return new UserDevicesDictByHashMap(properties);
        }
    }

    @Bean
    @ConditionalOnMissingBean
    public PermLibrary permLibrary() {
        return new DefaultPermLibrary();
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
    public AuthzHandlerRegister authzHandlerRegister(AuthzExceptionHandler authzExceptionHandler, DecryptHandler decryptHandler) {
        return new AuthzHandlerRegister(authzExceptionHandler, decryptHandler);
    }

    @Bean("AuthzHttpFilter")
    public FilterRegistrationBean<AuthzHttpFilter> filterRegistrationBean(Httpd httpd, AuthzProperties properties) {
        FilterRegistrationBean<AuthzHttpFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new AuthzHttpFilter(httpd, properties.getDashboard().isEnabled(), properties.getDashboard().getMappings()));
        registration.addUrlPatterns("/*");
        registration.setName("authzFilter");
        registration.setOrder(1);
        return registration;
    }

    @Bean
    public AuCoreInitialization auCoreInitialization(AuthzProperties properties, Httpd httpd, UserDevicesDict userDevicesDict, PermissionDict permissionDict, PermLibrary permLibrary, Cache cache) {
        return new AuCoreInitialization(properties, httpd, userDevicesDict, permissionDict, permLibrary, cache);
    }

    @Configuration
    @ConditionalOnExpression("T(org.apache.commons.lang.StringUtils).isNotEmpty('${authz.orm}')")
    public static class DataFilterAutoConfiguration {
        @Bean
        @ConditionalOnProperty(name = "authz.orm", havingValue = "MYBATIS")
        @ConditionalOnMissingBean
        public DataSecurityInterceptorForMybatis dataSecurityInterceptorForMybatis() {
            return new DataSecurityInterceptorForMybatis();
        }

        @Bean
        @ConditionalOnMissingBean
        public DataFinderSecurityInterceptor dataFinderSecurityInterceptor() {
            return new DefaultDataSecurityInterceptor();
        }
    }


    // dashboard
    @Bean
    @ConditionalOnProperty(name = "authz.dashboard.enabled", havingValue = "true")
    public ServletRegistrationBean DashboardServlet(AuthzProperties properties) {
        AuthzProperties.DashboardConfig         dashboard = properties.getDashboard();
        ServletRegistrationBean<SupportServlet> bean      = new ServletRegistrationBean<>(new SupportServlet("support/http/resources", dashboard.getMappings()), dashboard.getMappings());

        HashMap<String, String> initParameters = new HashMap<>();

        initParameters.put("username", dashboard.getUsername());
        initParameters.put("password", dashboard.getPassword());
        initParameters.put("allow", dashboard.getAllow());
        initParameters.put("deny", dashboard.getDeny());
        initParameters.put("remoteAddress", dashboard.getRemoteAddress());
        initParameters.entrySet().removeIf(e -> e.getValue() == null);

        // 后台需要有人登录
        bean.setInitParameters(initParameters);
        return bean;
    }


}
