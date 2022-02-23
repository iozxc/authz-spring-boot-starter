package cn.omisheep.authz.core;

import cn.omisheep.authz.annotation.Perms;
import cn.omisheep.authz.annotation.RateLimit;
import cn.omisheep.authz.annotation.Roles;
import cn.omisheep.authz.core.auth.AuKey;
import cn.omisheep.authz.core.auth.PermRolesMeta;
import cn.omisheep.authz.core.auth.deviced.DeviceConfig;
import cn.omisheep.authz.core.auth.deviced.UserDevicesDict;
import cn.omisheep.authz.core.auth.ipf.Httpd;
import cn.omisheep.authz.core.auth.ipf.LimitMeta;
import cn.omisheep.authz.core.auth.rpd.PermissionDict;
import cn.omisheep.authz.core.cache.Message;
import cn.omisheep.authz.core.util.AUtils;
import cn.omisheep.authz.core.util.LogUtils;
import cn.omisheep.commons.util.CollectionUtils;
import cn.omisheep.commons.util.TaskBuilder;
import lombok.SneakyThrows;
import org.springframework.aop.support.AopUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.handler.AbstractHandlerMethodMapping;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.StringJoiner;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
@SuppressWarnings("all")
public class AuCoreInitialization implements ApplicationContextAware {

    @Value("${server.servlet.context-path:}")
    private String contextPath;

    private final AuthzProperties properties;

    private final Httpd httpd;

    private final UserDevicesDict userDevicesDict;

    private final PermissionDict permissionDict;

    private ApplicationContext ctx;

    public AuCoreInitialization(AuthzProperties properties, Httpd httpd, UserDevicesDict userDevicesDict, PermissionDict permissionDict) {
        this.properties = properties;
        this.httpd = httpd;
        this.userDevicesDict = userDevicesDict;
        this.permissionDict = permissionDict;
    }

    @Override
    @SneakyThrows
    public void setApplicationContext(ApplicationContext applicationContext) {
        this.ctx = applicationContext;
        AbstractHandlerMethodMapping<RequestMappingInfo> methodMapping =
                (AbstractHandlerMethodMapping<RequestMappingInfo>) applicationContext.getBean("requestMappingHandlerMapping");
        Map<RequestMappingInfo, HandlerMethod> mapRet = methodMapping.getHandlerMethods();

        // init PermissionDict
        initPermissionDict(applicationContext, mapRet);
        LogUtils.logDebug("⬇ PermissionDict init success ⬇\n{}\n", AUtils.beautifulJson(permissionDict));

        // init Httpd
        initHttpd(applicationContext, mapRet);
        LogUtils.logDebug("⬇ Httpd init success ⬇\n{}\n", AUtils.beautifulJson(httpd));

        // init UserDevicesDict
        initUserDevicesDict();
        LogUtils.logDebug("UserDevicesDict init success");

        // init Jobs
        TaskBuilder.schedule(AuKey::refreshKeyGroup, properties.getRsaKeyRefreshWithPeriod());
        if (!properties.getCache().isEnabledRedis()) {
            TaskBuilder.schedule(Pelcron::activeExpireCycle, properties.getUserBufferRefreshWithPeriod());
        }
        TaskBuilder.schedule(Pelcron::GC, properties.getGcPeriod());

        AuInit.log.info("Started Authz  id: {}", Message.id);
//        initJob(CountingTaskForMinute.class, "1m", TimeUtils.nextIntactDateForMinute(), AggregateManager.class);
//        initJob(CountingTaskForDay.class, "1d", TimeUtils.nextIntactDateForDay(), AggregateManager.class);
    }


    private void initPermissionDict(ApplicationContext applicationContext, Map<RequestMappingInfo, HandlerMethod> mapRet) {
        permissionDict.setPermSeparator(properties.getPermSeparator());
        Map<String, Map<String, PermRolesMeta>> auMap = permissionDict.getAuMap();
        Map<String, PermRolesMeta> pMap = new HashMap<>();
        Map<String, PermRolesMeta> rMap = new HashMap<>();
        applicationContext.getBeansWithAnnotation(Perms.class).entrySet().forEach(entry -> {
            Perms permsFromController = AnnotationUtils.getAnnotation(entry.getValue().getClass(), Perms.class);
            pMap.put(entry.getValue().getClass().getName(),
                    generatePermRolesMeta(permsFromController, null));
        });
        applicationContext.getBeansWithAnnotation(Roles.class).entrySet().forEach(entry -> {
            Roles rolesFromController = AnnotationUtils.getAnnotation(entry.getValue().getClass(), Roles.class);
            rMap.put(entry.getValue().getClass().getName(),
                    generatePermRolesMeta(null, rolesFromController));
        });

        mapRet.entrySet().forEach(entry -> {
            PermRolesMeta pFc = pMap.get(entry.getValue().getBeanType().getName());
            PermRolesMeta rFc = rMap.get(entry.getValue().getBeanType().getName());
            PermRolesMeta permRolesMeta = generatePermRolesMeta(entry.getValue().getMethodAnnotation(Perms.class), entry.getValue().getMethodAnnotation(Roles.class));

            if (rFc != null) {
                if (permRolesMeta.getRequireRoles() != null) {
                    permRolesMeta.getRequireRoles().addAll(rFc.getRequireRoles());
                } else {
                    permRolesMeta.setExcludeRoles(rFc.getRequireRoles());
                }
                if (permRolesMeta.getExcludeRoles() != null) {
                    permRolesMeta.getExcludeRoles().addAll(rFc.getExcludeRoles());
                } else {
                    permRolesMeta.setExcludeRoles(rFc.getExcludeRoles());
                }
            }
            if (pFc != null) {
                if (permRolesMeta.getRequirePermissions() != null) {
                    permRolesMeta.getRequirePermissions().addAll(pFc.getRequirePermissions());
                } else {
                    permRolesMeta.setRequirePermissions(rFc.getRequirePermissions());
                }
                if (permRolesMeta.getExcludePermissions() != null) {
                    permRolesMeta.getExcludePermissions().addAll(pFc.getExcludePermissions());
                } else {
                    permRolesMeta.setExcludePermissions(rFc.getExcludePermissions());
                }
            }

            if (permRolesMeta != null) {
                entry.getKey().getMethodsCondition().getMethods().forEach(method -> {
                    entry.getKey().getPatternsCondition().getPatterns().forEach(patternValue -> {

                        permissionDict.getPaths().add(patternValue);
                        permissionDict.getPaddingPath().add(contextPath + patternValue);

                        StringJoiner stringJoiner = new StringJoiner("/");
                        for (String s : patternValue.split("/")) {
                            if (s.startsWith("{") && s.endsWith("}")) {
                                stringJoiner.add("*");
                            } else {
                                stringJoiner.add(s);
                            }
                        }
                        permissionDict.getPatternPath().add(stringJoiner.toString());

                        Map<String, PermRolesMeta> map = auMap.get(method.toString());
                        if (map == null) {
                            map = new HashMap<>();
                            auMap.put(method.toString(), map);
                        }
                        map.put(contextPath + patternValue, permRolesMeta);
                    });
                });
            }
        });

    }

    private PermRolesMeta generatePermRolesMeta(Perms p, Roles r) {
        PermRolesMeta prm = new PermRolesMeta();
        boolean flag = false;
        if (p != null) {
            if (p.require() != null && p.require().length != 0) {
                prm.setRequirePermissions(CollectionUtils.splitStrValsToSets(properties.getPermSeparator(), p.require()));
            }
            if (p.exclude() != null && p.exclude().length != 0) {
                prm.setExcludePermissions(CollectionUtils.splitStrValsToSets(properties.getPermSeparator(), p.exclude()));
            }
            flag = true;
        }
        if (r != null) {
            if (r.require() != null && r.require().length != 0) {
                prm.setRequireRoles(CollectionUtils.splitStrValsToSets(properties.getPermSeparator(), r.require()));
            }
            if (r.exclude() != null && r.exclude().length != 0) {
                prm.setExcludeRoles(CollectionUtils.splitStrValsToSets(properties.getPermSeparator(), r.exclude()));
            }
            flag = true;
        }
        return flag ? prm : null;
    }

    private void initHttpd(ApplicationContext applicationContext, Map<RequestMappingInfo, HandlerMethod> mapRet) {
        Map<String, Map<String, LimitMeta>> httpdLimitedMetaMap = httpd.getRateLimitMetadata();
        HashMap<String, LimitMeta> cMap = new HashMap<>();

        applicationContext.getBeansWithAnnotation(RateLimit.class).entrySet().forEach(entry -> {
            Class<?> aClass = AopUtils.getTargetClass(entry.getValue());
            RateLimit rateLimit = aClass.getAnnotation(RateLimit.class);
            if (rateLimit != null) {
                cMap.put(aClass.getName(),
                        new LimitMeta(rateLimit.window(), rateLimit.maxRequests(), rateLimit.punishmentTime(), rateLimit.minInterval(), rateLimit.associatedPatterns(), rateLimit.bannedType()));
            }
        });

        for (Map.Entry<RequestMappingInfo, HandlerMethod> entry : mapRet.entrySet()) {
            Set<RequestMethod> methods = entry.getKey().getMethodsCondition().getMethods();
            Set<String> patternValues = entry.getKey().getPatternsCondition().getPatterns();
            RateLimit rateLimit = entry.getValue().getMethodAnnotation(RateLimit.class); // 方法上的au
            if (rateLimit != null) {
                LimitMeta limitMeta = new LimitMeta(rateLimit.window(), rateLimit.maxRequests(), rateLimit.punishmentTime(), rateLimit.minInterval(), rateLimit.associatedPatterns(), rateLimit.bannedType());
                for (RequestMethod method : methods) {
                    for (String patternValue : patternValues) {
                        Map<String, LimitMeta> map = httpdLimitedMetaMap.get(method.toString());
                        if (map == null) {
                            map = new HashMap<>();
                            httpdLimitedMetaMap.put(method.toString(), map);
                        }
                        map.put(contextPath + patternValue, limitMeta);
                    }
                }
            } else {
                for (RequestMethod method : methods) {
                    for (String patternValue : patternValues) {
                        LimitMeta limitMeta = cMap.get(entry.getValue().getBeanType().getName());
                        if (limitMeta != null) {
                            Map<String, LimitMeta> map = httpdLimitedMetaMap.get(method.toString());
                            if (map == null) {
                                map = new HashMap<>();
                                httpdLimitedMetaMap.put(method.toString(), map);
                            }
                            map.put(contextPath + patternValue, limitMeta);
                        }
                    }
                }
            }

            HashMap<String, Httpd.RequestPool> requestPool = new HashMap<>();

            entry.getKey().getMethodsCondition().getMethods().forEach(method -> {
                entry.getKey().getPatternsCondition().getPatterns().forEach(patternValue -> requestPool.put(contextPath + patternValue, new Httpd.RequestPool()));
                ConcurrentHashMap<String, Httpd.RequestPool> reqMap = httpd.getRequestPools().get(method.toString());
                if (reqMap == null) {
                    reqMap = new ConcurrentHashMap<>();
                    httpd.getRequestPools().put(method.toString(), reqMap);
                }
                reqMap.putAll(requestPool);
            });

        }
    }

    private void initUserDevicesDict() {
        DeviceConfig.isSupportMultiDevice = properties.getUser().isSupportMultiDevice();
        DeviceConfig.isSupportMultiUserForSameDeviceType = properties.getUser().isSupportMultiUserForSameDeviceType();
    }

}
