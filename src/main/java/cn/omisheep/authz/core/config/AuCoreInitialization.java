package cn.omisheep.authz.core.config;

import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.AuthzVersion;
import cn.omisheep.authz.core.auth.DefaultPermLibrary;
import cn.omisheep.authz.core.auth.PermLibrary;
import cn.omisheep.authz.core.auth.deviced.DeviceConfig;
import cn.omisheep.authz.core.auth.deviced.UserDevicesDict;
import cn.omisheep.authz.core.auth.ipf.Httpd;
import cn.omisheep.authz.core.auth.rpd.AuthzDefender;
import cn.omisheep.authz.core.auth.rpd.PermissionDict;
import cn.omisheep.authz.core.cache.Cache;
import cn.omisheep.authz.core.codec.AuthzRSAManager;
import cn.omisheep.authz.core.msg.Message;
import cn.omisheep.authz.core.oauth.OpenAuthDict;
import cn.omisheep.authz.core.oauth.OpenAuthLibrary;
import cn.omisheep.authz.core.util.AUtils;
import cn.omisheep.authz.core.util.LogUtils;
import cn.omisheep.commons.util.TaskBuilder;
import lombok.SneakyThrows;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.system.ApplicationHome;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.handler.AbstractHandlerMethodMapping;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;

import java.util.Map;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@SuppressWarnings("all")
public class AuCoreInitialization implements ApplicationContextAware {

    private       ApplicationContext ctx;
    private final AuthzProperties    properties;
    private final UserDevicesDict    userDevicesDict;
    private final PermLibrary        permLibrary;
    private final Cache              cache;
    private final OpenAuthLibrary    openAuthLibrary;

    public AuCoreInitialization(AuthzProperties properties,
                                UserDevicesDict userDevicesDict,
                                PermLibrary permLibrary, OpenAuthLibrary openAuthLibrary, Cache cache) {
        this.properties      = properties;
        this.userDevicesDict = userDevicesDict;
        this.cache           = cache;
        this.permLibrary     = permLibrary;
        this.openAuthLibrary = openAuthLibrary;
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) {
        ctx = applicationContext;
        AUtils.init(applicationContext);
        init();
        CallbackInit.callbackInit(applicationContext);
        chechPermLibrary();
        printBanner();
    }

    public void printBanner() {
        if (properties.isBanner()) {
            AuthzVersion.printBanner();
        }
    }

    public void chechPermLibrary() {
        PermLibrary bean = ctx.getBean(PermLibrary.class);
        if (bean == null || bean instanceof DefaultPermLibrary) {
            AuInit.log.warn(
                    "not configured PermLibrary，Possible error in permission acquisition. Please implements cn.omisheep.authz.core.auth.PermLibrary");
        }
    }

    @SneakyThrows
    public void init() {
        AuthzAppVersion.init(properties.getApp());
        AbstractHandlerMethodMapping<RequestMappingInfo> methodMapping =
                (AbstractHandlerMethodMapping<RequestMappingInfo>) ctx.getBean("requestMappingHandlerMapping");
        Map<RequestMappingInfo, HandlerMethod> mapRet = methodMapping.getHandlerMethods();

        // init PermissionDict
        PermissionDict.init(properties, ctx, permLibrary, cache, mapRet);
        LogUtils.debug("PermissionDict init success \n");

        OpenAuthDict.init(properties, ctx, permLibrary, cache, mapRet);
        LogUtils.debug("OpenAuthDict init success \n");
//        initOpenAuthDict(ctx, mapRet);

        // init Httpd
        Httpd.init(properties, ctx, mapRet);
        LogUtils.debug("Httpd init success \n");

        // init UserDevicesDict
        initUserDevicesDict();
        LogUtils.debug("UserDevicesDict init success");

        AuthzDefender.init(userDevicesDict, permLibrary);

        // init Jobs
        AuthzRSAManager.setTime(properties.getRsa().getRsaKeyRefreshWithPeriod());
        if (properties.getRsa().isAuto() && (properties.getRsa().getCustomPrivateKey() == null || properties.getRsa().getCustomPublicKey() == null)) {
            AuthzRSAManager.setAuto(true);
        } else {
            AuthzRSAManager.setAuto(false);
            AuthzProperties.RSAConfig rsaConfig = properties.getRsa();
            AuthzRSAManager.setAuKeyPair(rsaConfig.getCustomPublicKey(), rsaConfig.getCustomPrivateKey());
        }

        if (!properties.getCache().isEnableRedis()) {
            TaskBuilder.schedule(Pelcron::activeExpireCycle, properties.getUserBufferRefreshWithPeriod());
        }
        TaskBuilder.schedule(Pelcron::GC, properties.getGcPeriod());

        openAuthLibrary.init();

        AuInit.log.info("Started Authz Message id: {}", Message.uuid);

        initVersionInfo();
        if (properties.isMd5check()) {
            AuInit.log.info("project md5 => {}", AuthzAppVersion.getMd5());
        }
    }

    private void initVersionInfo() {
        try {
            AuthzAppVersion.setProjectPath(getJarPath());
            AuthzAppVersion.setMd5check(properties.isMd5check());
            if (properties.getCache().isEnableRedis()) {
                AuthzAppVersion.born();
            }
        } catch (Exception e) {
            // skip
        }
    }

    @SneakyThrows
    private String getJarPath() {
        Object o = ctx.getBeansWithAnnotation(SpringBootApplication.class).values().stream().findAny().orElse(null);
        if (o != null) {
            ApplicationHome home = new ApplicationHome(o.getClass());
            return home.getSource().getAbsolutePath();
        }
        return null;
    }

    private void initUserDevicesDict() {
        DeviceConfig.isSupportMultiDevice                = properties.getUser().isSupportMultiDevice();
        DeviceConfig.isSupportMultiUserForSameDeviceType = properties.getUser().isSupportMultiUserForSameDeviceType();
    }

}
