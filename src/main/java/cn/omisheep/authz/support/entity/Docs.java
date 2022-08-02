package cn.omisheep.authz.support.entity;

import cn.omisheep.authz.core.AuthzVersion;
import cn.omisheep.authz.core.auth.ipf.Httpd;
import cn.omisheep.authz.core.auth.ipf.LimitMeta;
import cn.omisheep.authz.core.auth.rpd.PermissionDict;
import cn.omisheep.authz.core.config.AuthzAppVersion;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.experimental.Accessors;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Authz 文档生成
 *
 * @author zhouxinchen
 * @since 1.2.0
 */
@Accessors(chain = true)
public class Docs {

    public static final String VERSION      = "v1";
    public static final String VERSION_PATH = "/v1";
    @Getter
    @JsonProperty(index = 1)
    private final       String authz        = AuthzVersion.getVersion();

    @Getter
    @JsonProperty(index = 2)
    private License license = new License();

    @Getter
    @JsonProperty(index = 3)
    private final Info info;


    public Docs(Info info) {
        this.info = info;
    }

    @JsonProperty(index = 4)
    public Map<String, Object> getAppVersionInfo() {
        return AuthzAppVersion.getVersion();
    }

    @JsonProperty(index = 5)
    public Map<String, List<Map<String, String>>> getControllers() {
        return PermissionDict.getControllerMetadata();
    }

    @JsonProperty(index = 6)
    public Map<String, Map<String, Map<String, Object>>> getPaths() {
        Map<String, Map<String, LimitMeta>>               rateLimitMetadata = Httpd.getRateLimitMetadata();
        HashMap<String, Map<String, Map<String, Object>>> map               = new HashMap<>();
        PermissionDict.getRawParamMap().forEach((k, v) -> {
            Map<String, Map<String, Object>> m = map.computeIfAbsent(k, r -> new HashMap<>());
            v.forEach((_k, _v) -> {
                Map<String, Object> mm = m.computeIfAbsent(_k, r -> new HashMap<>());
                mm.put("paramInfo", _v);
                mm.put("requireLogin", false);
                mm.put("isAuth", false);
                Map<String, LimitMeta> limitMetaMap = rateLimitMetadata.get(k);
                if (limitMetaMap != null) {mm.put("hasRateLimit", limitMetaMap.containsKey(_k));}
                else {
                    mm.put("hasRateLimit", false);
                }
            });
        });
        PermissionDict.getRolePermission().forEach((k, v) -> {
            Map<String, Map<String, Object>> m = map.computeIfAbsent(k, r -> new HashMap<>());
            v.forEach((_k, _v) -> {
                Map<String, Object> mm = m.computeIfAbsent(_k, r -> new HashMap<>());
                mm.put("auth", _v);
                mm.put("isAuth", !_v.nonAll());
                mm.put("requireLogin", !_v.non());
            });
        });
        PermissionDict.getCertificatedMetadata().forEach((k, v) -> {
            Map<String, Map<String, Object>> m = map.computeIfAbsent(k, r -> new HashMap<>());
            v.forEach(meth -> m.computeIfAbsent(meth, r -> new HashMap<>()).put("requireLogin", true));
        });
        return map;
    }

    @JsonProperty(index = 7)
    public Map<String, Map<String, LimitMeta>> getRateLimit() {
        return Collections.unmodifiableMap(Httpd.getRateLimitMetadata());
    }

    @JsonProperty(index = 8)
    public Map<String, PermissionDict.ArgsMeta> getArgResource() {
        return PermissionDict.getArgs();
    }

    @JsonProperty(index = 9)
    public List<AuthzAppVersion.ConnectInfo> conns() { // 实例
        return AuthzAppVersion.getConnectInfo().get(AuthzAppVersion.LOCAL_CONNECT);
    }

//    @JsonProperty(index = 6)
//    public Map<String, Object> getBlacklist() {
//        return Blacklist.readAll();
//    }

//    @JsonProperty(index = 9)
//    public String[] getIgnoreSuffix() {
//        return httpd.getIgnoreSuffix().clone();
//    }
}
