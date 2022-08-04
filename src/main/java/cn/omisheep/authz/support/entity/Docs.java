package cn.omisheep.authz.support.entity;

import cn.omisheep.authz.core.AuthzVersion;
import cn.omisheep.authz.core.auth.ipf.Httpd;
import cn.omisheep.authz.core.auth.rpd.ArgsMeta;
import cn.omisheep.authz.core.auth.rpd.ParamMetadata;
import cn.omisheep.authz.core.auth.rpd.PermissionDict;
import cn.omisheep.authz.core.config.AuthzAppVersion;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.experimental.Accessors;

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
        HashMap<String, Map<String, Map<String, Object>>> map = new HashMap<>();

        PermissionDict.getParamPermission().forEach((api, v) -> v.forEach((method, param) -> {
            Map<String, Object> mm = map.computeIfAbsent(api, r -> new HashMap<>())
                    .computeIfAbsent(method, r -> new HashMap<>());
            boolean b = param != null && !param.isEmpty() && param.values()
                    .stream()
                    .anyMatch(ParamMetadata::hasParamAuth);
            mm.put("paramAuth", param);
            mm.put("hasParamAuth", b);
            mm.put("requireLogin", b);
            mm.put("hasRateLimit", false);
            mm.put("hasAuth", false);
        }));

        Httpd.getRateLimitMetadata().forEach((api, v) -> v.forEach((method, rateLimit) -> {
            Map<String, Object> mm = map.computeIfAbsent(api, r -> new HashMap<>())
                    .computeIfAbsent(method, r -> new HashMap<>());
            mm.put("hasRateLimit", true);
            mm.put("rateLimit", rateLimit);
        }));

        PermissionDict.getRolePermission().forEach((api, v) -> v.forEach((method, permRolesMeta) -> {
            Map<String, Object> mm = map.computeIfAbsent(api, r -> new HashMap<>())
                    .computeIfAbsent(method, r -> new HashMap<>());
            mm.put("auth", permRolesMeta);
            mm.put("hasAuth", !permRolesMeta.non());
            mm.put("requireLogin", !permRolesMeta.non());
        }));

        PermissionDict.getCertificatedMetadata()
                .forEach((k, v) -> v.forEach(meth -> map.computeIfAbsent(k, r -> new HashMap<>())
                        .computeIfAbsent(meth, r -> new HashMap<>())
                        .put("requireLogin", true)));

        return map;
    }

    @JsonProperty(index = 7)
    public Map<String, ArgsMeta> getArgResource() {
        return PermissionDict.getArgs();
    }

    @JsonProperty(index = 8)
    public List<AuthzAppVersion.ConnectInfo> conns() { // 实例
        return AuthzAppVersion.getConnectInfo().get(AuthzAppVersion.LOCAL_CONNECT);
    }

}
