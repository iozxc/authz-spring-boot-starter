package cn.omisheep.authz.support.entity;

import cn.omisheep.authz.core.AuthzVersion;
import cn.omisheep.authz.core.auth.ipf.Blacklist;
import cn.omisheep.authz.core.auth.ipf.Httpd;
import cn.omisheep.authz.core.auth.ipf.LimitMeta;
import cn.omisheep.authz.core.auth.rpd.PermissionDict;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.experimental.Accessors;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Authz 文档生成
 *
 * @author zhouxinchen
 * @since 1.2.0
 */
@Accessors(chain = true)
public class Docs {
    @Getter
    @JsonProperty(index = 1)
    private final String         authz = AuthzVersion.getVersion();
    @Getter
    @JsonProperty(index = 2)
    private final Info           info;
    private final Httpd          httpd;
    private final PermissionDict permissionDict;

    public Docs(Info info, Httpd httpd, PermissionDict permissionDict) {
        this.info           = info;
        this.httpd          = httpd;
        this.permissionDict = permissionDict;
    }

    @JsonProperty(index = 3)
    public Map<String, Map<String, Map<String, Object>>> getPaths() {
        HashMap<String, Map<String, Map<String, Object>>> map = new HashMap<>();
        permissionDict.getRawParamMap().forEach((k, v) -> {
            Map<String, Map<String, Object>> m = map.computeIfAbsent(k, r -> new HashMap<>());
            v.forEach((_k, _v) -> {
                Map<String, Object> mm = m.computeIfAbsent(_k, r -> new HashMap<>());
                mm.put("paramInfo", _v);
                mm.put("requireLogin", false);
            });
        });
        permissionDict.getRolePermission().forEach((k, v) -> {
            Map<String, Map<String, Object>> m = map.computeIfAbsent(k, r -> new HashMap<>());
            v.forEach((_k, _v) -> {
                Map<String, Object> mm = m.computeIfAbsent(_k, r -> new HashMap<>());
                mm.put("auth", _v);
                mm.put("requireLogin", !_v.non());
            });
        });
        permissionDict.getCertificatedMetadata().forEach((k, v) -> {
            Map<String, Map<String, Object>> m = map.computeIfAbsent(k, r -> new HashMap<>());
            v.forEach(meth -> m.computeIfAbsent(meth, r -> new HashMap<>()).put("requireLogin", true));
        });
        return map;
    }

    @JsonProperty(index = 4)
    public Map<String, Object> getBlacklist() {
        return Blacklist.readAll();
    }

    @JsonProperty(index = 5)
    public Map<String, Map<String, LimitMeta>> getRateLimit() {
        return Collections.unmodifiableMap(httpd.getRateLimitMetadata());
    }

    @JsonProperty(index = 6)
    public Map<String, PermissionDict.ArgsMeta> getArgResource() {
        return permissionDict.getArgs();
    }

    @JsonProperty(index = 7)
    public String[] getIgnoreSuffix() {
        return httpd.getIgnoreSuffix().clone();
    }
}
