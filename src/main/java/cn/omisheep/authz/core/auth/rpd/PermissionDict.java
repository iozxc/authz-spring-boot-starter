package cn.omisheep.authz.core.auth.rpd;

import cn.omisheep.authz.core.auth.PermRolesMeta;
import lombok.Getter;
import lombok.Setter;

import java.util.HashMap;
import java.util.Map;

/**
 * @author zhou xin chen
 */
@Getter
public class PermissionDict {

    @Setter
    private String permSeparator;

    /**
     * 权限
     */
    private final Map<String, Map<String, PermRolesMeta>> authzMetadata = new HashMap<>();
}
