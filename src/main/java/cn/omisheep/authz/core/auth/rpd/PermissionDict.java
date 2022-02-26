package cn.omisheep.authz.core.auth.rpd;

import lombok.Getter;
import lombok.Setter;

import java.util.HashMap;
import java.util.Map;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
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
