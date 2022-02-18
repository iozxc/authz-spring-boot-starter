package cn.omisheep.authz.core.auth.rpd;

import cn.omisheep.authz.core.auth.PermRolesMeta;
import lombok.Getter;
import lombok.Setter;

import java.util.HashMap;
import java.util.HashSet;
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
    private final Map<String, Map<String, PermRolesMeta>> auMap = new HashMap<>();

    /**
     * 所有的api集合，提供快速访问
     */
    private final HashSet<String> paths = new HashSet<>();

    /**
     * 所有的api集合，提供快速访问，(加上contextPath)
     */
    private final HashSet<String> paddingPath = new HashSet<>();

    /**
     * 格式化之后的path 其中 {xx} 替换为 *
     */
    private final HashSet<String> patternPath = new HashSet<>();
}
