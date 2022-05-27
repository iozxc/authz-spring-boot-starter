package cn.omisheep.authz.core.auth;

import java.util.Set;

/**
 * 参数和返回值都不为空
 * {@link org.springframework.lang.NonNull}
 *
 * @param <K> userId类型
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
public interface PermLibrary<K> {
    Set<String> getRolesByUserId(K userId);

    Set<String> getPermissionsByRole(String role);
}
