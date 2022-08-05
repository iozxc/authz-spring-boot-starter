package cn.omisheep.authz.core.auth.rpd;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.experimental.Accessors;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@EqualsAndHashCode(callSuper = true)
@Data
@Accessors(chain = true)
public class FieldDataPermRolesMeta extends PermRolesMeta {
    final String className;

    public static FieldDataPermRolesMeta of(String className,
                                            PermRolesMeta permRolesMeta) {
        if (permRolesMeta == null || permRolesMeta.non()) return null;
        FieldDataPermRolesMeta fieldDataPermRolesMeta = new FieldDataPermRolesMeta(className);
        fieldDataPermRolesMeta.roles       = permRolesMeta.roles;
        fieldDataPermRolesMeta.permissions = permRolesMeta.permissions;
        return fieldDataPermRolesMeta;
    }

}
