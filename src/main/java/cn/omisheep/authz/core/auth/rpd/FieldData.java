package cn.omisheep.authz.core.auth.rpd;

import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@Data
@AllArgsConstructor
public class FieldData {
    private String             className;
    private Meta roles;
    private Meta permissions;
}
