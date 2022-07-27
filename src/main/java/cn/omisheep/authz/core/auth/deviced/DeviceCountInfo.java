package cn.omisheep.authz.core.auth.deviced;

import lombok.Data;
import lombok.experimental.Accessors;

import java.util.Set;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.2.0
 */
@Data
@Accessors(chain = true)
public class DeviceCountInfo {
    private Set<String> types;
    private int         total;

    public int getTotal() {
        return Math.max(1, total);
    }
}