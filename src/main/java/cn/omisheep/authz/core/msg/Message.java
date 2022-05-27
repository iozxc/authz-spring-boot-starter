package cn.omisheep.authz.core.msg;

import java.util.UUID;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
public interface Message {
    String uuid = UUID.randomUUID().toString();
}
