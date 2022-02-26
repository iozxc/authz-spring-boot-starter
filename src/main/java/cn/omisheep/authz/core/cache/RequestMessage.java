package cn.omisheep.authz.core.cache;

import lombok.Data;
import lombok.experimental.Accessors;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
@Data
@Accessors(chain = true)
public class RequestMessage {
    private String uuid = Message.id;
    private String msg = "hello";
}
