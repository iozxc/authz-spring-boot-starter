package cn.omisheep.authz.core.msg;

import lombok.Data;
import lombok.experimental.Accessors;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@Data
@Accessors(chain = true)
public class RequestMessage implements Message {


    public static String CHANNEL;
    private       String id      = Message.uuid;
    private       String context = CHANNEL;

    private String method;
    private String api;
    private String ip;
    private long   now;

    public RequestMessage() {
    }

    public RequestMessage(String method, String api, String ip, long now) {
        this.method = method;
        this.api    = api;
        this.ip     = ip;
        this.now    = now;
    }

    public static boolean ignore(RequestMessage message) {
        return message == null || Message.uuid.equals(message.getId()) || !message.context.equals(CHANNEL);
    }
}
