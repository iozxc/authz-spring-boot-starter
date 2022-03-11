package cn.omisheep.authz.core.msg;

import lombok.Data;
import lombok.experimental.Accessors;

import java.util.function.Consumer;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
@Data
@Accessors(chain = true)
public class RequestMessage implements Message {

    public static String APP_NAME;
    public static String CHANNEL;
    private String id = Message.uuid;
    private String context = CHANNEL;
    private String method;
    private String api;
    private String ip;
    private long now;
    private String msg = "hello";

    public static boolean ignore(RequestMessage message) {
        return message == null || Message.uuid.equals(message.getId()) || !message.context.equals(CHANNEL);
    }

    public static Consumer<String> c = (s) -> {
        APP_NAME = s;
        CHANNEL = "AU_CONTEXT_CLOUD_APP_ID:" + s;
    };
}
