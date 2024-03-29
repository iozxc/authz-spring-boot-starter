package cn.omisheep.authz.core.msg;

import cn.omisheep.authz.core.config.AuthzAppVersion;
import lombok.Data;
import lombok.experimental.Accessors;

import java.util.List;
import java.util.Objects;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@Data
@Accessors(chain = true)
public class VersionMessage implements Message {
    public static String CHANNEL;
    private       String id      = Message.uuid;
    private       String context = CHANNEL;

    private int                 version;
    private AuthzModifier       authzModifier;
    private List<AuthzModifier> authzModifierList;
    private String              md5;
    private boolean             tag = false;


    public VersionMessage() {
    }

    public VersionMessage(int version) {
        this.version = version;
        if (AuthzAppVersion.isMd5check()) {
            this.md5 = AuthzAppVersion.getJarMd5();
        }
    }

    public VersionMessage(AuthzModifier authzModifier,
                          int version) {
        this.authzModifier = authzModifier;
        this.version       = version;
        if (AuthzAppVersion.isMd5check()) {
            this.md5 = AuthzAppVersion.getJarMd5();
        }
    }

    public VersionMessage(List<AuthzModifier> changelog,
                          int version) {
        this.authzModifierList = changelog;
        this.version           = version;
        if (AuthzAppVersion.isMd5check()) {
            this.md5 = AuthzAppVersion.getJarMd5();
        }
    }

    // 忽略条件
    public static boolean ignore(VersionMessage message) {
        return message == null // 消息为空
                || Message.uuid.equals(message.getId()) // 自己的消息
                || !message.context.equals(CHANNEL)// 不在一个频道
                || failureMd5Check(message); // md5检查失败
    }

    private static boolean failureMd5Check(VersionMessage message) {
        if (AuthzAppVersion.isMd5check()) {
            return !Objects.equals(message.md5, AuthzAppVersion.getJarMd5());
        } else {
            return false;
        }
    }

}
