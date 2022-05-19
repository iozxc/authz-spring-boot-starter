package cn.omisheep.authz.core.msg;

import cn.omisheep.authz.core.VersionInfo;
import cn.omisheep.authz.core.auth.AuthzModifier;
import lombok.Data;
import lombok.experimental.Accessors;

import java.util.List;
import java.util.Objects;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
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

    public VersionMessage(int version, String md5) {
        this.version = version;
        this.md5     = md5;
    }

    public VersionMessage(AuthzModifier authzModifier, int version, String md5) {
        this.authzModifier = authzModifier;
        this.version       = version;
        this.md5           = md5;
    }

    public VersionMessage(List<AuthzModifier> changelog, int version, String md5) {
        this.authzModifierList = changelog;
        this.version           = version;
        this.md5               = md5;
    }

    public static boolean ignore(VersionMessage message) {
        return message == null || Message.uuid.equals(message.getId()) || !message.context.equals(CHANNEL) ||
                !Objects.equals(message.md5, VersionInfo.md5);
    }

}
