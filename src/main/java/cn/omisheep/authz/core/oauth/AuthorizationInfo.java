package cn.omisheep.authz.core.oauth;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Data;
import lombok.experimental.Accessors;

import java.util.Date;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
@Data
@Accessors(chain = true)
public class AuthorizationInfo { //授权信息
    private final String clientId;
    private final String scope;
    private final Object userId;
    private final String deviceType;
    private final String deviceId;
    /**
     * 颁布时间
     */
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private final Date   issueTime;
    /**
     * 过期时间
     */
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private final Date   expiredTime;
}
