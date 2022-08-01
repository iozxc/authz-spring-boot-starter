package cn.omisheep.authz.core.oauth;

import lombok.Data;
import lombok.experimental.Accessors;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
@Data
@Accessors(chain = true)
public class ClientDetails {
    /**
     * 接入的客户端的名称
     */
    private String clientName;
    /**
     * 回调地址
     */
    private String redirectUrl;
    /**
     * 接入的客户端的密钥
     */
    private String clientSecret;
    /**
     * 接入的客户端ID
     */
    private String clientId;
}
