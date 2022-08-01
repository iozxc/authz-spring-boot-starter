package cn.omisheep.authz.core.tk;

import com.fasterxml.jackson.annotation.JsonValue;

/**
 * 授权方式
 *
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.2.0
 */
public enum GrantType {

    /**
     * 授权码模式
     */
    AUTHORIZATION_CODE("authorization_code"),

    /**
     * 密码模式(使用用户名，密码，直接获取token，在authz中为登录之后直接获取token)
     */
    PASSWORD("password"),

    /**
     * 客户端模式(无用户,用户向客户端注册,然后客户端以自己的名义向’服务端’获取资源)
     */
    CLIENT_CREDENTIALS("client_credentials");

    @JsonValue
    private final String type;

    GrantType(String type) {
        this.type = type;
    }

    public String getType() {
        return type;
    }

    public static GrantType grantType(String type) {
        for (GrantType value : GrantType.values()) {
            if (value.type.equals(type)) {
                return value;
            }
        }
        return null;
    }
}
