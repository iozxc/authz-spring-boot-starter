package cn.omisheep.authz.core.tk;

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
    AUTHORIZATION_CODE("authorization_code");

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
