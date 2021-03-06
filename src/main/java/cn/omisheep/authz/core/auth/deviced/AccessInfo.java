package cn.omisheep.authz.core.auth.deviced;

import java.util.Date;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
public class AccessInfo extends AuMap {

    public static final String EXPIRATION       = "aex";
    public static final String REFRESH_TOKEN_ID = "rtid";

    public AccessInfo() {
        super();
    }

    public AccessInfo setExpiration(Date expirationDate) {
        setDate(EXPIRATION, expirationDate);
        return this;
    }

    public Date getExpiration() {
        return getDate(EXPIRATION);
    }

    public long getExpirationVal() {
        return Long.parseLong((String) get(EXPIRATION));
    }

    public AccessInfo setRefreshTokenId(String refreshTokenId) {
        setValue(REFRESH_TOKEN_ID, refreshTokenId);
        return this;
    }

    public String getRefreshTokenId() {
        return getString(REFRESH_TOKEN_ID);
    }

}
