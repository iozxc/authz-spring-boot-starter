package cn.omisheep.authz.core.auth.deviced;

import java.util.Date;

import static cn.omisheep.authz.core.config.Constants.ACCESS_TOKEN_EXPIRATION;
import static cn.omisheep.authz.core.config.Constants.REFRESH_TOKEN_ID;


/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
public class AccessInfo extends AuMap {

    public AccessInfo() {
        super();
    }

    public AccessInfo setExpiration(Date expirationDate) {
        setDate(ACCESS_TOKEN_EXPIRATION, expirationDate);
        return this;
    }

    public Date getExpiration() {
        return getDate(ACCESS_TOKEN_EXPIRATION);
    }

    public long getExpirationVal() {
        return Long.parseLong((String) get(ACCESS_TOKEN_EXPIRATION));
    }

    public AccessInfo setRefreshTokenId(String refreshTokenId) {
        setValue(REFRESH_TOKEN_ID, refreshTokenId);
        return this;
    }

    public String getRefreshTokenId() {
        return getString(REFRESH_TOKEN_ID);
    }

}
