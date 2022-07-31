package cn.omisheep.authz.core.tk;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class IssueToken {
    private String    accessToken;
    private String    refreshToken;
    private Integer   expiresIn;
    private String    scope;

    public IssueToken(TokenPair tokenPair) {
        this.accessToken  = tokenPair.getAccessToken().getToken();
        this.refreshToken = tokenPair.getAccessToken().getToken();
        this.scope        = tokenPair.getAccessToken().getScope();
        this.expiresIn    = tokenPair.getAccessToken().getExpiresIn();
    }

}
