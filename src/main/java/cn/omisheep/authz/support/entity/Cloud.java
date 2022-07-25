package cn.omisheep.authz.support.entity;

import cn.omisheep.authz.core.config.AuthzAppVersion;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.experimental.Accessors;

import java.util.List;
import java.util.Map;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
@Accessors(chain = true)
public class Cloud {

    @JsonProperty(index = 1)
    public Map<String, List<AuthzAppVersion.ConnectInfo>> getConnectInfo() {
        return AuthzAppVersion.getConnectInfo();
    }

}
