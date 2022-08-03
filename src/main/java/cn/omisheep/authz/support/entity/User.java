package cn.omisheep.authz.support.entity;

import cn.omisheep.authz.core.AuthzProperties;
import com.google.common.base.Objects;
import lombok.Data;
import lombok.experimental.Accessors;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
@Data
@Accessors(chain = true)
public class User {
    private String username;
    private String password;
    private String uuid;
    private String ip;

    public User() {
    }

    public User(AuthzProperties.DashboardConfig.User user) {
        this.username = user.getUsername();
        this.password = user.getPassword();
        this.uuid     = null;
        this.ip       = user.getIp();
    }

    public User(String username,
                String password,
                String ip) {
        this.username = username;
        this.password = password;
        this.ip       = ip;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof User)) return false;
        User user = (User) o;
        return Objects.equal(getUsername(), user.getUsername());
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(getUsername());
    }
}
