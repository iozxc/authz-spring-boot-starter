package cn.omisheep.authz.support.entity;

import cn.omisheep.authz.core.AuthzProperties;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.google.common.base.Objects;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
@Data
@Accessors(chain = true)
@NoArgsConstructor
public class User implements Cloneable {
    private String                                                    username;
    private String                                                    password;
    private String                                                    ip;
    private List<AuthzProperties.DashboardConfig.DashboardPermission> permissions;
    private String                                                    uuid;

    public User(AuthzProperties.DashboardConfig.User user) {
        this.username    = user.getUsername();
        this.password    = user.getPassword();
        this.ip          = user.getIp();
        this.permissions = Arrays.asList(user.getPermissions());
        this.uuid        = null;
    }

    public User(String username,
                String password,
                String ip,
                AuthzProperties.DashboardConfig.DashboardPermission[] permissions) {
        this.username    = username;
        this.password    = password;
        this.ip          = ip;
        this.permissions = Arrays.asList(permissions);
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

    @Override
    public User clone() {
        try {
            User clone = (User) super.clone();
            clone.permissions = new ArrayList<>(this.permissions);
            clone.username    = this.username;
            clone.password    = this.password;
            clone.ip          = this.ip;
            clone.uuid        = this.uuid;
            return clone;
        } catch (CloneNotSupportedException e) {
            throw new AssertionError();
        }
    }
}
