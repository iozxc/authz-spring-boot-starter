package cn.omisheep.authz.support.entity;

import com.google.common.base.Objects;
import lombok.Data;
import lombok.experimental.Accessors;

import java.util.List;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
@Data
@Accessors(chain = true)
public class User {
    private String       username;
    private String       password;
    private List<String> permissions;

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
