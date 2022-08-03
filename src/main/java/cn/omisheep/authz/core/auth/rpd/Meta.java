package cn.omisheep.authz.core.auth.rpd;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;
import lombok.experimental.Accessors;

import java.util.Set;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
@Data
@Accessors(chain = true)
@JsonInclude(NON_NULL)
public class Meta {

    Set<Set<String>> require;
    Set<Set<String>> exclude;

    public boolean non() {
        return (require == null || require.size() == 0) && (exclude == null || exclude.size() == 0);
    }

    @Override
    public String toString() {
        return (require != null ? "require: " + require : "") + (exclude != null ? "\t, exclude: " + exclude : "");
    }

}
