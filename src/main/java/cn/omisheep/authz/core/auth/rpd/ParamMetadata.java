package cn.omisheep.authz.core.auth.rpd;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonValue;
import lombok.Data;
import lombok.experimental.Accessors;

import java.util.List;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_EMPTY;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@Data
@Accessors(chain = true)
@JsonInclude(NON_EMPTY)
public class ParamMetadata {
    private Class<?>                 paramType;
    private List<PermRolesMeta.Meta> rolesMetaList;
    private List<PermRolesMeta.Meta> permissionsMetaList;

    public ParamMetadata(Class<?> paramType,
                         List<PermRolesMeta.Meta> rolesMetaList,
                         List<PermRolesMeta.Meta> permissionsMetaList) {
        this.paramType = paramType;
        if (rolesMetaList != null && !rolesMetaList.isEmpty()) this.rolesMetaList = rolesMetaList;
        if (permissionsMetaList != null && !permissionsMetaList.isEmpty()) this.permissionsMetaList = permissionsMetaList;
    }

    public ParamMetadata() {
    }

    public enum ParamType {
        PATH_VARIABLE("pathVariable"),
        REQUEST_PARAM("requestParam");

        @JsonValue
        private final String val;

        ParamType(String val) {
            this.val = val;
        }

        public String getVal() {
            return val;
        }
    }

}