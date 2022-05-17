package cn.omisheep.authz.core.auth.rpd;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;
import lombok.experimental.Accessors;

import java.util.List;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_EMPTY;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
@Data
@Accessors(chain = true)
@JsonInclude(NON_EMPTY)
public class ParamMetadata {
    private Class<?>                 paramType;
    private List<PermRolesMeta.Meta> rolesMetaList;
    private List<PermRolesMeta.Meta> permissionsMetaList;

    public enum ParamType {
        PATH_VARIABLE,
        REQUEST_PARAM
    }

}