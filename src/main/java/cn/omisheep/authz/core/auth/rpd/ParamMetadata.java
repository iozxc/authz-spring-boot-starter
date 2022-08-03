package cn.omisheep.authz.core.auth.rpd;

import cn.omisheep.commons.util.NamingUtils;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonValue;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

import java.util.List;
import java.util.Locale;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_EMPTY;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Accessors(chain = true)
@JsonInclude(NON_EMPTY)
public class ParamMetadata {
    private Class<?>                 clz;
    private ParamType                paramType;
    private List<ParamPermRolesMeta> paramMetaList;

    public static ParamMetadata of(Class<?> clz,
                                   ParamType paramType,
                                   List<ParamPermRolesMeta> paramMetaList) {
        if (paramMetaList == null || paramMetaList.isEmpty()) return null;
        return new ParamMetadata(clz, paramType, paramMetaList);
    }

    public enum ParamType {
        PATH_VARIABLE("pathVariable"),
        REQUEST_PARAM("requestParam");

        @JsonValue
        private final String val;

        @JsonCreator
        public static ParamType create(String target) {
            return valueOf(NamingUtils.humpToUnderline(target).toUpperCase(Locale.ROOT));
        }

        ParamType(String val) {
            this.val = val;
        }

        public String getVal() {
            return val;
        }
    }

}