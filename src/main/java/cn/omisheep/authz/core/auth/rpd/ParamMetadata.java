package cn.omisheep.authz.core.auth.rpd;

import cn.omisheep.authz.core.schema.ModelParser;
import cn.omisheep.authz.core.util.ValueMatcher;
import cn.omisheep.commons.util.NamingUtils;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonValue;
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
@Accessors(chain = true)
@JsonInclude(NON_EMPTY)
public class ParamMetadata {
    @JsonIgnore
    private Class<?>                 clz;
    private ValueMatcher.ValueType   valueMatchType;
    private ParamType                paramType;
    private List<ParamPermRolesMeta> paramMetaList;

    public String getValueType() {
        return ModelParser.simpleTypeName(clz);
    }

    public ParamMetadata(Class<?> clz,
                         ParamType paramType,
                         List<ParamPermRolesMeta> paramMetaList) {
        this.valueMatchType = ValueMatcher.checkTypeByClass(clz);
        this.clz            = clz;
        this.paramType      = paramType;
        this.paramMetaList  = paramMetaList;
    }

    public boolean hasParamAuth() {
        return paramMetaList != null;
    }

    public static ParamMetadata of(Class<?> clz,
                                   ParamType paramType,
                                   List<ParamPermRolesMeta> paramMetaList) {
        return new ParamMetadata(clz, paramType, paramMetaList);
    }

    public static ParamMetadata of(Class<?> clz,
                                   ParamType paramType) {
        return new ParamMetadata(clz, paramType, null);
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