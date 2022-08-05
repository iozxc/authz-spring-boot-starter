package cn.omisheep.authz.core.schema;

import cn.omisheep.commons.util.web.JSONUtils;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;
import lombok.experimental.Accessors;

import java.util.List;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
@Data
@Accessors(chain = true)
public class Model {
    protected String            typeName;
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    protected List<ModelMember> members;
    protected boolean           isArray;
    protected boolean           isCollection;

    public Model() {
    }

    public Model(String typeName) {
        this.typeName = typeName;
    }

    @Override
    public String toString() {
        return JSONUtils.toJSONString(this);
    }
}
