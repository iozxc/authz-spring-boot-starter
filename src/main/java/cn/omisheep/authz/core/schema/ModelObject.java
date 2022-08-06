package cn.omisheep.authz.core.schema;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.experimental.Accessors;

import java.util.ArrayList;
import java.util.List;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
@EqualsAndHashCode(callSuper = true)
@Data
@Accessors(chain = true)
public class ModelObject extends Model implements ToJson {

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    protected List<ModelMember> members = new ArrayList<>();

    public ModelObject() {
    }

    public ModelObject(String typeName) {
        super(typeName);
    }

}
