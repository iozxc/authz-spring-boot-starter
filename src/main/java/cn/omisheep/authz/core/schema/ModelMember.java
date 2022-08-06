package cn.omisheep.authz.core.schema;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import lombok.experimental.Accessors;

import java.util.ArrayList;
import java.util.List;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
@EqualsAndHashCode(callSuper = true)
@Data
@ToString(callSuper = true)
@Accessors(chain = true)
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class ModelMember extends Model implements ToJson {

    @JsonProperty(index = 1)
    protected String memberName;

    protected List<ModelMember> members = new ArrayList<>();

    protected ModelObject item;

    protected List<ModelMember> items;

    public ModelMember(String typeName) {
        super(typeName);
    }

    public ModelMember(String typeName,
                       String memberName) {
        super(typeName);
        this.memberName = memberName;
    }

    @Override
    public ModelMember setTypeName(String typeName) {
        super.setTypeName(typeName);
        return this;
    }
}
