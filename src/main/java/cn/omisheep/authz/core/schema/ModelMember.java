package cn.omisheep.authz.core.schema;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
@EqualsAndHashCode(callSuper = true)
@Data
@ToString(callSuper = true)
public class ModelMember extends Model {
    private String memberName;

    public ModelMember(String typeName) {
        super(typeName);
    }

    public ModelMember(String typeName,
                       String memberName) {
        super(typeName);
        this.memberName = memberName;
    }


}
