package cn.omisheep.authz.core.schema;

import lombok.Data;
import lombok.EqualsAndHashCode;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
@EqualsAndHashCode(callSuper = true)
@Data
public class ModelCollection extends Model implements ToJson {

    protected ModelObject item = new ModelObject();

    public ModelCollection(String typeName) {
        super(typeName);
    }

}
