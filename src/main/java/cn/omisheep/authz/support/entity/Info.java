package cn.omisheep.authz.support.entity;

import lombok.Data;
import lombok.experimental.Accessors;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
@Data
@Accessors(chain = true)
public class Info {
    private String  description;
    private String  version;
    private String  title;
}
