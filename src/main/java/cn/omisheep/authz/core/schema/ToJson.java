package cn.omisheep.authz.core.schema;

import cn.omisheep.commons.util.web.JSONUtils;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
public interface ToJson {

    default String toJson() {
        return JSONUtils.toJSONString(this);
    }

}
