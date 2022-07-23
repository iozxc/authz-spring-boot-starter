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
    private License license = new License();

    @Data
    public static class License {
        private String name = "Apache 2.0";
        private String url  = "http://www.apache.org/licenses/LICENSE-2.0";
    }
}
