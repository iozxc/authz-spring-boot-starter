package cn.omisheep.authz.core.util.ua;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;
import lombok.experimental.Accessors;
import org.apache.commons.lang.StringUtils;

import java.io.Serializable;

/**
 * @author zhouxinchen
 * @since 1.2.7
 */
@Accessors(chain = true)
@Data
public class UserAgent implements Serializable {

    private static final long serialVersionUID = 1L;

    /**
     * 浏览器类型
     */
    private Browser browser;
    /**
     * 浏览器版本
     */
    private String  version;

    /**
     * 平台类型
     */
    private Platform platform;

    /**
     * 系统类型
     */
    private OS os;

    @JsonIgnore
    private String userAgentString;


    /**
     * 是否为移动平台
     *
     * @return 是否为移动平台
     */
    public boolean isMobile() {
        return platform.isMobile() || browser.isMobile();
    }

    /**
     * 设置是否为PC
     *
     * @return 是否为PC
     */
    public boolean isPC() {
        return platform.isPC();
    }

    public String getOsVersion() {
        if (StringUtils.isBlank(userAgentString)) return null;
        return browser.getVersion(userAgentString);
    }

}
