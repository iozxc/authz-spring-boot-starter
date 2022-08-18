package cn.omisheep.authz.core.util.ua;

/**
 * @author zhouxinchen
 * @since 1.2.7
 */
public interface UserAgentInfo {

    /**
     * UNKNOWN
     */
    String NAME_UNKNOWN = "Unknown";

    /**
     * 其它版本
     */
    String OTHER_VERSION = "[\\/ ]([\\d\\w\\.\\-]+)";

    /**
     * 获取信息名称
     *
     * @return 信息名称
     */
    String getName();

    /**
     * 是否为Unknown
     *
     * @return 是否为Unknown
     */
    default boolean isUnknown() {
        return NAME_UNKNOWN.equals(getName());
    }

}
