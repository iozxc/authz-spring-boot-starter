package cn.omisheep.authz.core.util.ua;

import org.apache.commons.lang.StringUtils;

/**
 * @author zhouxinchen
 * @since 1.2.7
 */
public class UserAgentParser {

    private UserAgentParser() {
        throw new UnsupportedOperationException();
    }

    /**
     * 解析User-Agent
     *
     * @param userAgentString User-Agent字符串
     * @return {@link UserAgent}
     */
    public static UserAgent parse(String userAgentString) {
        if (StringUtils.isBlank(userAgentString)) {
            return new UserAgent()
                    .setUserAgentString(userAgentString)
                    .setPlatform(Platform.UNKNOWN)
                    .setOs(OS.UNKNOWN)
                    .setBrowser(Browser.UNKNOWN);
        }
        final UserAgent userAgent = new UserAgent().setUserAgentString(userAgentString);

        // 浏览器
        final Browser browser = parseBrowser(userAgentString);
        userAgent.setBrowser(browser);
        userAgent.setVersion(browser.getVersion(userAgentString));

        // 操作系统
        final OS os = parseOS(userAgentString);
        userAgent.setOs(os);

        // 平台
        final Platform platform = parsePlatform(userAgentString);
        userAgent.setPlatform(platform);

        return userAgent;
    }

    /**
     * 解析浏览器类型
     *
     * @param userAgentString User-Agent字符串
     * @return 浏览器类型
     */
    private static Browser parseBrowser(String userAgentString) {
        for (Browser browser : Browser.values()) {
            if (browser.isMatch(userAgentString)) {
                return browser;
            }
        }
        return Browser.UNKNOWN;
    }

    /**
     * 解析系统类型
     *
     * @param userAgentString User-Agent字符串
     * @return 系统类型
     */
    private static OS parseOS(String userAgentString) {
        for (OS os : OS.values()) {
            if (os.isMatch(userAgentString)) {
                return os;
            }
        }
        return OS.UNKNOWN;
    }

    /**
     * 解析平台类型
     *
     * @param userAgentString User-Agent字符串
     * @return 平台类型
     */
    private static Platform parsePlatform(String userAgentString) {
        for (Platform platform : Platform.values()) {
            if (platform.isMatch(userAgentString)) {
                return platform;
            }
        }
        return Platform.UNKNOWN;
    }

}
