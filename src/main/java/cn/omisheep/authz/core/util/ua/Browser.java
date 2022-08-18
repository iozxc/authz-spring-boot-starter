package cn.omisheep.authz.core.util.ua;

import java.util.regex.Pattern;

import static cn.omisheep.authz.core.util.ua.MatchUtils.group;
import static cn.omisheep.authz.core.util.ua.MatchUtils.match;

/**
 * 浏览器对象
 *
 * @author zhouxinchen
 * @since 1.2.7
 */
public enum Browser implements UserAgentInfo {

    /**
     * 未知
     */
    UNKNOWN(NAME_UNKNOWN, null, null),
    // 部分特殊浏览器是基于安卓、Iphone等的，需要优先判断
    // 企业微信 企业微信使用微信浏览器内核,会包含 MicroMessenger 所以要放在前面
    WXWORK("wxwork", "wxwork", "wxwork\\/([\\d\\w\\.\\-]+)"),
    // 微信
    MICRO_MESSENGER("MicroMessenger", "MicroMessenger", OTHER_VERSION),
    // 微信小程序
    MINI_PROGRAM("miniProgram", "miniProgram", OTHER_VERSION),
    // QQ浏览器
    QQ_BROWSER("QQBrowser", "MQQBrowser", "MQQBrowser\\/([\\d\\w\\.\\-]+)"),
    // 钉钉内置浏览器
    DING_TALK("DingTalk", "DingTalk", "AliApp\\(DingTalk\\/([\\d\\w\\.\\-]+)\\)"),
    // 支付宝内置浏览器
    ALIPAY("Alipay", "AlipayClient", "AliApp\\(AP\\/([\\d\\w\\.\\-]+)\\)"),
    // 淘宝内置浏览器
    TAOBAO("Taobao", "taobao", "AliApp\\(TB\\/([\\d\\w\\.\\-]+)\\)"),
    // UC浏览器
    UC_BROWSER("UCBrowser", "UC?Browser", "UC?Browser\\/([\\d\\w\\.\\-]+)"),
    // 夸克浏览器
    QUARK("Quark", "Quark", OTHER_VERSION),
    // 联想浏览器
    LENOVO("Lenovo", "SLBrowser", "SLBrowser/([\\d\\w\\.\\-]+)"),
    MS_EDGE("MSEdge", "Edge|Edg", "(?:edge|Edg|EdgA)\\/([\\d\\w\\.\\-]+)"),
    CHROME("Chrome", "chrome", OTHER_VERSION),
    FIREFOX("Firefox", "firefox", OTHER_VERSION),
    IE_MOBILE("IEMobile", "iemobile", OTHER_VERSION),
    ANDROID_BROWSER("Android Browser", "android", "version\\/([\\d\\w\\.\\-]+)"),
    SAFARI("Safari", "safari", "version\\/([\\d\\w\\.\\-]+)"),
    OPERA("Opera", "opera", OTHER_VERSION),
    KONQUEROR("Konqueror", "konqueror", OTHER_VERSION),
    PS3r("PS3", "playstation 3", "([\\d\\w\\.\\-]+)\\)\\s*$"),
    PSP("PSP", "playstation portable", "([\\d\\w\\.\\-]+)\\)?\\s*$"),
    LOTUS("Lotus", "lotus.notes", "Lotus-Notes\\/([\\w.]+)"),
    THUNDERBIRD("Thunderbird", "thunderbird", OTHER_VERSION),
    NETSCAPE("Netscape", "netscape", OTHER_VERSION),
    SEAMONKEY("Seamonkey", "seamonkey", OTHER_VERSION),
    OUTLOOK("Outlook", "microsoft.outlook", OTHER_VERSION),
    EVOLUTION("Evolution", "evolution", OTHER_VERSION),
    MSIE("MSIE", "msie", "msie ([\\d\\w\\.\\-]+)"),
    MSIE11("MSIE11", "rv:11", "rv:([\\d\\w\\.\\-]+)"),
    GABBLE("Gabble", "Gabble", OTHER_VERSION),
    YAMMER_DESKTOP("Yammer Desktop", "AdobeAir", "([\\d\\w\\.\\-]+)\\/Yammer"),
    YAMMER_MOBILE("Yammer Mobile", "Yammer[\\s]+([\\d\\w\\.\\-]+)", "Yammer[\\s]+([\\d\\w\\.\\-]+)"),
    APACHE_HTTP_CLIENT("Apache HTTP Client", "Apache\\\\-HttpClient", "Apache\\-HttpClient\\/([\\d\\w\\.\\-]+)"),
    BLACK_BERRY("BlackBerry", "BlackBerry", "BlackBerry[\\d]+\\/([\\d\\w\\.\\-]+)");

    private final String  name;
    private final Pattern regex;
    private       Pattern versionPattern;

    Browser(String name,
            String regex,
            String versionRegex) {
        this.name  = name;
        this.regex = (regex == null) ? null : Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
        if (OTHER_VERSION.equals(versionRegex)) {
            versionRegex = name + versionRegex;
        }
        if (null != versionRegex) {
            this.versionPattern = Pattern.compile(versionRegex, Pattern.CASE_INSENSITIVE);
        }
    }

    /**
     * 获取浏览器版本
     *
     * @param userAgentString User-Agent字符串
     * @return 版本
     */
    public String getVersion(String userAgentString) {
        if (isUnknown()) {
            return null;
        }
        return group(this.versionPattern, userAgentString, 1);
    }

    /**
     * 是否移动浏览器
     *
     * @return 是否移动浏览器
     */
    public boolean isMobile() {
        final String name = this.getName();
        return "PSP".equals(name) ||
                "Yammer Mobile".equals(name) ||
                "Android Browser".equals(name) ||
                "IEMobile".equals(name) ||
                "MicroMessenger".equals(name) ||
                "miniProgram".equals(name) ||
                "DingTalk".equals(name);
    }

    @Override
    public String getName() {
        return name;
    }

    boolean isMatch(String content) {
        return match(this.regex, content);
    }

}
