package cn.omisheep.authz.core.util.ua;

import java.util.regex.Pattern;

import static cn.omisheep.authz.core.util.ua.MatchUtils.group;
import static cn.omisheep.authz.core.util.ua.MatchUtils.match;

/**
 * @author zhouxinchen
 * @since 1.2.7
 */
public enum OS implements UserAgentInfo {

    UNKNOWN(NAME_UNKNOWN, null),
    Windows_10("Windows 10 or Windows Server 2016", "windows nt 10\\.0", "windows nt (10\\.0)"),
    Windows_8_1("Windows 8.1 or Windows Server 2012R2", "windows nt 6\\.3", "windows nt (6\\.3)"),
    Windows_8("Windows 8 or Windows Server 2012", "windows nt 6\\.2", "windows nt (6\\.2)"),
    Windows_Vista("Windows Vista", "windows nt 6\\.0", "windows nt (6\\.0)"),
    Windows_7("Windows 7 or Windows Server 2008R2", "windows nt 6\\.1", "windows nt (6\\.1)"),
    Windows_2003("Windows 2003", "windows nt 5\\.2", "windows nt (5\\.2)"),
    Windows_XP("Windows XP", "windows nt 5\\.1", "windows nt (5\\.1)"),
    Windows_2000("Windows 2000", "windows nt 5\\.0", "windows nt (5\\.0)"),
    Windows_Phone("Windows Phone", "windows (ce|phone|mobile)( os)?", "windows (?:ce|phone|mobile) (\\d+([._]\\d+)*)"),
    Windows("Windows", "windows"),
    OSX("OSX", "os x (\\d+)[._](\\d+)", "os x (\\d+([._]\\d+)*)"),
    Android("Android", "Android", "Android (\\d+([._]\\d+)*)"),
    Linux("Linux", "linux"),
    Wii("Wii", "wii", "wii libnup/(\\d+([._]\\d+)*)"),
    PS3("PS3", "playstation 3", "playstation 3; (\\d+([._]\\d+)*)"),
    PSP("PSP", "playstation portable", "Portable\\); (\\d+([._]\\d+)*)"),
    iPad("iPad", "\\(iPad.*os (\\d+)[._](\\d+)", "\\(iPad.*os (\\d+([._]\\d+)*)"),
    iPhone("iPhone", "\\(iPhone.*os (\\d+)[._](\\d+)", "\\(iPhone.*os (\\d+([._]\\d+)*)"),
    YPod("YPod", "iPod touch[\\s\\;]+iPhone.*os (\\d+)[._](\\d+)", "iPod touch[\\s\\;]+iPhone.*os (\\d+([._]\\d+)*)"),
    YPad("YPad", "iPad[\\s\\;]+iPhone.*os (\\d+)[._](\\d+)", "iPad[\\s\\;]+iPhone.*os (\\d+([._]\\d+)*)"),
    YPhone("YPhone", "iPhone[\\s\\;]+iPhone.*os (\\d+)[._](\\d+)", "iPhone[\\s\\;]+iPhone.*os (\\d+([._]\\d+)*)"),
    Symbian("Symbian", "symbian(os)?"),
    Darwin("Darwin", "Darwin\\/([\\d\\w\\.\\-]+)", "Darwin\\/([\\d\\w\\.\\-]+)"),
    Adobe_Air("Adobe Air", "AdobeAir\\/([\\d\\w\\.\\-]+)", "AdobeAir\\/([\\d\\w\\.\\-]+)"),
    Java("Java", "Java[\\s]+([\\d\\w\\.\\-]+)", "Java[\\s]+([\\d\\w\\.\\-]+)");

    OS(String name,
       String regex) {
        this.name           = name;
        this.regex          = (regex == null) ? null : Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
        this.versionPattern = null;
    }

    OS(String name,
       String regex,
       String versionRegex) {
        this.name  = name;
        this.regex = (regex == null) ? null : Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
        if (versionRegex != null) {
            this.versionPattern = Pattern.compile(versionRegex, Pattern.CASE_INSENSITIVE);
        } else {
            this.versionPattern = null;
        }
    }


    private final String  name;
    private final Pattern regex;
    private final Pattern versionPattern;

    /**
     * 获取浏览器版本
     *
     * @param userAgentString User-Agent字符串
     * @return 版本
     */
    public String getVersion(String userAgentString) {
        if (isUnknown() || null == this.versionPattern) {
            // 无版本信息
            return null;
        }
        return group(this.versionPattern, userAgentString, 1);
    }

    @Override
    public String getName() {
        return name;
    }

    boolean isMatch(String content) {
        return match(this.regex, content);
    }

}
