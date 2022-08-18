package cn.omisheep.authz.core.util.ua;

import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

import static cn.omisheep.authz.core.util.ua.MatchUtils.match;


/**
 * @author zhouxinchen
 * @since 1.2.7
 */
public enum Platform implements UserAgentInfo {

    /**
     * 未知
     */
    UNKNOWN(NAME_UNKNOWN, null),
    /**
     * Iphone
     */
    IPHONE("iPhone", "iphone"),
    /**
     * ipod
     */
    IPOD("iPod", "ipod"),
    /**
     * ipad
     */
    IPAD("iPad", "ipad"),
    /**
     * android
     */
    ANDROID("Android", "android"),
    /**
     * android
     */
    GOOGLE_TV("GoogleTV", "googletv"),
    /**
     * Windows Phone
     */
    WINDOWS_PHONE("Windows Phone", "windows (ce|phone|mobile)( os)?"),
    /**
     * htcFlyer
     */
    HTC_FLYER("htcFlyer", "htc_flyer"),
    /**
     * Symbian
     */
    SYMBIAN("Symbian", "symbian(os)?"),
    /**
     * Blackberry
     */
    BLACKBERRY("Blackberry", "blackberry"),
    /**
     * Windows
     */
    WINDOWS("Windows", "windows"),
    /**
     * Mac
     */
    MAC("Mac", "(macintosh|darwin)"),
    /**
     * Linux
     */
    LINUX("Linux", "linux"),
    /**
     * Wii
     */
    WII("Wii", "wii"),
    /**
     * Playstation
     */
    PLAYSTATION("Playstation", "playstation"),
    /**
     * Java
     */
    JAVA("Java", "java");

    /**
     * 支持的移动平台类型
     */
    public static final List<Platform> mobilePlatforms = Arrays.asList(
            WINDOWS_PHONE,
            IPAD,
            IPOD,
            IPHONE,
            ANDROID,
            GOOGLE_TV,
            HTC_FLYER,
            SYMBIAN,
            BLACKBERRY
    );

    /**
     * 支持的桌面平台类型
     */
    public static final List<Platform> desktopPlatforms = Arrays.asList(
            WINDOWS,
            MAC,
            LINUX,
            WII,
            PLAYSTATION,
            JAVA
    );

    private final String  name;
    private final Pattern regex;

    Platform(String name,
             String regex) {
        this.name  = name;
        this.regex = (regex == null) ? null : Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
    }

    /**
     * 是否为移动平台
     *
     * @return 是否为移动平台
     */
    public boolean isMobile() {
        return mobilePlatforms.contains(this);
    }

    /**
     * 是否为PC端
     *
     * @return 是否为PC
     */
    public boolean isPC() {
        return desktopPlatforms.contains(this);
    }

    /**
     * 是否为Iphone或者iPod设备
     *
     * @return 是否为Iphone或者iPod设备
     */
    public boolean isIPhoneOrIPod() {
        return this.equals(IPHONE) || this.equals(IPOD);
    }

    /**
     * 是否为Iphone或者iPod设备
     *
     * @return 是否为Iphone或者iPod设备
     */
    public boolean isIPad() {
        return this.equals(IPAD);
    }

    /**
     * 是否为IOS平台，包括IPhone、IPod、IPad
     *
     * @return 是否为IOS平台，包括IPhone、IPod、IPad
     */
    public boolean isIos() {
        return isIPhoneOrIPod() || isIPad();
    }

    /**
     * 是否为Android平台，包括Android和Google TV
     *
     * @return 是否为Android平台，包括Android和Google TV
     */
    public boolean isAndroid() {
        return this.equals(ANDROID) || this.equals(GOOGLE_TV);
    }

    @Override
    public String getName() {
        return name;
    }

    boolean isMatch(String content) {
        return match(this.regex, content);
    }

}
