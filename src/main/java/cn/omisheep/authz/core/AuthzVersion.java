package cn.omisheep.authz.core;

import cn.omisheep.commons.util.Color;

import java.io.File;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.1.2
 */
public class AuthzVersion {
    private AuthzVersion() {
    }

    public static String getVersion() {
        Package pkg = AuthzVersion.class.getPackage();
        return (pkg != null ? pkg.getImplementationVersion() : null);
    }

    public static void printBanner() {
        Color.RESET.println("               _    _          ");
        Color.RESET.print("      ");
        Color.RAND.print(":)");
        Color.RESET.println("      | |  | |         ");
        Color.RESET.println("  __ _  _   _ | |_ | |__   ____");
        Color.RESET.println(" / _` || | | || __|| '_ \\ |_  /");
        Color.RESET.println("| (_| || |_| || |_ | | | | / / ");
        Color.RESET.println(" \\__,_| \\__,_| \\__||_| |_|/___|");
        Color.RESET.println("  \t\t Authz  v" + getVersion());
    }

    /**
     * 源码磁盘目录
     */
    public static final String SRC_FOLDER = new File(
            AuthzVersion.class.getClassLoader().getResource("").getPath()).toString();

    /**
     * 获取操作系统名称
     */
    private static final String OS_NAME = System.getProperty("os.name").toLowerCase();

    /**
     * 是否苹果操作系统
     */
    public static final boolean isMac = OS_NAME.contains("mac");

    /**
     * 是否视窗操作系统
     */
    public static final boolean isWindows = OS_NAME.contains("window");

    /**
     * 是否 Linux 操作系统
     */
    public static final boolean isLinux = OS_NAME.contains("linux");

}
