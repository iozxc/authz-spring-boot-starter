package cn.omisheep.authz.core;

import cn.omisheep.commons.util.Color;

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
        Color.WHITE_BOLD.println("               _    _          ");
        Color.WHITE_BOLD.print("      ");
        Color.RAND.print(":)");
        Color.WHITE_BOLD.println("      | |  | |         ");
        Color.WHITE_BOLD.println("  __ _  _   _ | |_ | |__   ____");
        Color.WHITE_BOLD.println(" / _` || | | || __|| '_ \\ |_  /");
        Color.WHITE_BOLD.println("| (_| || |_| || |_ | | | | / / ");
        Color.WHITE_BOLD.println(" \\__,_| \\__,_| \\__||_| |_|/___|");
        Color.GREEN_BOLD_BRIGHT.print("  \t\tAuthz  ");
        Color.RESET.print("v" + getVersion());
        Color.RESET.println();
    }
}
