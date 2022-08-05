package cn.omisheep.authz.core;

import cn.omisheep.commons.util.Color;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.1.2
 */
public class AuthzVersion {

    private AuthzVersion() {
        throw new UnsupportedOperationException();
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

}
