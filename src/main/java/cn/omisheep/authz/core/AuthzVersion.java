package cn.omisheep.authz.core;

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

}
