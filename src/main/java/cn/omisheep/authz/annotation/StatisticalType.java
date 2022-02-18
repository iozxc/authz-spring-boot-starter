package cn.omisheep.authz.annotation;

/**
 * qq: 1269670415
 *
 * @author zhou xin chen
 */
public enum StatisticalType {

    /**
     * 00:00-24:00内
     * 访问某站点的用户数，
     * 相同设备，不同用户，算做多次
     * 相同用户，不同设备，算做一次
     * 未注册用户忽略
     */
    UV, // Unique Visitor

    /**
     * 00:00-24:00内
     * 用户对同一页面的多次访问，访问量累计
     * 用户对某个页面怎么反复加载都算作一次PV
     */
    PV, // Page View

    /**
     * 00:00-24:00内 相同IP地址之被计算一次
     */
    IP, // Internet Protocol

    /**
     * 00:00-24:00内 所有访客访问了多少次您的网站
     */
    VV // Visit View
}
