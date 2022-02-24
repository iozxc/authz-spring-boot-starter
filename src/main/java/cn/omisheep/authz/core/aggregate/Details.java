package cn.omisheep.authz.core.aggregate;

import cn.omisheep.authz.core.util.AUtils;
import lombok.Data;

import java.io.Serializable;

/**
 * 正常查询
 * 可以查看到月 日
 * <p>
 * 特别的
 * 只能查看近24小时内的 时 和 分
 * <p>
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
@Data
public class Details implements Serializable {

    private static final long serialVersionUID = 9209233157933461593L;

    private LatestHours latestHours;
    private LatestMonths latestMonths;

    public Details(int maxHourCapacity, int maxMonthCapacity) {
        latestMonths = new LatestMonths(maxMonthCapacity);
        latestHours = new LatestHours(maxHourCapacity);
    }

    public Details() {
        latestMonths = new LatestMonths();
        latestHours = new LatestHours();
    }

    public void updateHour(int num) {
        latestHours.update(num);
    }

    public void updateMonth(int num) {
        latestMonths.update(num);
    }

    @Override
    public String toString() {
        return AUtils.beautifulJson(this);
    }

}
