package cn.omisheep.authz.core.aggregate;

import cn.omisheep.commons.util.CapacityRestrictedQueue;
import cn.omisheep.commons.util.TimeUtils;
import lombok.Data;
import org.springframework.util.Assert;

import java.io.Serializable;
import java.util.Arrays;

/**
 * qq: 1269670415
 *
 * @author zhou xin chen
 */
@Data
public class LatestMonths implements Summable, Serializable {
    private static final long serialVersionUID = -8475095254772414060L;

    private long[] list;
    private long total;

    private final CapacityRestrictedQueue<Month> months;

    public LatestMonths() {
        this(12);
    }

    public LatestMonths(int maxCapacity) {
        months = new CapacityRestrictedQueue<>(maxCapacity);
    }

    private void createMonth(int... yearAndMonth) {
        months.offerFirst(new Month(yearAndMonth[0], yearAndMonth[1]));
    }

    public void update(int dayInMonth, int num) {
        if (months.size() == 0) {
            createMonth(TimeUtils.yesterdayYearAndMonth());
            months.getFirst().set(dayInMonth, num);
        } else {
            Month first = months.getFirst();
            first.set(dayInMonth, num);
            if (first.getMonth() != TimeUtils.currentMonth()) {
                createMonth(TimeUtils.currentMonth());
            }
        }

        this.list = months.stream().mapToLong(Summable::getTotal).toArray();
        this.total = Arrays.stream(list).sum();
    }

    public void update(int num) {
        update(TimeUtils.nowMinus("1d").getDayOfMonth(), num);
    }

    @Data
    public static class Month implements Summable, Serializable {
        private static final long serialVersionUID = -8166291528042324667L;
        private long[] days;
        private long total = 0;

        private final String date = TimeUtils.nowString("y-M");
        private final int month = TimeUtils.currentMonth();

        public Month() {
            // to json string or serialize
        }

        public Month(int year, int month) {
            days = new long[TimeUtils.maxDaysInMonth(year, month)];
        }

        public void set(int dayInMonth, int num) {
            Assert.isTrue(num > 0, "ensure num > 0");
            Assert.isTrue(dayInMonth >= 0 && dayInMonth <= 31, "ensure dayInMonth from 1 to 31");
            total += num - days[dayInMonth - 1];
            days[dayInMonth - 1] = num;
        }

    }


}
