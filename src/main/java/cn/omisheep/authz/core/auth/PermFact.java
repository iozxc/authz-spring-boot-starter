package cn.omisheep.authz.core.auth;

import cn.omisheep.authz.PermLibrary;
import lombok.Getter;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;

import java.util.List;
import java.util.Map;

/**
 * qq: 1269670415
 *
 * @author zhou xin chen
 */
@SuppressWarnings("all")
public class PermFact implements ApplicationContextAware {

    @Getter
    private PermLibrary permLibrary;

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        Map<String, PermLibrary> map = applicationContext.getBeansOfType(PermLibrary.class);
        for (PermLibrary value : map.values()) {
            permLibrary = value;
        }
    }

    private List<String> getRolesByUserId(Object userId) {
        return permLibrary.getRolesByUserId(userId);
    }

    private List<String> getPermissionsByRole(String role) {
        return permLibrary.getPermissionsByRole(role);
    }

    /**
     * 如果返回为空，则会调用 getRolesByUserId 或者 getPermissionsByRole
     *
     * @param userId 用户id
     * @return 权限列表
     */
    private List<String> getPermissionsByUserId(Object userId) {
        return permLibrary.getPermissionsByUserId(userId);
    }


}
