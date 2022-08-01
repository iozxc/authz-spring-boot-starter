package cn.omisheep.authz.core.oauth;

import cn.omisheep.authz.core.callback.AuthorizationCallback;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;

import java.util.List;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
public interface OpenAuthLibrary extends AuthorizationCallback {

    /**
     * listAll 从数据库【获取】资源。用于初始化注册过的客户端信息
     *
     * @return 所有注册过的客户端信息 List（客户端id，客户端name，客户端密钥，重定向url）
     */
    @NonNull
    List<ClientDetails> init();

    /**
     * 从数据库【添加】资源，新增客户端信息
     *
     * @param clientDetails 客户端的详细信息（客户端id，客户端name，客户端密钥，重定向url）
     */
    void registerClient(@NonNull ClientDetails clientDetails);

    /**
     * 从数据库【获取】资源，通过clientId获取客户端信息
     *
     * @param clientId 客户端id
     * @return 客户端的详细信息（客户端id，客户端name，客户端密钥，重定向url）
     */
    @Nullable
    ClientDetails getClientById(@NonNull String clientId);

    /**
     * 从数据库【删除】资源，通过clientId删除客户端信息
     *
     * @param clientId 客户端id
     */
    void deleteClientById(@NonNull String clientId);

    /**
     * 成功授权时的回调方法
     *
     * @param authorizedDeviceDetails 授权信息
     */
    @Override
    default void authorize(@NonNull AuthorizedDeviceDetails authorizedDeviceDetails) {

    }

}
