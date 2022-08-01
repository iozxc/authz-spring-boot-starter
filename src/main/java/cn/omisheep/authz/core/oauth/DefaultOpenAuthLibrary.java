package cn.omisheep.authz.core.oauth;

import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;

import java.util.ArrayList;
import java.util.List;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
public class DefaultOpenAuthLibrary implements OpenAuthLibrary {

    @NonNull
    @Override
    public List<ClientDetails> init() {
        return new ArrayList<>();
    }

    @Nullable
    @Override
    public ClientDetails getClientById(@NonNull String clientId) {
        return null;
    }

    @Override
    public void deleteClientById(@NonNull String clientId) {
    }

    @Override
    public void registerClient(@NonNull ClientDetails clientDetails) {
    }

    @Override
    public void createAuthorizationCodeCallback(@NonNull String authorizationCode,
                                                @NonNull AuthorizationInfo authorizationInfo) {
    }

    @Override
    public void authorize(@NonNull AuthorizedDeviceDetails authorizedDeviceDetails) {
    }

}
