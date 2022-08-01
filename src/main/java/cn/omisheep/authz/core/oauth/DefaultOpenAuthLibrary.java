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
        System.out.println("init"); // todo
        return new ArrayList<>();
    }

    @Nullable
    @Override
    public ClientDetails getClientById(@NonNull String clientId) {
        System.out.println(clientId); // todo
        return null;
    }

    @Override
    public void deleteClientById(@NonNull String clientId) {
        System.out.println(clientId); // todo
    }

    @Override
    public void registerClient(@NonNull ClientDetails clientDetails) {
        System.out.println(clientDetails); // todo
    }
}
