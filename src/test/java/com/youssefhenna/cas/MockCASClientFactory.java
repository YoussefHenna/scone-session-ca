package com.youssefhenna.cas;

import com.youssefhenna.model.TrustedCASConfig;
import jakarta.annotation.Priority;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Alternative;

@Alternative
@Priority(1)
@ApplicationScoped
public class MockCASClientFactory implements CASClientFactory {

    private final MockCASClient client = new MockCASClient();

    public MockCASClient getClient() {
        return client;
    }

    @Override
    public CASClient create(TrustedCASConfig.TrustedCAS trustedCAS) {
        return client;
    }
}