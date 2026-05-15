package com.youssefhenna.cas;

import com.youssefhenna.model.TrustedCASConfig;
import jakarta.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class CASClientFactoryImpl implements CASClientFactory {

    @Override
    public CASClient create(TrustedCASConfig.TrustedCAS trustedCAS) {
        return new CASClientImpl(
            trustedCAS.casAddress(),
            trustedCAS.casPort(),
            trustedCAS.casKeyHash(),
            trustedCAS.casSoftwareKeyHash()
        );
    }
}