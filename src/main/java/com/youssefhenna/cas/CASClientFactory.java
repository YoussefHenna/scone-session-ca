package com.youssefhenna.cas;

import com.youssefhenna.model.TrustedCASConfig;

public interface CASClientFactory {
    CASClient create(TrustedCASConfig.TrustedCAS trustedCAS);
}