package com.youssefhenna.model;

import java.util.ArrayList;

public record TrustedCASConfig(ArrayList<TrustedCAS> trustedCasList) {
    public record TrustedCAS(String casAddress, String casPort, String casKeyHash, String casSoftwareKeyHash){}
}
