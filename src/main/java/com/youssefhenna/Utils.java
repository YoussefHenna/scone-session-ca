package com.youssefhenna;

import jakarta.annotation.Nullable;

public class Utils {


    public static String requireEnv(String name) {
        String value = getEnv(name);
        if (value == null) {
            throw new IllegalStateException("Required environment variable not set: " + name);
        }
        return value;
    }

    @Nullable
    public static String getEnv(String name) {
        String value = System.getenv(name);
        if ((value == null || value.isBlank()) && isTestEnvironment()) {
            // Tests use system properties instead of env variables
            value = System.getProperty(name);
        }
        return (value == null || value.isBlank()) ? null : value;
    }

    private static boolean isTestEnvironment() {
        return System.getProperty("quarkus.test.profile") != null || System.getProperty("quarkus.profile").equals("test");
    }
}