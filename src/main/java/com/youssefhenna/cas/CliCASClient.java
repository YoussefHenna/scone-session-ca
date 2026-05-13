package com.youssefhenna.cas;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;

public class CliCASClient implements CASClient {
    private final ObjectMapper objectMapper = new ObjectMapper();

    private String cli(String... args) throws IOException, InterruptedException, CASClientException {
        Process process = new ProcessBuilder(args)
                .redirectErrorStream(false)
                .start();

        String stdout = new String(process.getInputStream().readAllBytes());
        String stderr = new String(process.getErrorStream().readAllBytes());
        int exitCode = process.waitFor();

        if (exitCode != 0) {
            throw new CASClientException(exitCode, stderr.isBlank() ? stdout : stderr);
        }

        return stdout;
    }

    @Override
    public String readSession(String name) throws IOException, InterruptedException, CASClientException {
        return cli("scone", "session", "read", name);
    }
}