package com.youssefhenna;

import io.quarkus.test.common.QuarkusTestResourceLifecycleManager;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class StaticChallengeSessionsTestResource implements QuarkusTestResourceLifecycleManager {

    private final List<File> tempFiles = new ArrayList<>();

    @Override
    public Map<String, String> start() {
        try {
            String json = """
                {"staticChallengeSessions":[{"casAddress":"test-cas","casPort":"8080","challengeSession":"/my-session","verifySession":"/my-verify-session"}]}
                """.strip();
            File file = writeTempFile("static-challenge-sessions-", ".json", json);
            System.setProperty("STATIC_CHALLENGE_SESSIONS_CONFIG_FILE", file.getAbsolutePath());
            return Map.of();
        } catch (IOException e) {
            throw new RuntimeException("Failed to write static challenge sessions config", e);
        }
    }

    @Override
    public void stop() {
        for (File f : tempFiles) {
            f.delete();
        }
        tempFiles.clear();
        System.clearProperty("STATIC_CHALLENGE_SESSIONS_CONFIG_FILE");
    }

    private File writeTempFile(String prefix, String suffix, String content) throws IOException {
        File file = File.createTempFile(prefix, suffix);
        file.deleteOnExit();
        Files.writeString(file.toPath(), content);
        tempFiles.add(file);
        return file;
    }
}