package com.youssefhenna.model;

import java.util.ArrayList;

public record StaticChallengeSessionsConfig(ArrayList<StaticChallengeSession> staticChallengeSessions) {
    public record StaticChallengeSession(String casAddress, String casPort, String challengeSession, String verifySession){}
}
