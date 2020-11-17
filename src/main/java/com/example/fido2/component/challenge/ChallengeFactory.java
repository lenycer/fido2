package com.example.fido2.component.challenge;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class ChallengeFactory {

    @Autowired
    List<ChallengeComponent> challengeComponentList;

    public ChallengeComponent getInstance(String type) {
        return challengeComponentList.stream().filter(c -> c.getType().equals(type)).findFirst().orElseThrow(() -> new RuntimeException("type not supported."));
    }
}
