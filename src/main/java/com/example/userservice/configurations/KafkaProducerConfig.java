package com.example.userservice.configurations;

import org.springframework.context.annotation.Bean;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;

@Component
public class KafkaProducerConfig {

    private KafkaTemplate<String, String> kafkaTemplate;
    public KafkaProducerConfig(KafkaTemplate<String, String> kafkaTemplate){
        this.kafkaTemplate = kafkaTemplate;
    }
    public void sendMessage(String topic, String message) {
        kafkaTemplate.send(topic, message);
    }
}
