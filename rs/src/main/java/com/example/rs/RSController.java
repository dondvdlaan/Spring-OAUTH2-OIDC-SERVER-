package com.example.rs;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class RSController {

    @GetMapping("/demo")
    public String demo(){

        return "demo";
    }
}
