package com.example.springsecurityjwtexample.domain.Response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class HttpResponse {
    private Boolean success;
    private Integer statusCode;
    private String message;
    private Object data;
}
