package com.example.springsecurityjwtexample.domain.Response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class HttpResponseError {
    private Boolean success;
    private Integer statusCode;
    private String errorCode;
    private String message;
}
