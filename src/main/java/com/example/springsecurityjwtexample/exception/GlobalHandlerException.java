package com.example.springsecurityjwtexample.exception;

import com.example.springsecurityjwtexample.domain.Response.HttpResponseError;
import org.hibernate.exception.ConstraintViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalHandlerException {

    @ExceptionHandler(value = BindException.class)
    public ResponseEntity<HttpResponseError> handlerException(BindException e){
        return new ResponseEntity<>(new HttpResponseError(false, 400, "BAD_REQUEST", e.getAllErrors().get(0).getDefaultMessage()), HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(value = ConstraintViolationException.class)
    public ResponseEntity<HttpResponseError> handlerException(ConstraintViolationException e){
        return new ResponseEntity<>(new HttpResponseError(false, 400, "Constraint_Violation", e.getMessage()), HttpStatus.BAD_REQUEST);
    }

}
