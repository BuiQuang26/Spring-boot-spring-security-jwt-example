package com.example.springsecurityjwtexample.security;

public class SecurityConstant {
    public static Long ACCESS_TOKEN_EXPIRED_TIME = 20 * 60 * 1000L; //20m
    public static Long REFRESH_TOKEN_EXPIRED_TIME = 24 * 60 * 60 * 1000L; //24h
}
