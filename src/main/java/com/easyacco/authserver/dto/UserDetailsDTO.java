package com.easyacco.authserver.dto;

import lombok.*;

import java.util.Date;

@NoArgsConstructor
@AllArgsConstructor
@Data
public class UserDetailsDTO {

    private String fullName;
    private String userName;
    private String roles;
    private String password;
    private int userId;

}
