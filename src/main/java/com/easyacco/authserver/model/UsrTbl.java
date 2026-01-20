package com.easyacco.authserver.model;

import java.io.Serializable;
import java.sql.Timestamp;
import java.util.Date;

import com.easyacco.authserver.dto.UserDetailsDTO;
import jakarta.persistence.*;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;


/**
 * The persistent class for the usr_tbl database table.
 * Stores detail for the user of application
 *
 */
@NoArgsConstructor
@AllArgsConstructor
@Data
@Entity
@Table(name="usr_tbl")
@NamedQuery(name="UsrTbl.findAll", query="SELECT u FROM UsrTbl u")

@SqlResultSetMapping(
        name="userDetailMapping",
        classes={
                @ConstructorResult(
                        targetClass= UserDetailsDTO.class,
                        columns={
                                @ColumnResult(name="fullName"),
                                @ColumnResult(name="userName"),
                                @ColumnResult(name="roles"),
                                @ColumnResult(name="password"),
                                @ColumnResult(name="userId")
                        }
                )
        }
)

@NamedNativeQuery(name="getUserDetailsByUserName",
        query = "select  concat(u.first_name, \" \", u.last_name) as fullName," +
                "u.user_name as userName, u.user_id as userId," +
                "GROUP_CONCAT(r.role_name) AS roles, u.password from usr_tbl u " +
                "join user_roles_tbl ur " +
                "on u.user_id = ur.user_id join role_tbl r on ur.role_id = r.role_id " +
                "where u.user_name = :userName " +
                "group by u.user_id, u.user_name, u.password",
        resultSetMapping="userDetailMapping")

public class UsrTbl implements Serializable {
    private static final long serialVersionUID = 1L;

    @Id
    @GeneratedValue(strategy=GenerationType.IDENTITY)
    @Column(name="user_id")
    private int userId;

    private byte active;

    @Column(name="created_on", insertable = false)
    private Timestamp createdOn;

    @Temporal(TemporalType.DATE)
    private Date dob;

    @Column(name="first_name")
    private String firstName;

    @Column(name="last_name")
    private String lastName;

    @Column(name="middle_name")
    private String middleName;

    @Column(name="updated_on", insertable = false)
    private Timestamp updatedOn;

    @Column(name="user_name")
    private String userName;

    @Column(name="password")
    private String password;

    @Column(name="email")
    private String email;

    @Column(name="contact_number")
    private String contact_number;

    @Column(name="city")
    private String city;



}