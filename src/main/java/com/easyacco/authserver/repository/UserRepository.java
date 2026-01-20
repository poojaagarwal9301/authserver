package com.easyacco.authserver.repository;

import com.easyacco.authserver.dto.UserDetailsDTO;
import com.easyacco.authserver.model.UsrTbl;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Repository
@Transactional
public interface UserRepository extends JpaRepository<UsrTbl, Integer> {

    @Query(name = "getUserDetailsByUserName", nativeQuery = true)
    Optional<UserDetailsDTO> getUserDetailsByUserName(@Param("userName") String userName);
}
