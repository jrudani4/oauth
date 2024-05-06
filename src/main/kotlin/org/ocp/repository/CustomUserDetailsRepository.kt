package org.ocp.repository

import org.ocp.model.CustomUserDetails
import org.springframework.data.jpa.repository.JpaRepository
import java.util.*

interface CustomUserDetailsRepository : JpaRepository<CustomUserDetails, Long> {

    fun findByEmail(email: String): Optional<CustomUserDetails>
}