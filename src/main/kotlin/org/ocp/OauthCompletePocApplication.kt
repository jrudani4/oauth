package org.ocp

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class OauthCompletePocApplication

fun main(args: Array<String>) {
    runApplication<OauthCompletePocApplication>(*args)
}
