package io.mosip.vercred.vcverifier.utils

import android.annotation.SuppressLint
import android.os.Build
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset
import java.time.format.DateTimeParseException
import java.util.Base64

class Util {
    val isAndroid: Boolean
        get() = System.getProperty("java.vm.name")?.contains("Dalvik") == true


    @SuppressLint("NewApi")
    fun decodeFromBase64UrlFormatEncoded(content: String): ByteArray {
        return if (BuildConfig.getVersionSDKInt() >= Build.VERSION_CODES.O) {
            Base64.getUrlDecoder().decode(content.toByteArray())
        } else {
            TODO("VERSION.SDK_INT < O")
        }
    }

    @SuppressLint("NewApi")
    fun decodeFromBase64FormatEncoded(content: String): ByteArray {
        return if (BuildConfig.getVersionSDKInt() >= Build.VERSION_CODES.O) {
            Base64.getDecoder().decode(content.toByteArray())
        } else {
            TODO("VERSION.SDK_INT < O")
        }
    }

    @SuppressLint("NewApi")
    fun isTimestamp(text: String?): Boolean {
        if (BuildConfig.getVersionSDKInt() >= Build.VERSION_CODES.O) {
            try {
                // Try to parse as a timestamp (e.g., "2024-10-03T10:15:30")
                Instant.parse(text)
                return true
            } catch (e: DateTimeParseException) {
                println(e.message)
                return false
            }
        } else return false
    }

    @SuppressLint("NewApi")
    fun convertLocalDateTimeStringToInstant(dateStr: String): Instant {
        return if (BuildConfig.getVersionSDKInt() >= Build.VERSION_CODES.O) {
            val localDate = LocalDate.parse(dateStr)
            localDate.atStartOfDay(ZoneOffset.UTC).toInstant()
        } else {
            TODO("VERSION.SDK_INT < O")
        }
    }

     fun calculateDigest(
         algorithm: String,
         data: ByteArrayOutputStream,
    ): ByteArray =
        MessageDigest.getInstance(algorithm).digest(data.toByteArray())
}