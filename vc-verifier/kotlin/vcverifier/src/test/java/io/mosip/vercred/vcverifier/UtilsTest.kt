package io.mosip.vercred.vcverifier

import io.mosip.vercred.vcverifier.utils.Util
import org.json.JSONArray
import org.junit.Assert.assertEquals
import org.junit.Test


class UtilsTest {

    val utils = Util()

    @Test
    fun `test validate date invalid`() {
        val result = utils.isValidDate("123456789")
        assertEquals(false, result)
    }

    @Test
    fun `test validate date valid`() {
        val result = utils.isValidDate("2024-09-02T17:36:13.644Z")
        assertEquals(true, result)
    }

    @Test
    fun `test validate uri invalid`() {
        val result = utils.isValidUri("invalid_uri")
        assertEquals(false, result)
    }

    @Test
    fun `test validate uri valid`() {
        val result = utils.isValidUri("http://www.google.com")
        assertEquals(true, result)
    }

    @Test
    fun `test validate uri valid did`() {
        val result = utils.isValidUri("did:jwk:eysdsdsd")
        assertEquals(true, result)
    }

    @Test
    fun `test empty JSONArray`() {
        val jsonArray = JSONArray()
        val result = utils.jsonArrayToList(jsonArray)
        assertEquals(emptyList<Any>(), result)
    }

    @Test
    fun `test JSONArray with strings`() {
        val jsonArray = JSONArray()
        jsonArray.put("element1")
        jsonArray.put("element2")
        jsonArray.put("element3")

        val result = utils.jsonArrayToList(jsonArray)
        assertEquals(listOf("element1", "element2", "element3"), result)
    }

    @Test
    fun `date expired`(){
        val result = utils.isDateExpired("2024-09-02T17:36:13.644Z")
        assertEquals(true, result)
    }

    @Test
    fun `date not expired`(){
        val result = utils.isDateExpired("2024-11-02T17:36:13.644Z")
        assertEquals(false, result)
    }

    @Test
    fun `invalid date`(){
        val result = utils.isDateExpired("12345")
        assertEquals(false, result)
    }
}