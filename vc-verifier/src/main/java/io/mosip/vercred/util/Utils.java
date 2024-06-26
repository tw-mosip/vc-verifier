package io.mosip.vercred.util;

public class Utils {
    public boolean isAndroid() {
        return System.getProperty("java.vm.name").contains("Dalvik");
    }
}
