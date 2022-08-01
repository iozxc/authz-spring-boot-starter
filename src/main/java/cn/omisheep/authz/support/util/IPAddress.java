package cn.omisheep.authz.support.util;

import cn.omisheep.authz.core.util.LogUtils;

import java.util.NoSuchElementException;

/**
 * @author Marcel Dullaart
 * @since 1.0
 */
public class IPAddress implements Cloneable {

    /** IP address */
    protected int    ipAddress = 0;
    protected String ipAddressStr;

    public IPAddress(String ipAddressStr) {
        try {
            this.ipAddressStr = ipAddressStr;
            ipAddress         = parseIPAddress(ipAddressStr);
        } catch (Exception e) {
            LogUtils.error(e);
        }
    }

    public IPAddress(int address) {
        ipAddress = address;
    }

    // -------------------------------------------------------------------------

    /**
     * Return the String representation of the IP address.
     *
     * @return The IP address.
     */
    public final String getIpAddress() {
        return ipAddressStr;
    }

    // -------------------------------------------------------------------------

    /**
     * Return the string representation of the IP Address following the common decimal-dotted notation xxx.xxx.xxx.xxx.
     *
     * @return Return the string representation of the IP address.
     */
    public String toString() {
        StringBuilder result = new StringBuilder();
        int           temp;

        temp = ipAddress & 0x000000FF;
        result.append(temp);
        result.append(".");

        temp = (ipAddress >> 8) & 0x000000FF;
        result.append(temp);
        result.append(".");

        temp = (ipAddress >> 16) & 0x000000FF;
        result.append(temp);
        result.append(".");

        temp = (ipAddress >> 24) & 0x000000FF;
        result.append(temp);

        return result.toString();
    }

    // -------------------------------------------------------------------------

    /**
     * Check if the IP address is belongs to a Class A IP address.
     *
     * @return Return <code>true</code> if the encapsulated IP address belongs to a class A IP address, otherwise
     * returne <code>false</code>.
     */
    public final boolean isClassA() {
        return (ipAddress & 0x00000001) == 0;
    }

    // -------------------------------------------------------------------------

    /**
     * Check if the IP address is belongs to a Class B IP address.
     *
     * @return Return <code>true</code> if the encapsulated IP address belongs to a class B IP address, otherwise
     * returne <code>false</code>.
     */
    public final boolean isClassB() {
        return (ipAddress & 0x00000003) == 1;
    }

    // -------------------------------------------------------------------------

    /**
     * Check if the IP address is belongs to a Class C IP address.
     *
     * @return Return <code>true</code> if the encapsulated IP address belongs to a class C IP address, otherwise
     * returne <code>false</code>.
     */
    public final boolean isClassC() {
        return (ipAddress & 0x00000007) == 3;
    }

    // -------------------------------------------------------------------------

    /**
     * Convert a decimal-dotted notation representation of an IP address into an 32 bits interger value.
     *
     * @param ipAddressStr Decimal-dotted notation (xxx.xxx.xxx.xxx) of the IP address.
     * @return Return the 32 bits integer representation of the IP address.
     */
    final int parseIPAddress(String ipAddressStr) {
        int result = 0;

        if (ipAddressStr == null) {
            throw new IllegalArgumentException();
        }

        try {
            String tmp = ipAddressStr;

            // get the 3 first numbers
            int offset = 0;
            for (int i = 0; i < 3; i++) {

                // get the position of the first dot
                int index = tmp.indexOf('.');

                // if there is not a dot then the ip string representation is
                // not compliant to the decimal-dotted notation.
                if (index != -1) {

                    // get the number before the dot and convert it into
                    // an integer.
                    String numberStr = tmp.substring(0, index);
                    int    number    = Integer.parseInt(numberStr);
                    if ((number < 0) || (number > 255)) {
                        throw new IllegalArgumentException("Invalid IP Address [" + ipAddressStr + "]");
                    }

                    result += number << offset;
                    offset += 8;
                    tmp = tmp.substring(index + 1);
                } else {
                    throw new IllegalArgumentException("Invalid IP Address [" + ipAddressStr + "]");
                }
            }

            // the remaining part of the string should be the last number.
            if (tmp.length() > 0) {
                int number = Integer.parseInt(tmp);
                if ((number < 0) || (number > 255)) {
                    throw new IllegalArgumentException("Invalid IP Address [" + ipAddressStr + "]");
                }

                result += number << offset;
                ipAddress = result;
            } else {
                throw new IllegalArgumentException("Invalid IP Address [" + ipAddressStr + "]");
            }
        } catch (NoSuchElementException | NumberFormatException ex) {
            throw new IllegalArgumentException("Invalid IP Address [" + ipAddressStr + "]", ex);
        }

        return result;
    }

    public int hashCode() {
        return this.ipAddress;
    }

    public boolean equals(Object another) {
        return another instanceof IPAddress && ipAddress == ((IPAddress) another).ipAddress;
    }

    @Override
    protected Object clone() throws CloneNotSupportedException {
        return super.clone();
    }
}
