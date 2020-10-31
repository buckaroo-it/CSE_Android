package nl.buckaroo.cse;

import android.util.Base64;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.regex.Pattern;
import javax.crypto.Cipher;

public class CSE {
    private static Boolean isNullOrWhitespace(String input) {
        if(input == null) return true;
        int length = input.length();
        if (length > 0) {
            for (int i = 0; i < length; i++) {
                if (!Character.isWhitespace(input.charAt(i))) {
                    return false;
                }
            }
            return true;
        }
        return false;
    }

    /**
     * Encrypts the data using RSA public key encryption
     * @return A base64 encoded value that can be used to initiate a transaction using the Buckaroo Payment Gateway
     */
    public static String encrypt(String cardNumber, String year, String month, String cvc, String cardholder) {
        String encryptableString = cardNumber + "," + year + "," + month + "," + cvc + "," + cardholder;

        try {
            Cipher cipher = Cipher.getInstance("RSA/None/OAEPWithSHA-1AndMGF1Padding");
            BigInteger modulus = new BigInteger(Base64.decode("AODXS2u1iKvsoHE6OLRhbvHnO6kcLWdYyxIyp7V37OeoGlrWmEsXPnq+5Yxttq27+NU+a2mH3c7z6ld2HExQji6XSSCZM076K2PiA0dPZDerhyhrrUo3ZA6WKyhR3lP8dFuz9BlFtknNeAexvy/AtnjEqpAwDLQDcrzgh3ZP9nIWDoGKiLmXyJ02jRMx22G+ovg+bCnrtQ9eRtrhBWPoJLi5rQ6t8T1MyvxvoWhuCrCC+SSm7fpFd/w4m7tzlKYjAzdWKaHKmlEebKBZioiYtTx7YEGdGsnV8b3hyEYbRPuRYC+8N9O4DqmzCeKt31wwGUMygcJTWJ8IAGhVtT0s5Pc=", Base64.DEFAULT));
            BigInteger publicExponent = new BigInteger(Base64.decode("AQAB", Base64.DEFAULT));

            RSAPublicKeySpec keySpecX509 = new RSAPublicKeySpec(modulus, publicExponent);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            RSAPublicKey pubKey = (RSAPublicKey) kf.generatePublic(keySpecX509);
            cipher.init(Cipher.ENCRYPT_MODE, pubKey);

            byte[] encryptableBytes = encryptableString.getBytes("UTF8");
            byte[] cipherText = cipher.doFinal(encryptableBytes);

            return "001" + Base64.encodeToString(cipherText, Base64.DEFAULT);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * Validates if the cardholder name is entered
     */
    public static Boolean validateCardholderName(String name) {
        if (name == null) return false;
        // Cardholder name should be filled.
        return !isNullOrWhitespace(name);
    }

    /**
     * Validates the entered card number. The following checks are performed:
     * 1. Not empty
     * 2. Digits only
     * 3. Luhn check
     * 4. Card number matches the scheme pattern
     */
    public static Boolean validateCardNumber(String cardNumber, CardBrand cardBrand) {
        if (cardNumber == null) return false;
        // Accept only digits.
        if (Pattern.matches("[^0-9]+", cardNumber)) return false;
        // Accept only card numbers with a length between 10 and 19.
        if (cardNumber.length() < 10 || cardNumber.length() > 19) return false;
        // The Luhn Algorithm.
        int sum = 0;
        for (int i = 0; i < cardNumber.length(); i++) {
            int digit = Integer.parseInt(String.valueOf(cardNumber.charAt(i)), 10);
            if (i % 2 == cardNumber.length() % 2) {
                digit *= 2;
                if (digit > 9) {
                    digit -= 9;
                }
            }
            sum += digit;
        }
        if (sum % 10 != 0) return false;
        if (cardBrand == null) {
            // We could not determine the card brand, so we don't know how the card number should be formatted, so return true.
            return true;
        }
        else {
            switch (cardBrand) {
                case Visa:
                    return Pattern.matches("^4[0-9]{12}(?:[0-9]{3})?$", cardNumber);
                case Mastercard:
                    return Pattern.matches("^(5[1-5]|2[2-7])[0-9]{14}$", cardNumber);
                case Bancontact:
                    return Pattern.matches("^(4796|6060|6703|5613|5614)[0-9]{12,15}$", cardNumber);
                case Maestro:
                    return Pattern.matches("^\\d{12,19}$", cardNumber);
                case Amex:
                    return Pattern.matches("^3[47][0-9]{13}$", cardNumber);
                default:
                    // Not a card brand Buckaroo recognizes, so return false.
                    return false;
            }
        }
    }

    /**
     * Checks if a valid cvc is entered. The following checks are performed:
     * 1. Digits only
     * 2. 3 digits for Mastercard & Visa
     * 3. 4 digits for Amex
     * 4. No cvc for Bancontact or Maestro
     * 5. 0, 3 or 4 digits for Unknown
     */
    public static Boolean validateCvc(String cvc, CardBrand cardBrand) {
        if (cvc == null) return false;
        // Determine if the cvc has the correct length.
        if (cardBrand == null) {
            // We do not know the card brand, so accept cvc length of 0, 3, or 4.
            if (cvc.length() == 0) return true;
            if (cvc.length() != 3 && cvc.length() != 4) return false;
        }
        else {
            switch (cardBrand) {
                case Bancontact:
                case Maestro:
                    // These card brands does not use a cvc so no cvc should be set.
                    return cvc.length() == 0;
                case Amex:
                    // American Express uses a cvc with 4 digits.
                    if (cvc.length() != 4)
                        return false;
                    break;
                default:
                    // All other card brands uses cvc with 3 digits.
                    if (cvc.length() != 3)
                        return false;
                    break;
            }
        }
        // Accept only digits
        return !Pattern.matches("[^0-9]+", cvc);
    }

    /**
     * Checks if a valid year digit is entered. This can be 2 or 4 digits.
     */
    public static Boolean validateYear(String year) {
        if (year == null) return false;
        // Accept only digits.
        if (Pattern.matches("[^0-9]+", year)) return false;
        // Only years with a length of 2 or 4 are accepted.
        return year.length() == 2 || year.length() == 4;
    }

    /**
     * Checks if a valid month digit is entered
     */
    public static Boolean validateMonth(String month) {
        if (month == null) return false;
        // Accept only digits.
        if(Pattern.matches("[^0-9]+", month)) return false;
        // Only months with a length of 1 or 2 are accepted.
        if (month.length() != 1 && month.length() != 2) return false;
        // Check the value of month, it should be between 1 and 12.
        int monthInt = Integer.parseInt(month);
        return monthInt >= 1 && monthInt <= 12;
    }

    /**
     * Returns the best guess for the card brand. In most cases tif he number of digits entered is below 4 CardType Unknown is returned.
     */
    public static CardBrand predictCardBrand(String cardNumberBeginning) {
        if (Pattern.matches("^3.*$", cardNumberBeginning)) {
            return CardBrand.Amex;
        }

        // This prevents a premature result on card numbers entered with a length below 4
        if (cardNumberBeginning.length() < 4) {
            return CardBrand.Unknown;
        }

        if (Pattern.matches("^(5018|5020|5038|6304|6759|6761|6763).*$", cardNumberBeginning)) {
            return CardBrand.Maestro;
        }

        if (Pattern.matches("^(4796|6060|6703|5613|5614).*$", cardNumberBeginning)) {
            return CardBrand.Bancontact;
        }

        if (Pattern.matches("^4.*$", cardNumberBeginning)) {
            return CardBrand.Visa;
        }

        if (Pattern.matches("^5.*$", cardNumberBeginning)) {
            return CardBrand.Mastercard;
        }

        return CardBrand.Unknown;
    }
}
