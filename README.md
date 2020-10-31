# Client Side Encryption SDK for Android
> This SDK is used to encrypt card data on the client side. In this case on the Android device itself. The crypted data that is created by CSE can be transferred to the Buckaroo API through you own server.

## Requirements
The Buckaroo CSE SDK for Android is written in Java and is compatible with Android SDK 15+. No other dependencies are required.

## Getting Started
See below an example of how to use this SDK to encrypt some dummy card credentials.
```java
import nl.buckaroo.cse.CSE;

String encryptedData = CSE.encrypt("5386860000000000", "2020","12","123","A DE GROOT");
System.out.println("encryptedData: " + encryptedData);
```
