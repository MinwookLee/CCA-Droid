# Overview

CCA-Droid is a new static analysis tool to Check Cryptographic API misuses related to CCA in Android apps using more sophisticated cryptographic API misuse rules and backward program slicing techniques achieving a highcode coverage.

# Build Environment

We tested with the following versions of software:

1. Windows 10

2. Java 11

3. Gradle 7.1

# Prerequisites

Replace <CCADroidHome\> below with the directory path where you cloned the CCA-Droid git repo.

1. Android SDK(Software Devlopment Kit) needs to be installed.
      - Reference: https://developer.android.com/studio#command-tools
      - Download commandlinetools-win-xxxxxxx-latest.zip file and Unzip the file
      - `mkdir .\android-29`
      - `.\sdkmanager.bat "platform-tools" "platforms;android-29" --sdk_root="<CCADroidHome>\android-29"`

2. Environment variable "ANDROID_SDK_HOME" needs to be set.
   - Set environment variable "ANDROID_SDK_HOME" to "<CCADroidHome>\android-29"

# How to run

1. Set crypto rules
   - We support 15 types of Crypto rules in `Configuration` class
      - Rule 1 : WeakAlgorithmChecker
      - Rule 2 : ECBModeChecker
      - Rule 3 : HardcodedKeyChecker
      - Rule 4 : StaticSaltChecker
      - Rule 5 : PBEIterationChecker
      - Rule 6 : StaticSeedsChecker
      - Rule 7 : PredictableIVChecker
      - Rule 8 : PredictableKeyChecker
      - Rule 9 : RSAKeySizeChecker
      - Rule 10 : ReuseIVAndKeyChecker
      - Rule 11 : RSAPaddingChecker
      - Rule 12 : EncryptAndMACChecker
      - Rule 13 : OperationModeChecker
      - Rule 14 : MACKeySizeChecker
      - Rule 15 : SameKeyChecker

2. Build CCA-Droid
      - `./gradlew.bat clean assemble`

3. Run CCA-Droid
      - `java -jar <CCADroidHome>/build/libs/CCA-Droid.jar <APK file path>` 

# How to analyze detction result

For example, if CCA-Droid detects misuses, it will shows the detection result as below:

```java
[*] Rule id : 3
[*] Rule description : This slice uses a static key
[*] Caller : <com.androidseclab.Crypto1: byte[] encrypt()>
[*] Slicing signature : <javax.crypto.spec.SecretKeySpec: void <init>(byte[],java.lang.String)>
[*] Parameter Number : 0
[*] Target lines:
Line{unit=$r3 = "SOME_STRING", location=<com.androidseclab.Crypto1: byte[] encrypt()>, number=3}
Line{unit=$r4 = virtualinvoke $r3.<java.lang.String: byte[] getBytes()>(), location=<com.androidseclab.Crypto1: byte[] encrypt()>, number=4}
Line{unit=specialinvoke $r1.<javax.crypto.spec.SecretKeySpec: void <init>(byte[],java.lang.String)>($r4, "AES"), location=<com.androidseclab.Crypto1: byte[] encrypt()>, number=6}
```

Each line means:

`[*] Rule id` : rule number

`[*] Rule description` : description of the rule

`[*] Caller` : method signature of calling the slicing criteria

`[*] Slicing signature` : method signature of crypto API

`[*] Parameter Number` : parameter number of the slicing slicing crtieria

`[*] Target lines` : target lines related to the rule