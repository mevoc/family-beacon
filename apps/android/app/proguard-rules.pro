# Release shrinking is not configured yet — slice 7 owns distribution.
#
# One rule is here already because it is not optional and is easy to discover
# too late: JNA reaches the native library through reflection, so R8 must not
# rename or strip the classes the generated UniFFI bindings register.
-keep class com.sun.jna.** { *; }
-keep class * implements com.sun.jna.** { *; }
-keep class uniffi.beacon.** { *; }
