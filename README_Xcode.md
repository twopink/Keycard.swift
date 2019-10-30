In order to get a working Keycard.xcodeproj do the following steps.

1. Generate the project from the Swift Package:

    swift package generate-xcodeproj

2. Open the Keycard.xcodeproj and open Build Settings of the Keycard project.

3. Set the Deployment Target for Keycard project as 12.0 (or whatever minimum is set for the Keycard target)

4. Set the Base SDK Build Setting to iOS

    SDKROOT = iphoneos

5. Set the Build Settings of the secp256k1 target:

    HEADER_SEARCH_PATHS = $(inherited) $(SRCROOT)/.build/checkouts/secp256k1.swift/secp256k1/Classes/secp256k1/include $(SRCROOT)/.build/checkouts/secp256k1.swift/secp256k1/Classes/secp256k1 $(SRCROOT)/.build/checkouts/secp256k1.swift/secp256k1/Classes/secp256k1/src $(SRCROOT)/.build/checkouts/secp256k1.swift/secp256k1/Classes/secp256k1/src/modules/recovery $(SRCROOT)/.build/checkouts/secp256k1.swift/secp256k1/Classes/secp256k1/src/modules/ecdh $(SRCROOT)/.build/checkouts/secp256k1.swift/secp256k1/Classes

    MODULEMAP_FILE = $(SRCROOT)/.build/checkouts/secp256k1.swift/include/module.modulemap

The generated Xcode project by the Swift Package Manager doesn't set proper build settings that were defined in the Package.swift, that is why we have to set them manually.

6. Now the Keycard target should be building successfully.
