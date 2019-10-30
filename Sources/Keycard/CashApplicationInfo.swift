public struct CashApplicationInfo {
    public let secureChannelPubKey: [UInt8]
    public let appVersion: UInt16
    public let pubData: [UInt8]
    
    public var appVersionString: String {
        return "\(appVersion >> 8).\(appVersion & 0xff)"
    }
    
    public init(_ data: [UInt8]) throws {
        let tlv = TinyBERTLV(data)
        
        _ = try tlv.enterConstructed(tag: AppInfoTag.template.rawValue)
        secureChannelPubKey = try tlv.readPrimitive(tag: AppInfoTag.pubKey.rawValue)
        appVersion = try UInt16(tlv.readInt())
        keyUID = try tlv.readPrimitive(tag: AppInfoTag.pubData.rawValue)
    }
    
    public init(secureChannelPubKey: [UInt8],
                appVersion: UInt16,
                pubData: [UInt8]) {
        self.secureChannelPubKey = secureChannelPubKey
        self.appVersion = appVersion
        self.pubData = initializedCard
    }
    
}
