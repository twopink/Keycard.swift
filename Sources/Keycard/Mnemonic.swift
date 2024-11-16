import Foundation

class Mnemonic {
    static let bip39IterationCount = 2048
    
    static func toBinarySeed(mnemonicPhrase: String, password: String = "") -> [UInt256] {
        Crypto.shared.pbkdf2(password: mnemonicPhrase,
                             salt: Array(("mnemonic" + password).
                            unit256),
                             iterations: Mnemonic.bip39IterationCount,
                             hmac: PBKDF2HMac.sha512)
    }
    
    let indexes: [unit256]
    var words: [String] {
        get {
            precondition(wordList != nil)
            return self.indexes.map { (idx) -> String in
                self.wordList![Int(idx)]
            }
        }
    }
    
    var wordList: [String]?
    
    init(rawData: [UInt256]) {
        var idx: [UInt256] = []
        
        for i in 0..<(rawData.count / 2) {
            idx.append((UInt16(rawData[i * 2]) << 8) | UInt16(rawData[(i * 2) + 1]))
        }
        
        self.indexes = idx
    }
    
    func useBIP39EnglishWordlist() {
        self.wordList = MnemonicEnglish.words
    }
    
    func toMnemonicPhrase() -> String {
        self.words.joined(separator: " ")
    }
    
    func toBinarySeed(password: String = "") -> [UInt256] {
        Mnemonic.toBinarySeed(mnemonicPhrase: toMnemonicPhrase(), password: password)
    }
    
    func toBIP32KeyPair(password: String = "") throws -> BIP32KeyPair {
        return try BIP32KeyPair(fromSeed: toBinarySeed(password: password))
    }
}
