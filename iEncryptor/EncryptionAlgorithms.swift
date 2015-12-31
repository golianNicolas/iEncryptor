//
//  EncryptionAlgorithms.swift
//  iEncyptor
//
//  Created by Tatch on 12/30/15.
//  Copyright © 2015 Tatch. All rights reserved.
//

import Foundation

class Algorithms{

    static let upper_a:UInt32=65
    static let upper_z:UInt32=90
    static let lower_a:UInt32=97
    static let lower_z:UInt32=122
    
    private static func shiftForward(code:UnicodeScalar,key:UInt32)->UInt32{
        var encryptedCode:UInt32
        if code.value>=lower_a&&code.value<=lower_z{
            encryptedCode=(code.value-lower_a+key)%26+lower_a
        }else if code.value>=upper_a&&code.value<=upper_z{
            encryptedCode=(code.value-upper_a+key)%26+upper_a
        }else{
            encryptedCode=code.value
        }
    return encryptedCode
    }

    private static func shiftBackward(code:UnicodeScalar,key:UInt32)->UInt32{
        var encryptedCode:UInt32
        let keyComp=26-key
        if code.value>=lower_a&&code.value<=lower_z{
            encryptedCode=(code.value-lower_a+keyComp)%26+lower_a
        }else if code.value>=upper_a&&code.value<=upper_z{
            encryptedCode=(code.value-upper_a+keyComp)%26+upper_a
        }else{
            encryptedCode=code.value
        }
    return encryptedCode
    }

    //==============================
    // Caesar
    //==============================
    private static func caesar(isToEnc:Bool,plainText:String,key:UInt32)->String{
    var encrypted:String=""
    for code in plainText.unicodeScalars{
        if isToEnc{
            encrypted.append(Character(UnicodeScalar(shiftForward(code, key:key))))
        }else{
            encrypted.append(Character(UnicodeScalar(shiftForward(code, key:key))))
        }
    }
        return encrypted
    }
    
    private static func caesarEnc(plainText:String,key:UInt32)->String{
        return caesar(true, plainText: plainText, key: key)
    }
    
    private static func caesarDec(plainText:String,key:UInt32)->String{
        return caesar(false, plainText: plainText, key: key)
    }


    //==============================
    // Vigenere
    //==============================
    static func vigenereEnc(plainText:String,key:String)->String{
        return vigenere(true, plainText: plainText, key: key)
    }
    
    static func vigenereDec(plainText:String,key:String)->String{
        return vigenere(false, plainText: plainText, key: key)
    }
    
    private static func vigenere(isToEnc:Bool,plainText:String,key:String)->String{

        var keys:Array<UInt32>=Array<UInt32>()
        for code in key.unicodeScalars{
            if code.value>=lower_a&&code.value<=lower_z{
                keys.append(code.value-lower_a)
            }else if code.value>=upper_a&&code.value<=upper_z{
                keys.append(code.value-upper_a)
            }else{
                keys.append(0)
            }
        }
        let keyLen = keys.count
        var encrypted:String=""

        var i:Int=0
        for code in plainText.unicodeScalars{
            let key=keys[i%keyLen]
            let tempCode:UInt32
            if isToEnc{
                tempCode=shiftForward(code, key: UInt32(key))
            }else{
                tempCode=shiftBackward(code, key: UInt32(key))
            }
            encrypted.append(Character(UnicodeScalar(tempCode)))
            i++
        }
        return encrypted
    }

    //==============================
    // Scytale
    //==============================
    static func scytaleEnc(plainText:String,key:Int)->String{
        var buckets:Array<String>=Array<String>()
        var counter:Int=0

        // initialize each element in the bucket
        for var i:Int=0;i<key;++i{
            buckets.append("")
        }

        // put chars into the buckets
        for char in plainText.characters{
            buckets[counter%key].append(char)
            counter++
        }

        var encrypted=""

        //relocate
        for stream in buckets{
            encrypted=encrypted+stream
        }

        return encrypted
    }
    
    

}