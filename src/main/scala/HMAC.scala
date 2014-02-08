package com.bonipart.util.crypto

import net.liftweb.util.SecurityHelpers.hash256

object HMACSHA256 {
  // http://en.wikipedia.org/wiki/Hash-based_message_authentication_code
  // HMAC(K,m) = H((K xor opad) + H((K xor ipad) + msg))

  def apply(k: Array[Byte], msg: Array[Byte]): Array[Byte] = {
    val blkSize = 64 // SHA256 block size
    val key = k.padTo(blkSize, 0x00.toByte) // either truncate or pad k to blkSize
    val oKeyPad = key.map(k => (k ^ 0x5c).toByte)
    val iKeyPad = key.map(k => (k ^ 0x36).toByte)

    hash256(oKeyPad ++ hash256(iKeyPad ++ msg))
  }
}
