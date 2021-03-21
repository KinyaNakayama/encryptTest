import org.bouncycastle.crypto.engines.DESEngine
import org.bouncycastle.crypto.macs.ISO9797Alg3Mac
import org.bouncycastle.crypto.paddings.ISO7816d4Padding
import org.bouncycastle.crypto.params.KeyParameter
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.DESedeKeySpec
import javax.crypto.spec.IvParameterSpec
import kotlin.experimental.xor


fun main() {

    val cardNumber = "AA12345678BB"
    printByteArray("cardNumber", cardNumber.toByteArray())

    val keyEnc = MessageDigest.getInstance("SHA-1").digest(cardNumber.toByteArray()).copyOfRange(0, 16)
    val keyMac = MessageDigest.getInstance("SHA-1").digest(cardNumber.toByteArray()).copyOfRange(0, 16)
    printByteArray("keyEnc", keyEnc)
    printByteArray("keyMac", keyMac)

    val rndIcc = byteArrayOf(
        0x5A, 0x6E, 0x7E, 0x38, 0x51, 0x62, 0xB7.toByte(), 0xA3.toByte()
    )
    val rndIfd = byteArrayOf(
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88.toByte()
    )
    val keyIfd = byteArrayOf(
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F
    )
    printByteArray("rndIcc", rndIcc)
    printByteArray("rndIfd", rndIfd)
    printByteArray("keyIfd", keyIfd)

    val encData = rndIfd + rndIcc + keyIfd
    printByteArray("encData", encData)

    val encIfd = tdes2keyEncode(
        keyEnc,
        encData
    )
    println("-----------------------------------------------------------------------------")
    printByteArray("encIfd", encIfd)
    printByteArray(
        "expect",
        byteArrayOf(
            0x93.toByte(), 0x77.toByte(), 0x45.toByte(), 0xC2.toByte(),
            0x08.toByte(), 0x83.toByte(), 0xA1.toByte(), 0xBA.toByte(),
            0xD1.toByte(), 0xE0.toByte(), 0x41.toByte(), 0x93.toByte(),
            0x72.toByte(), 0x2A.toByte(), 0x15.toByte(), 0x92.toByte(),
            0x37.toByte(), 0x8F.toByte(), 0x81.toByte(), 0xA8.toByte(),
            0xF1.toByte(), 0xDC.toByte(), 0x58.toByte(), 0x91.toByte(),
            0x57.toByte(), 0xAE.toByte(), 0xB0.toByte(), 0xF7.toByte(),
            0x54.toByte(), 0x4F.toByte(), 0xA1.toByte(), 0xBA.toByte()
        )
    )
    println("-----------------------------------------------------------------------------")

    val macIfd = retailMac(
        keyMac,
        encIfd
    )
    printByteArray("macIfd", macIfd)
    printByteArray(
        "expect",
        byteArrayOf(
            0x1A.toByte(), 0xD7.toByte(), 0xFB.toByte(), 0x6A.toByte(),
            0x33.toByte(), 0x89.toByte(), 0xE0.toByte(), 0x17.toByte()
        )
    )
    println("-----------------------------------------------------------------------------")

    val encIcc = byteArrayOf(
        0x58.toByte(), 0x60.toByte(), 0x77.toByte(), 0x5B.toByte(),
        0x4D.toByte(), 0x03.toByte(), 0x2C.toByte(), 0xC5.toByte(),
        0x64.toByte(), 0xBA.toByte(), 0x20.toByte(), 0x4B.toByte(),
        0x8E.toByte(), 0xA8.toByte(), 0x68.toByte(), 0xF6.toByte(),
        0x94.toByte(), 0xA7.toByte(), 0x4E.toByte(), 0x74.toByte(),
        0x75.toByte(), 0xA8.toByte(), 0xFE.toByte(), 0xF2.toByte(),
        0x40.toByte(), 0x58.toByte(), 0x8B.toByte(), 0xDA.toByte(),
        0x1A.toByte(), 0xF4.toByte(), 0x96.toByte(), 0xCE.toByte()
    )
    printByteArray("encIcc", encIcc)

    println("-----------------------------------------------------------------------------")
    val macIcc = byteArrayOf(
        0x59.toByte(), 0x38.toByte(), 0x8F.toByte(), 0xD6.toByte(),
        0xCD.toByte(), 0x45.toByte(), 0x24.toByte(), 0x8B.toByte()
    )
    printByteArray("macIcc", macIcc)
    printByteArray(
        "expect",
        retailMac(
            keyMac,
            encIcc
        )
    )
    println("-----------------------------------------------------------------------------")

    val decIcc = tdes2keyDecode(
        keyEnc,
        encIcc
    )
    printByteArray("decIcc", decIcc)

    println("-----------------------------------------------------------------------------")
    printByteArray("rndIcc", rndIcc)
    printByteArray("expect", decIcc.copyOfRange(0, 8))
    println("-----------------------------------------------------------------------------")
    printByteArray("rndIfd", rndIfd)
    printByteArray("expect", decIcc.copyOfRange(8, 16))
    println("-----------------------------------------------------------------------------")

    val keyIcc = decIcc.copyOfRange(16, 32)
    printByteArray("keyIcc", keyIcc)
    printByteArray(
        "expect",
        byteArrayOf(
            0x19.toByte(), 0xD0.toByte(), 0x49.toByte(), 0x49.toByte(),
            0x0F.toByte(), 0xFF.toByte(), 0x52.toByte(), 0xEE.toByte(),
            0xDB.toByte(), 0xFC.toByte(), 0xB9.toByte(), 0x30.toByte(),
            0xBC.toByte(), 0x81.toByte(), 0x0E.toByte(), 0xD0.toByte()
        )
    )
    println("-----------------------------------------------------------------------------")

    val xorKey = xorByteArray(keyIfd, keyIcc)
    printByteArray("xorKey", xorKey)
    printByteArray(
        "expect",
        byteArrayOf(
            0x59.toByte(), 0x91.toByte(), 0x0B.toByte(), 0x0A.toByte(),
            0x4B.toByte(), 0xBA.toByte(), 0x14.toByte(), 0xA9.toByte(),
            0x93.toByte(), 0xB5.toByte(), 0xF3.toByte(), 0x7B.toByte(),
            0xF0.toByte(), 0xCC.toByte(), 0x40.toByte(), 0x9F.toByte()
        )
    )
    println("-----------------------------------------------------------------------------")

    val keySessionEnc = MessageDigest.getInstance("SHA-1").digest(
        xorKey + byteArrayOf(0x00, 0x00, 0x00, 0x01)
    ).copyOfRange(0, 16)
    printByteArray("keySessionEnc", keySessionEnc)
    printByteArray(
        "expectKeySEnc",
        byteArrayOf(
            0xCE.toByte(), 0x94.toByte(), 0x93.toByte(), 0x8E.toByte(),
            0x19.toByte(), 0xE3.toByte(), 0xB9.toByte(), 0x7D.toByte(),
            0xF9.toByte(), 0x6E.toByte(), 0xAB.toByte(), 0xCE.toByte(),
            0xDC.toByte(), 0x17.toByte(), 0x15.toByte(), 0xCC.toByte()
        )
    )
    println("-----------------------------------------------------------------------------")

    val authSendMessage = tdes2keyEncode(
        keySessionEnc,
        cardNumber.toByteArray() + byteArrayOf(0x80.toByte(), 0x00, 0x00, 0x00)
    )
    printByteArray("authSendMessage", authSendMessage)
    printByteArray(
        "expectAuthSendM",
        byteArrayOf(
            0x1A.toByte(), 0xA8.toByte(), 0x29.toByte(), 0x73.toByte(),
            0xDB.toByte(), 0x95.toByte(), 0x9A.toByte(), 0x81.toByte(),
            0x1F.toByte(), 0x97.toByte(), 0x11.toByte(), 0xD7.toByte(),
            0x28.toByte(), 0xF0.toByte(), 0xEE.toByte(), 0xF6.toByte()
        )
    )

}

fun tdes2keyEncode(
    key: ByteArray,
    data: ByteArray
): ByteArray {
    val cipherKey1 = Cipher.getInstance("DESede/CBC/NoPadding").apply {
        init(
            Cipher.ENCRYPT_MODE,
            SecretKeyFactory.getInstance("DESede").generateSecret(DESedeKeySpec(key + key.copyOfRange(0, 8))),
            IvParameterSpec(ByteArray(8))
        )
    }
    return data.let {
        cipherKey1.doFinal(it)
    }
}

fun tdes2keyDecode(
    key: ByteArray,
    data: ByteArray
): ByteArray {
    val cipherKey1 = Cipher.getInstance("DESede/CBC/NoPadding").apply {
        init(
            Cipher.DECRYPT_MODE,
            SecretKeyFactory.getInstance("DESede").generateSecret(DESedeKeySpec(key + key.copyOfRange(0, 8))),
            IvParameterSpec(ByteArray(8))
        )
    }
    return data.let {
        cipherKey1.doFinal(it)
    }
}

fun retailMac(
    key: ByteArray,
    data: ByteArray
): ByteArray {
    val mac = ISO9797Alg3Mac(
        DESEngine(),
        ISO7816d4Padding()
    ).apply {
        init(
            KeyParameter(key)
        )
    }

    var result = ByteArray(8)
    mac.update(data, 0, data.size)
    mac.doFinal(result, 0)
    return result

}

fun xorByteArray(
    data1: ByteArray,
    data2: ByteArray
): ByteArray {
    return data1.mapIndexed { index, byte ->
        byte xor data2[index]
    }.toByteArray()
}

fun printByteArray(
    title: String,
    data: ByteArray
) {
    data.map { byteToHexString(it) }.let {
        println("$title : $it")
    }
}

fun byteToHexString(byte: Byte): String {
    return "%02X".format(byte.toByte())
}