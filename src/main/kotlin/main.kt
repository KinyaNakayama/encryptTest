import org.bouncycastle.crypto.engines.DESEngine
import org.bouncycastle.crypto.macs.ISO9797Alg3Mac
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.DESKeySpec
import javax.crypto.spec.DESedeKeySpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.Mac

import java.security.Security


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

    val encIfd = tdes2key(
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

}

fun tdes2key(
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

fun retailMac(
    key: ByteArray,
    data: ByteArray
): ByteArray {
    val mac = ISO9797Alg3Mac(
        DESEngine(),
        org.bouncycastle.crypto.paddings.ISO7816d4Padding()
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