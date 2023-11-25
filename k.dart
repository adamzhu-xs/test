import 'dart:convert';
import 'dart:typed_data';

import 'package:basic_utils/basic_utils.dart';
import 'package:pointycastle/export.dart';

Future<void> main() async {
  var pubkey = '''-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAjv5LOt9mYjvlpWWIxdahNHU6b3EN
SM57WsLILZaq+0GRPBrvpEC50RQ6wJYqHizd0vTATOJ6JorqFldXTCTAAy0BGzcL
ImdSMrMwCZf8M0JAmRSo3T2qyF4NBxquLBMaI3a77Mo5939Mjmcjy8ke3cRNnnUd
gL0Y6lJuiSyOUXo9yis=
-----END PUBLIC KEY-----''';

  var prikey = '''-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIBjRQlt2Vm9VmKi8sY0bWxJZvsgSXXOTijJql+nCyjKUs2FiFPG5Mc
f+WyWcejbQHtYbBVtIkdCD56mahIkHa6xWKgBwYFK4EEACOhgYkDgYYABACO/ks6
32ZiO+WlZYjF1qE0dTpvcQ1Izntawsgtlqr7QZE8Gu+kQLnRFDrAlioeLN3S9MBM
4nomiuoWV1dMJMADLQEbNwsiZ1IyszAJl/wzQkCZFKjdParIXg0HGq4sExojdrvs
yjn3f0yOZyPLyR7dxE2edR2AvRjqUm6JLI5Rej3KKw==
-----END EC PRIVATE KEY-----''';

  var publicKey = CryptoUtils.ecPublicKeyFromPem(pubkey);
  var privateKey = CryptoUtils.ecPrivateKeyFromPem(prikey);

  var pubkeyFromJava =
      'MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAr8gxZn13MCIx5TBoCIrp7noLxmryWGOjv62byFJl2+muPTo6GzJPE2uVW9Pay8zifAVEW9zNB7muqZ9r94Vw2T0AW7KeE+B578ieHRDHKqTPfEuNPW658XOApy/j3ghkfWsrJqYmPkmde0lPs+x1F1YgRd7MI5LCU+Cko3tY87ZwOY8=';
  var publicKeyFromJava = CryptoUtils.ecPublicKeyFromPem(
      '-----BEGIN PUBLIC KEY-----\n$pubkeyFromJava\n-----END PUBLIC KEY-----');

  var agreement = ECDHBasicAgreement();
  agreement.init(privateKey);
  var sharedSecret = agreement.calculateAgreement(publicKeyFromJava);

  final Uint8List unit8List = utf8.encode(sharedSecret.toRadixString(16));
  final hash = SHA256Digest().process(unit8List);

  var text = '123412341234';
  var padded = pad(utf8.encode(text), 8); // 8 for PKCS#5

  var iv = utf8.encode('1234567890123456');

  var enc = aesCbcEncrypt(hash, iv, padded);
  print(enc);
  print(base64.encode(enc));

  var dec = aesCbcDecrypt(hash, iv, enc);
  print(utf8.decode(dec));

  // print(sharedSecret.toRadixString(16));
  // d435420ee5dcf640c9867ccfd4eac88571eaff95f64a1f697b0e78082898061fb5e1a8734317632e673a15dc104119f97912c3dca5c199162edb73a01e7ae75ca
}

void genKeys() {
  final keypair =
      CryptoUtils.generateEcKeyPair(curve: ECCurve_secp521r1().domainName);
  var x509pemFromDart =
      CryptoUtils.encodeEcPublicKeyToPem(keypair.publicKey as ECPublicKey);
  var sec1pemFromDart =
      CryptoUtils.encodeEcPrivateKeyToPem(keypair.privateKey as ECPrivateKey);
  print(x509pemFromDart);
  print(sec1pemFromDart);
}

Uint8List aesCbcEncrypt(
    Uint8List key, Uint8List iv, Uint8List paddedPlaintext) {
  assert([128, 192, 256].contains(key.length * 8));
  assert(128 == iv.length * 8);
  assert(128 == paddedPlaintext.length * 8);

  // Create a CBC block cipher with AES, and initialize with key and IV

  final cbc = CBCBlockCipher(AESEngine())
    ..init(true, ParametersWithIV(KeyParameter(key), iv)); // true=encrypt

  // Encrypt the plaintext block-by-block

  final cipherText = Uint8List(paddedPlaintext.length); // allocate space

  var offset = 0;
  while (offset < paddedPlaintext.length) {
    offset += cbc.processBlock(paddedPlaintext, offset, cipherText, offset);
  }
  assert(offset == paddedPlaintext.length);

  return cipherText;
}

Uint8List aesCbcDecrypt(Uint8List key, Uint8List iv, Uint8List cipherText) {
  assert([128, 192, 256].contains(key.length * 8));
  assert(128 == iv.length * 8);
  assert(128 == cipherText.length * 8);

  // Create a CBC block cipher with AES, and initialize with key and IV

  final cbc = CBCBlockCipher(AESEngine())
    ..init(false, ParametersWithIV(KeyParameter(key), iv)); // false=decrypt

  // Decrypt the cipherText block-by-block

  final paddedPlainText = Uint8List(cipherText.length); // allocate space

  var offset = 0;
  while (offset < cipherText.length) {
    offset += cbc.processBlock(cipherText, offset, paddedPlainText, offset);
  }
  assert(offset == cipherText.length);

  return paddedPlainText;
}

Uint8List pad(Uint8List bytes, int blockSizeBytes) {
  // The PKCS #7 padding just fills the extra bytes with the same value.
  // That value is the number of bytes of padding there is.
  //
  // For example, something that requires 3 bytes of padding with append
  // [0x03, 0x03, 0x03] to the bytes. If the bytes is already a multiple of the
  // block size, a full block of padding is added.

  final padLength = blockSizeBytes - (bytes.length % blockSizeBytes);

  final padded = Uint8List(bytes.length + padLength)..setAll(0, bytes);
  PKCS7Padding().addPadding(padded, bytes.length);

  return padded;
}
