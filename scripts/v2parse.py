# -*- coding: utf-8 -*-
# language: Python 3, file: v2parse.py — 解析并验签 APK v2 签名块(用于确认格式理解正确)
import sys, struct
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography import x509

MAGIC = b'APK Sig Block 42'
V2_ID = 0x7109871a


def find_block(d):
    i = d.rfind(MAGIC)
    if i < 0:
        return None
    bs = struct.unpack_from('<Q', d, i - 8)[0]
    start = i + 16 - bs - 8
    return start, bs + 8, i


def lp(d, o):
    n = struct.unpack_from('<I', d, o)[0]
    return d[o + 4:o + 4 + n], o + 4 + n


def parse_v2(value):
    signers, _ = lp(value, 0)
    signer, _ = lp(signers, 0)
    signed_data, o = lp(signer, 0)
    sigs, _ = lp(signer, o)
    pk, _ = lp(signer, o) if False else lp(signer, o)
    # 重新解一遍(上面的 offset 写法容易错)
    o = 0
    sd, o = lp(signer, o)
    sg, o = lp(signer, o)
    pk, o = lp(signer, o)
    return sd, sg, pk


def parse_seq(b):
    out = []
    o = 0
    while o < len(b):
        item, o = lp(b, o)
        out.append(item)
    return out


def main(path):
    d = open(path, 'rb').read()
    blk = find_block(d)
    if not blk:
        print('无 APK Signing Block')
        return 1
    start, size, magic_at = blk
    print('签名块 start=0x%x size=%d' % (start, size))
    o = start + 8
    v2 = None
    while o < magic_at - 8:
        ln = struct.unpack_from('<Q', d, o)[0]
        pid = struct.unpack_from('<I', d, o + 8)[0]
        val = d[o + 12:o + 8 + ln]
        print('  pair id=0x%08x len=%d' % (pid, ln - 4))
        if pid == V2_ID:
            v2 = val
        o += 8 + ln
    if v2 is None:
        print('没有 v2 块')
        return 1

    signers_raw, _ = lp(v2, 0)
    signer, _ = lp(signers_raw, 0)
    o = 0
    signed_data, o = lp(signer, o)
    sigs_blob, o = lp(signer, o)
    pubkey_der, o = lp(signer, o)
    print('\n  signed_data=%d  signatures=%d  pubkey=%d' % (len(signed_data), len(sigs_blob), len(pubkey_der)))

    # signed_data 内部三段
    o2 = 0
    digests, o2 = lp(signed_data, o2)
    certs, o2 = lp(signed_data, o2)
    attrs, o2 = lp(signed_data, o2)
    print('  digests=%d certs=%d attrs=%d' % (len(digests), len(certs), len(attrs)))
    for item in parse_seq(digests):
        alg = struct.unpack_from('<I', item, 0)[0]
        dg, _ = lp(item, 4)
        print('    digest alg=0x%04x len=%d  %s' % (alg, len(dg), dg.hex()[:48]))
    cert_list = parse_seq(certs)
    print('    证书数 = %d' % len(cert_list))
    sig_list = parse_seq(sigs_blob)
    print('    签名数 = %d' % len(sig_list))

    # 用证书公钥验签 signed_data
    cert = x509.load_der_x509_certificate(cert_list[0])
    print('\n  证书: %s' % cert.subject.rfc4514_string())
    print('  颁发: %s' % cert.issuer.rfc4514_string())
    for item in sig_list:
        alg = struct.unpack_from('<I', item, 0)[0]
        sig, _ = lp(item, 4)
        print('  验签 alg=0x%04x sig_len=%d' % (alg, len(sig)))
        try:
            cert.public_key().verify(sig, signed_data, padding.PKCS1v15(), hashes.SHA256())
            print('    => 签名有效 ✔  (说明我解析的 signed_data 边界正确)')
        except Exception as e:
            print('    => 验签失败: %s' % e)
    # 公钥是否等同证书公钥
    try:
        pk = load_der_public_key(pubkey_der)
        a = pk.public_numbers()
        b = cert.public_key().public_numbers()
        print('  公钥与证书一致: %s' % (a.n == b.n and a.e == b.e))
    except Exception as e:
        print('  公钥解析失败: %s' % e)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1]))
