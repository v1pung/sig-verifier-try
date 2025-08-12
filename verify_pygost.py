"""
Usage:
    python3 verify_pygost_full.py <file.pdf> <signature.sig>

Might be hard to install pygost, i did this:
Dockerfile:
    FROM python:3.11-slim

    WORKDIR /work

    RUN apt-get update && apt-get install -y git && apt-get clean

    RUN git clone https://github.com/mosquito/pygost.git /tmp/pygost && \
        cd /tmp/pygost && \
        for f in FAQ INSTALL NEWS; do \
            if [ ! -f "$f" ]; then \
                sed -i "/$f/d" setup.py; \
            fi; \
        done && \
        pip install --no-cache-dir asn1crypto /tmp/pygost

    COPY sig_verifier.py .

and usage: docker run --rm -v "$PWD":/work -w /work gost-verify-py python3 verify_pygost.py name.pdf signature.sig
"""
import sys
from asn1crypto import cms, core
from pygost import gost3410, gost34112012
from pygost.utils import bytes2long, hexenc


def load_cms(sig_bytes):
    ci = cms.ContentInfo.load(sig_bytes)
    if ci['content_type'].native != 'signed_data':
        raise ValueError("Not a SignedData CMS")
    sd = ci['content']
    if len(sd['signer_infos']) < 1:
        raise ValueError("No signerInfos")
    signer_info = sd['signer_infos'][0]
    cert = None
    if sd['certificates'] is not None and len(sd['certificates']) > 0:
        cert = sd['certificates'][0].chosen
    return signer_info, cert, sd


def extract_pub_bytes_from_cert(cert):
    """
    Extract raw public-key bytes from SubjectPublicKeyInfo without
    relying on asn1crypto OID-based public key parsing (which may KeyError).
    Returns original BIT STRING contents (including possible leading 0x00 unused-bits byte).
    """
    spki = cert['tbs_certificate']['subject_public_key_info']
    spki_der = spki.dump()
    seq = core.Sequence.load(spki_der)  # [algo, subjectPublicKey BIT STRING]
    bitstr = seq[1]
    if not isinstance(bitstr, core.BitString):
        raise ValueError("subjectPublicKey not BIT STRING")
    contents = bitstr.contents  # first byte = unused bits count, rest = key bytes
    return contents  # caller will normalize


def normalize_pub_xy(bs_contents):
    """
    Normalize different possible encodings to X||Y (64 bytes) or 128 for 512-bit.
    Accept a few variants: 0x04||XY, leading 0x00, extra bytes — try sensible trims and yield candidates.
    Returns list of candidate raw X||Y byte strings.
    """
    if len(bs_contents) == 0:
        return []
    unused = bs_contents[0]
    key_bytes = bs_contents[1:]
    candidates = []

    # direct
    if len(key_bytes) in (64, 128):
        candidates.append(key_bytes)
    # if it's 0x04||X||Y
    if len(key_bytes) in (65, 129) and key_bytes[0] == 0x04:
        candidates.append(key_bytes[1:])
    # if there is a leading zero that some encoders add
    if len(key_bytes) > 0 and key_bytes[0] == 0x00 and (len(key_bytes) - 1) in (64, 128, 65, 129):
        kb = key_bytes[1:]
        if len(kb) in (64, 128):
            candidates.append(kb)
        if len(kb) in (65, 129) and kb[0] == 0x04:
            candidates.append(kb[1:])

    for offset in range(0, max(0, len(key_bytes) - 63)):
        window = key_bytes[offset:offset + 64]
        if len(window) == 64:
            candidates.append(window)

    uniq = []
    for c in candidates:
        if c not in uniq:
            uniq.append(c)
    return uniq


def canonical_signed_attrs_der(signer_info):
    attrs = signer_info['signed_attrs']
    sorted_attrs = sorted(list(attrs), key=lambda a: a['type'].dump())
    return cms.CMSAttributes(sorted_attrs).dump()


def load_sig_bytes(raw):
    # raw may be bytes or asn1 object
    if isinstance(raw, (bytes, bytearray)):
        b = bytes(raw)
    else:
        # try to fetch parsed.contents if available
        try:
            b = raw.parsed.contents
        except Exception:
            b = bytes(raw)
    # try ASN.1 SEQUENCE {r,s}
    try:
        seq = core.Sequence.load(b)
        if len(seq) == 2:
            r = int(seq[0]).to_bytes(32, "big")
            s = int(seq[1]).to_bytes(32, "big")
            return r + s, "asn1-seq(32/32)"
    except Exception:
        pass
    # raw bytes
    if len(b) == 64:
        return b, "raw-64"
    if len(b) == 128:
        return b[32:64] + b[96:128], "raw-128->64(heur)"

    if len(b) > 64:
        # try last 64 bytes
        return b[-64:], f"tail64-from-{len(b)}"
    raise ValueError("Unsupported signature length: %d" % len(b))


def try_verify_all(pub_candidates, sig_candidate, digest_variants, attempt_logger):
    """
    Try many curves and many signature forms.
    pub_candidates: list of X||Y (bytes)
    sig_candidate: 64-byte r||s
    digest_variants: list of (label, digest_bytes)
    attempt_logger: list to append attempt tuples (digest_label, curve_name, pub_label, sig_form, hash_label, ok_or_exc)
    """
    # prepare signature formats to try
    r = sig_candidate[:len(sig_candidate) // 2]
    s = sig_candidate[len(sig_candidate) // 2:]
    sig_variants = [
        ("r||s", r + s),
        ("s||r", s + r),
        ("rev(r)||rev(s)", r[::-1] + s[::-1]),
        ("rev(s)||rev(r)", s[::-1] + r[::-1]),
    ]

    # pub forms
    pub_forms = []
    for p in pub_candidates:
        L = len(p)
        pub_forms = []
        pub_forms.append(("X||Y", p))
        if L == 64:
            pub_forms.append(("0x04||X||Y", b"\x04" + p))
            pub_forms.append(("Y||X", p[32:64] + p[:32]))
            pub_forms.append(("0x04||Y||X", b"\x04" + p[32:64] + p[:32]))
        elif L == 128:
            pub_forms.append(("0x04||X||Y", b"\x04" + p))
        pub_forms = list(dict(pub_forms).items())

    # iterate curves from pygost
    curve_keys = list(gost3410.CURVES.keys())
    for dlabel, digest in digest_variants:
        for pub_idx, p in enumerate(pub_candidates):
            # produce pub forms for this candidate
            forms = [("X||Y", p)]
            if len(p) == 64:
                forms += [("0x04||X||Y", b"\x04" + p), ("Y||X", p[32:] + p[:32]),
                          ("0x04||Y||X", b"\x04" + p[32:] + p[:32])]
            elif len(p) == 128:
                forms += [("0x04||X||Y", b"\x04" + p)]
            for pub_label, pub_bytes in forms:
                for sig_name, sig_bytes in sig_variants:
                    half = len(sig_bytes) // 2
                    for curve_name in curve_keys:
                        curve = gost3410.CURVES[curve_name]
                        # skip mismatch q size heuristics? we'll try and let pygost error explain
                        try:
                            # try to unmarshal public; if fails skip quickly
                            try:
                                pub_point = gost3410.pub_unmarshal(pub_bytes)
                            except Exception as e_pub:
                                attempt_logger.append(
                                    (dlabel, curve_name, pub_label, sig_name, "pub_unmarshal", str(e_pub)))
                                continue
                            r_int = bytes2long(sig_bytes[:half])
                            s_int = bytes2long(sig_bytes[half:])
                            # try verify
                            gost3410.verify(curve, pub_point, digest, (r_int, s_int))
                            attempt_logger.append((dlabel, curve_name, pub_label, sig_name, "OK", "verified"))
                            return True, (dlabel, curve_name, pub_label, sig_name)
                        except Exception as e:
                            attempt_logger.append((dlabel, curve_name, pub_label, sig_name, "ERR", str(e)))
                            continue
    return False, attempt_logger


def main(pdf_path, sig_path):
    pdf_data = open(pdf_path, "rb").read() if pdf_path else None
    sig_data = open(sig_path, "rb").read()

    signer_info, cert, sd = load_cms(sig_data)
    has_certs = sd['certificates'] is not None and len(sd['certificates']) > 0
    print(f"[DBG] CMS has certificates: {has_certs}")

    if pdf_data:
        pdf_h = gost34112012.GOST34112012(data=pdf_data, digest_size=32).digest()
        print("[INFO] PDF streebog256:", hexenc(pdf_h))

    md = None
    if 'signed_attrs' in signer_info and signer_info['signed_attrs'] is not None:
        for a in signer_info['signed_attrs']:
            if a['type'].native == 'message_digest':
                md = a['values'][0].native
                break
    if md:
        print("[INFO] messageDigest (from attrs):", hexenc(md))

    # prepare signed_attrs variants
    raw_attrs_der = signer_info['signed_attrs'].dump()
    canon_attrs_der = canonical_signed_attrs_der(signer_info)
    raw_h = gost34112012.GOST34112012(data=raw_attrs_der, digest_size=32).digest()
    canon_h = gost34112012.GOST34112012(data=canon_attrs_der, digest_size=32).digest()
    print("raw signed_attrs len:", len(raw_attrs_der), "hash:", hexenc(raw_h))
    print("canon signed_attrs len:", len(canon_attrs_der), "hash:", hexenc(canon_h))

    # extract public key candidates
    if cert is None:
        print("[ERROR] No certificate available in CMS")
        return 2

    raw_bit_contents = extract_pub_bytes_from_cert(cert)
    print("[DBG] raw key_bytes len:", len(raw_bit_contents), "start:", hexenc(raw_bit_contents[:8]))
    pub_cands = normalize_pub_xy(raw_bit_contents)
    print(f"[DBG] found pub candidate count: {len(pub_cands)}")
    for i, p in enumerate(pub_cands):
        print(f"  pub[{i}] len {len(p)} start: {hexenc(p[:8])}")

    # signature bytes
    sig_field = signer_info['signature'].native
    sig_bytes, sig_method = load_sig_bytes(sig_field)
    print("[DBG] signature candidate len:", len(sig_bytes), "method:", sig_method, "start:", hexenc(sig_bytes[:8]))

    # digest variants to try
    digest_variants = [
        ("canon_streebog256", canon_h),
        ("raw_streebog256", raw_h),
    ]
    if md is not None:
        digest_variants.append(("messageDigest", md))

    # try heavy verification
    attempts = []
    print("\n[TRY] Attempt verification combinations...")
    ok, info = try_verify_all(pub_cands, sig_bytes, digest_variants, attempts)

    if ok:
        print("[OK] Verified! detail:", info)
        return 0

    # Not verified -> print summary of attempts (trim)
    print("\n[FAIL] no verify. sample attempts:")
    for rec in attempts[:120]:
        print(rec)
    # extra q-check: print whether r/s < q for some curves for quick sanity
    try:
        r = bytes2long(sig_bytes[:32])
        s = bytes2long(sig_bytes[32:])
        print("\n[CHK] r,s as ints:", r, s)
        print("[CHK] curve q bits / r<q s<q for some curves:")
        for k in list(gost3410.CURVES.keys())[:40]:
            q = gost3410.CURVES[k].q
            qbits = q.bit_length()
            print(f"{k:40s} q_bits {qbits:3d} r<q? {r < q} s<q? {s < q}")
    except Exception:
        pass
    return 2


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: verify_pygost_full.py <pdf> <sig>")
        sys.exit(1)
    sys.exit(main(sys.argv[1], sys.argv[2]))
