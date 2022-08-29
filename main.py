import os
import sys
import hashlib
import struct
import logging
import time
import binascii

from loxodo.src.twofish.twofish_ecb import TwofishECB
from loxodo.src.twofish.twofish_cbc import TwofishCBC

Tag = b"PWS3"
BlkSz = 16
Eof = b"PWS3-EOFPWS3-EOF"

logging.basicConfig(level=logging.INFO, stream=sys.stderr)

MemDumpsDirpath = ""
SafeOutDirpath = ""
Passwd = b""

def compStretchedKey(Passwd, salt, iterations):
    stretched = hashlib.sha256(Passwd + salt).digest()
    for _ in range(iterations):
        stretched = hashlib.sha256(stretched).digest()
    return stretched

def decipherKeys(stretchedKey, cipheredKeys):
    (b1, b2, b3, b4) = [cipheredKeys[i : i + 16] for i in (0, 16, 32, 48)]
    cipher = TwofishECB(stretchedKey)
    return {
        "key": cipher.decrypt(b1) + cipher.decrypt(b2),
        "hmacKey": cipher.decrypt(b3) + cipher.decrypt(b4),
    }

for memDumpFilename in os.listdir(MemDumpsDirpath):
    memDumpFilepath = os.path.join(MemDumpsDirpath, memDumpFilename)
    # main
    with open(memDumpFilepath, "rb") as memDumpFile:
        logging.info("{}".format(memDumpFilepath))

        tag = memDumpFile.read(4)
        if tag != Tag:
            logging.debug("no tag, skipping".format(Tag))
            continue

        salt = memDumpFile.read(32)
        iterationsRaw = memDumpFile.read(4)
        statedStretchedKeyHash = memDumpFile.read(32)

        if (len(salt) + len(iterationsRaw) + len(statedStretchedKeyHash)) != 68:
            logging.debug("too short 1, skipping")
            continue

        iterations = struct.unpack("<L", iterationsRaw)[0]
        if iterations != 2048:
            logging.debug(
                "iterations ({}) != 2048, skipping".format(
                    iterations
                )
            )
            continue

        _stretchedKeyPerfCounter = time.perf_counter()
        stretchedKey = compStretchedKey(Passwd, salt, iterations)
        logging.debug(
            "took {}s to compute the stretched key, {} iterations".format(
                time.perf_counter() - _stretchedKeyPerfCounter, iterations
            )
        )

        stretchedKeyHash = hashlib.sha256(stretchedKey).digest()
        if stretchedKeyHash != statedStretchedKeyHash:
            logging.debug(
                "stretchedKeyHash ({}) != statedStretchedKeyHash ({}), skipping".format(
                    binascii.hexlify(stretchedKeyHash),
                    binascii.hexlify(statedStretchedKeyHash),
                )
            )
            continue

        logging.info(
            "passwd (of hash, sha256: {}) matches".format(
                hashlib.sha256(Passwd).hexdigest()
            )
        )

        cipheredKeys = memDumpFile.read(64)
        cbcIV = memDumpFile.read(16)

        if len(cipheredKeys) + len(cbcIV) != 80:
            logging.warning("too short 2, skipping")
            continue

        # decipheredKeys = decipherKeys(stretchedKey, cipheredKeys)

        blks = []
        eof_ = b""
        eofFound = False
        while True:
            blk = memDumpFile.read(BlkSz)
            if len(blk) < BlkSz:
                break
            if blk == Eof:
                eof_ = blk
                eofFound = True
                break
            blks.append(blk)

        if not eofFound:
            logging.error("eof not found")
            continue

        logging.info("eof found")
        expectedHmac = memDumpFile.read(32)
        if len(expectedHmac) != 32:
            logging.error("too short 3, skipping")
            continue

        logging.info("safe found")

        safe = (
            tag
            + salt
            + iterationsRaw
            + statedStretchedKeyHash
            + cipheredKeys
            + cbcIV
            + (b"").join(blks)
            + eof_
            + expectedHmac
        )

        safeFilepath = os.path.join(SafeOutDirpath, memDumpFilename)
        with open(safeFilepath, "wb") as safeFile:
            safeFile.write(safe)

        logging.info("safe recovered")
