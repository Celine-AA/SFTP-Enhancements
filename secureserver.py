import os
import sys
import re
import vt
from hashlib import md5
from twisted.conch import avatar, interfaces as conchinterfaces
from twisted.conch.ssh import factory, keys, session
from twisted.conch.ssh import filetransfer
from twisted.cred import portal, checkers
from twisted.internet import reactor, defer
from twisted.python import log, components
from zope.interface import implementer
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

client = vt.Client('APIKEY')

log.startLogging(sys.stdout)

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
USER_DIRS = {
    "salma": os.path.join(BASE_DIR, "users", "salma"),
    "celine": os.path.join(BASE_DIR, "users", "celine"),
}
for path in USER_DIRS.values():
    os.makedirs(path, exist_ok=True)

# --- AES Encryption Setup ---
def load_aes_key():
    key_dir = os.path.join(BASE_DIR, "keys")
    os.makedirs(key_dir, exist_ok=True)
    key_path = os.path.join(key_dir, "aes.key")
    if not os.path.exists(key_path):
        with open(key_path, "wb") as f:
            f.write(os.urandom(16))  # AES-128
    with open(key_path, "rb") as f:
        return f.read()

AES_KEY = load_aes_key()


def get_cipher(iv):
    return Cipher(algorithms.AES(AES_KEY), modes.CFB(iv), backend=default_backend())


def encrypt_data_chunk(iv, data):
    cipher = get_cipher(iv)
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


def decrypt_data(data):
    iv = data[:16]
    cipher = get_cipher(iv)
    decryptor = cipher.decryptor()
    return decryptor.update(data[16:]) + decryptor.finalize()


# --- Password checker with logging ---
class LoggingPasswordChecker(checkers.InMemoryUsernamePasswordDatabaseDontUse):
    def requestAvatarId(self, credentials):
        print(f"Trying login: {credentials.username.decode()} / {credentials.password.decode()}")
        avatarId = super().requestAvatarId(credentials)
        print(f"Login success for: {avatarId}")
        return avatarId


# --- File wrapper for read/write ---
class FileReader:
    def __init__(self, file):
        self.file = file
        self.iv = self.file.read(16)  # Read IV from beginning
        self.decryptor = get_cipher(self.iv).decryptor()
        self.file_offset = 16  # skip IV
        self.buffer = b''

    def readChunk(self, offset, length):
        self.file.seek(self.file_offset + offset)
        chunk = self.file.read(length)
        decrypted = self.decryptor.update(chunk)
        return decrypted

    def close(self):
        try:
            final = self.decryptor.finalize()
        except Exception as e:
            print(f"[WARN] Error finalizing decryption: {e}")
        self.file.close()

class FileWriter:
    def __init__(self, file):
        self.file = file
        self.iv = os.urandom(16)
        self.encryptor = get_cipher(self.iv).encryptor()
        self.position = 0
        self.file.seek(0)
        self.file.write(self.iv)  # Write IV at the beginning
        self.position += len(self.iv)

        self.hasher = md5()  # Hash plaintext before encryption

    def writeChunk(self, offset, data):
        self.hasher.update(data)  # Update hash with plaintext
        encrypted = self.encryptor.update(data)
        self.file.seek(self.position)
        self.file.write(encrypted)
        self.position += len(encrypted)
        return defer.succeed(None)

    def close(self):
        final = self.encryptor.finalize()
        self.file.write(final)
        self.file.close()

        # Get the hash of the plaintext
        md5_hash = self.hasher.hexdigest()
        print(f"[VirusTotal] MD5 hash of plaintext: {md5_hash}")

        # Query VirusTotal using the correct hash
        try:
            file_info = client.get_object(f"/files/{md5_hash}")
            positives = file_info.last_analysis_stats.get("malicious", 0)
            if positives > 0:
                print(f"[ALERT] File flagged as malicious by {positives} engine(s). Deleting file.")
                os.remove(self.file.name)
                raise Exception("Upload rejected: file flagged as malicious.")
            else:
                print(f"[VirusTotal] File is clean according to VirusTotal.")
        except Exception as e:
            print(f"[ERROR] Finalizing encryption or VirusTotal scan failed: {e}")
        try:
            self.file.close()
        except:
            pass


# SFTP (traditional)

# --- Custom directory object ---
class DirectoryLister:
    def __init__(self, path):
        self.path = path
        self.files = os.listdir(path)
        self.index = 0

    def __iter__(self):
        return self

    def __next__(self):
        if self.index >= len(self.files):
            raise StopIteration

        filename = self.files[self.index]
        self.index += 1

        full_path = os.path.join(self.path, filename)
        stat_data = os.stat(full_path)

        attrs = {
            "size": stat_data.st_size,
            "uid": stat_data.st_uid,
            "gid": stat_data.st_gid,
            "permissions": stat_data.st_mode,
            "atime": int(stat_data.st_atime),
            "mtime": int(stat_data.st_mtime),
        }

        is_dir = os.path.isdir(full_path)
        perms = 'd' if is_dir else '-'
        perms += 'r' if (stat_data.st_mode & 0o400) else '-'
        perms += 'w' if (stat_data.st_mode & 0o200) else '-'
        perms += 'x' if (stat_data.st_mode & 0o100) else '-'
        perms += 'r' if (stat_data.st_mode & 0o040) else '-'
        perms += 'w' if (stat_data.st_mode & 0o020) else '-'
        perms += 'x' if (stat_data.st_mode & 0o010) else '-'
        perms += 'r' if (stat_data.st_mode & 0o004) else '-'
        perms += 'w' if (stat_data.st_mode & 0o002) else '-'
        perms += 'x' if (stat_data.st_mode & 0o001) else '-'

        nlink = stat_data.st_nlink
        uid = stat_data.st_uid
        gid = stat_data.st_gid
        size = stat_data.st_size
        mtime = stat_data.st_mtime
        import time
        time_str = time.strftime('%b %d %H:%M', time.localtime(mtime))
        longname = f"{perms} {nlink} {uid} {gid} {size} {time_str} {filename}"

        filename_bytes = filename.encode('utf-8')

        return (filename_bytes, longname, attrs)

    def close(self):
        pass

@implementer(conchinterfaces.ISFTPServer)
class SimpleSFTP:
    def __init__(self, avatar):
        self.avatar = avatar
        self.root = avatar.home

    def _abs_for_dir(self, path):
        if isinstance(path, bytes):
            path = path.decode("utf-8")

        print(f"[DEBUG] Raw incoming path (dir): {path}")
        path = path.replace("\\", "/")
        root_real = os.path.realpath(self.root)
        norm_path = os.path.normpath(path)

        if os.path.isabs(norm_path):
            candidate = os.path.realpath(norm_path)
        else:
            candidate = os.path.realpath(os.path.join(root_real, norm_path))

        print(f"[DEBUG] Final resolved path (dir): {candidate}")

        if not candidate.startswith(root_real):
            raise filetransfer.SFTPError(
                filetransfer.FX_PERMISSION_DENIED,
                f"Access outside user directory: {candidate}"
            )

        return candidate

    def _abs_for_io(self, path):
        if isinstance(path, bytes):
            path = path.decode("utf-8")

        print(f"[DEBUG] Raw incoming path (io): {path}")

        if re.match(r"^[A-Z]:\\", path, re.I):
            filename = os.path.basename(path)
        else:
            filename = path

        full = os.path.join(self.root, filename)
        print(f"[DEBUG] Final resolved path (io): {full}")
        return full

    def gotVersion(self, version, ext):
        print(f"Received version: {version}")
        print(f"Received extensions: {ext}")
        return {}

    def openFile(self, filename, flags, attrs):
        print(f"Opening file: {filename}")
        full = self._abs_for_io(filename)
        print(f"Full path: {full}")

        try:
            if flags & filetransfer.FXF_READ:
                fobj = open(full, "rb")
                return defer.succeed(FileReader(fobj))
            else:
                fobj = open(full, "r+b" if os.path.exists(full) else "wb")
                return defer.succeed(FileWriter(fobj))
        except Exception as e:
            print(f"Error opening file: {e}")
            return defer.fail(filetransfer.SFTPError(filetransfer.FX_FAILURE, str(e)))

    def removeFile(self, path):
        try:
            os.remove(self._abs_for_io(path))
            return defer.succeed(None)
        except Exception as e:
            return defer.fail(filetransfer.SFTPError(filetransfer.FX_FAILURE, str(e)))

    def renameFile(self, oldpath, newpath):
        try:
            os.rename(self._abs_for_io(oldpath), self._abs_for_io(newpath))
            return defer.succeed(None)
        except Exception as e:
            return defer.fail(filetransfer.SFTPError(filetransfer.FX_FAILURE, str(e)))

    def makeDirectory(self, path, attrs):
        try:
            os.makedirs(self._abs_for_io(path), exist_ok=True)
            return defer.succeed(None)
        except Exception as e:
            return defer.fail(filetransfer.SFTPError(filetransfer.FX_FAILURE, str(e)))

    def removeDirectory(self, path):
        try:
            os.rmdir(self._abs_for_io(path))
            return defer.succeed(None)
        except Exception as e:
            return defer.fail(filetransfer.SFTPError(filetransfer.FX_FAILURE, str(e)))

    def openDirectory(self, path):
        print(f"Opening directory: {path}")
        try:
            full = self._abs_for_dir(path)
            return defer.succeed(DirectoryLister(full))
        except Exception as e:
            print(f"Error opening directory: {e}")
            return defer.fail(filetransfer.SFTPError(filetransfer.FX_FAILURE, str(e)))

    def getAttrs(self, path, followLinks):
        try:
            full = self._abs_for_io(path)
            stat_data = os.stat(full)
            attrs = {
                "size": stat_data.st_size,
                "uid": stat_data.st_uid,
                "gid": stat_data.st_gid,
                "permissions": stat_data.st_mode,
                "atime": int(stat_data.st_atime),
                "mtime": int(stat_data.st_mtime),
            }
            return defer.succeed(attrs)
        except Exception as e:
            return defer.fail(filetransfer.SFTPError(filetransfer.FX_FAILURE, str(e)))

    def setAttrs(self, path, attrs):
        return defer.succeed(None)

    def readLink(self, path):
        try:
            return defer.succeed(os.readlink(self._abs_for_io(path)).encode())
        except Exception as e:
            return defer.fail(filetransfer.SFTPError(filetransfer.FX_FAILURE, str(e)))

    def makeLink(self, linkPath, targetPath):
        try:
            os.symlink(self._abs_for_io(targetPath), self._abs_for_io(linkPath))
            return defer.succeed(None)
        except Exception as e:
            return defer.fail(filetransfer.SFTPError(filetransfer.FX_FAILURE, str(e)))

    def realPath(self, path):
        print(f"Resolving real path for: {path}")
        try:
            full = self._abs_for_io(path)
            return defer.succeed(full.encode())
        except Exception as e:
            return defer.fail(filetransfer.SFTPError(filetransfer.FX_FAILURE, str(e)))

@implementer(conchinterfaces.ISession)
class SimpleAvatar(avatar.ConchUser):
    def __init__(self, username):
        avatar.ConchUser.__init__(self)
        self.username = username
        self.home = USER_DIRS[username.decode()]

        self.channelLookup[b"session"] = session.SSHSession
        self.subsystemLookup[b"sftp"] = filetransfer.FileTransferServer

    def getPty(self, terminal, windowSize, attrs): pass
    def openShell(self, protocol): pass
    def execCommand(self, protocol, cmd): pass
    def eofReceived(self): pass
    def closed(self): pass

    def gotSFTP(self):
        return SimpleSFTP(self)

components.registerAdapter(
    lambda avatar: avatar.gotSFTP(),
    SimpleAvatar,
    conchinterfaces.ISFTPServer
)

@implementer(portal.IRealm)
class SimpleRealm:
    def requestAvatar(self, avatarId, mind, *interfaces):
        print(f"[Realm] Creating avatar for: {avatarId}")
        if conchinterfaces.IConchUser in interfaces:
            return conchinterfaces.IConchUser, SimpleAvatar(avatarId), lambda: None
        else:
            raise Exception(f"Unsupported interface: {interfaces}")

def getRSAKeys():
    key_dir = os.path.join(BASE_DIR, "keys")
    os.makedirs(key_dir, exist_ok=True)
    priv_path = os.path.join(key_dir, "server.key")
    pub_path = os.path.join(key_dir, "server.key.pub")

    if not os.path.exists(priv_path):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        with open(priv_path, "wb") as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))
        with open(pub_path, "wb") as f:
            f.write(key.public_key().public_bytes(
                serialization.Encoding.OpenSSH,
                serialization.PublicFormat.OpenSSH,
            ))

    with open(priv_path, "rb") as f: priv = keys.Key.fromString(f.read())
    with open(pub_path, "rb") as f: pub = keys.Key.fromString(f.read())
    return priv, pub

def run():
    priv, pub = getRSAKeys()

    sftp_factory = factory.SSHFactory()
    sftp_factory.portal = portal.Portal(SimpleRealm())

    checker = LoggingPasswordChecker()
    checker.addUser(b"salma", b"salma")
    checker.addUser(b"celine", b"celine")
    sftp_factory.portal.registerChecker(checker)

    print("Registered users:")
    for username in checker.users:
        print(f" - {username.decode()}")

    sftp_factory.privateKeys = {b'ssh-rsa': priv}
    sftp_factory.publicKeys = {b'ssh-rsa': pub}

    reactor.listenTCP(2222, sftp_factory)
    print("SFTP server running on port 2222")
    reactor.run()

if __name__ == "__main__":
    run()
