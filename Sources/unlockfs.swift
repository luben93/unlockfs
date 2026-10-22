// unlockfs: read-only FUSE filesystem (FUSE-T) serving AES-GCM encrypted files behind a Touch ID / password prompt.
// The first open() after the grant lapsed asks the user; approval is cached for a TTL (ssh-agent style).
// Built with -D UNLOCKFS_TESTING, the prompt can be replaced by a control file for automated tests (never in release builds).
import Foundation
import CryptoKit
import CFuse
import LocalAuthentication
import AppKit
import Security

// MARK: config
let env = ProcessInfo.processInfo.environment
let home = NSHomeDirectory()
let storeDir = env["UNLOCKFS_STORE"] ?? home + "/.unlockfs/store"
#if UNLOCKFS_TESTING
let authMode = env["UNLOCKFS_AUTH"] ?? "touchid"
let testDir = env["UNLOCKFS_TEST_DIR"]
#else
let authMode = "touchid"
let testDir: String? = nil
#endif
let ttl = TimeInterval(env["UNLOCKFS_TTL"] ?? "") ?? 8 * 3600
let denySecs = TimeInterval(env["UNLOCKFS_DENY_SECS"] ?? "") ?? 30
let pidFile = env["UNLOCKFS_PIDFILE"] ?? home + "/.unlockfs.pid"
let reason = env["UNLOCKFS_REASON"] ?? "Unlock protected files"
let overhead = 28   // 12 nonce + 16 tag

func die(_ m: String) -> Never { FileHandle.standardError.write(Data((m + "\n").utf8)); exit(1) }
func log(_ m: String) { FileHandle.standardError.write(Data("[unlockfs] \(m)\n".utf8)) }

// MARK: key
func loadKey() -> SymmetricKey {
    #if UNLOCKFS_TESTING
    if authMode == "test" || env["UNLOCKFS_KEYFILE"] != nil {
        guard let p = env["UNLOCKFS_KEYFILE"] ?? testDir.map({ $0 + "/key" }) else { die("UNLOCKFS_TEST_DIR required in test mode") }
        if let data = FileManager.default.contents(atPath: p), data.count == 32 { return SymmetricKey(data: data) }
        let k = SymmetricKey(size: .bits256); let data = k.withUnsafeBytes { Data($0) }
        FileManager.default.createFile(atPath: p, contents: data, attributes: [.posixPermissions: 0o600]); return k
    }
    #endif
    let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "unlockfs",
                            kSecAttrAccount as String: "store-key", kSecReturnData as String: true]
    var out: AnyObject?
    if SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let d = out as? Data, d.count == 32 { return SymmetricKey(data: d) }
    let k = SymmetricKey(size: .bits256); let data = k.withUnsafeBytes { Data($0) }
    let add: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "unlockfs",
                              kSecAttrAccount as String: "store-key", kSecValueData as String: data]
    guard SecItemAdd(add as CFDictionary, nil) == errSecSuccess else { die("cannot store key in keychain") }
    return k
}
let key = loadKey()

// MARK: grant state (ssh-agent style)
let gate = NSLock()
var grantUntil: UInt64 = 0   // monotonic ns (CLOCK_MONOTONIC counts sleep, immune to wall-clock changes)
var denyUntil: UInt64 = 0
func nowNs() -> UInt64 { clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) }
func ns(_ s: TimeInterval) -> UInt64 { UInt64(s * 1e9) }

func prompt() -> Bool {
    #if UNLOCKFS_TESTING
    if authMode == "test" {
        let d = testDir!
        let line = "\(Date().timeIntervalSince1970) PROMPT\n"
        if let h = FileHandle(forWritingAtPath: d + "/prompts.log") { h.seekToEndOfFile(); h.write(Data(line.utf8)); h.closeFile() }
        else { FileManager.default.createFile(atPath: d + "/prompts.log", contents: Data(line.utf8)) }
        if let delay = Double(env["UNLOCKFS_TEST_DELAY"] ?? "") { Thread.sleep(forTimeInterval: delay) }
        let ans = (try? String(contentsOfFile: d + "/answer", encoding: .utf8))?.trimmingCharacters(in: .whitespacesAndNewlines)
        return ans == "approve"
    }
    #endif
    let ctx = LAContext(); var err: NSError?
    guard ctx.canEvaluatePolicy(.deviceOwnerAuthentication, error: &err) else { log("auth unavailable: \(err?.localizedDescription ?? "?")"); return false }
    let sem = DispatchSemaphore(value: 0); var ok = false
    ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, _ in ok = success; sem.signal() }
    sem.wait(); return ok
}

/// Serialised: concurrent opens wait on one prompt, then see the grant.
func ensureGrant() -> Bool {
    gate.lock(); defer { gate.unlock() }
    let now = nowNs()
    if now < grantUntil { return true }
    if now < denyUntil { return false }
    if prompt() { grantUntil = nowNs() + ns(ttl); log("granted for \(Int(ttl))s"); return true }
    denyUntil = nowNs() + ns(denySecs); log("denied; blocked for \(Int(denySecs))s"); return false
}
func revoke(_ why: String) { gate.lock(); grantUntil = 0; denyUntil = 0; gate.unlock(); log("grant revoked (\(why))") }

// MARK: store
func sealed(_ plain: Data) throws -> Data { try AES.GCM.seal(plain, using: key).combined! }
func opened(_ blob: Data) throws -> Data { try AES.GCM.open(try AES.GCM.SealedBox(combined: blob), using: key) }

var handles: [UInt64: Data] = [:]; var nextHandle: UInt64 = 1; let hlock = NSLock()

func encPath(_ p: String) -> String { storeDir + p + ".enc" }

// MARK: FUSE callbacks
func fsGetattr(_ cpath: UnsafePointer<CChar>?, _ st: UnsafeMutablePointer<stat>?) -> Int32 {
    let p = String(cString: cpath!); var s = stat()
    memset(st, 0, MemoryLayout<stat>.size)
    if lstat(storeDir + p, &s) == 0, (s.st_mode & S_IFMT) == S_IFDIR {
        st!.pointee.st_mode = S_IFDIR | 0o755; st!.pointee.st_nlink = 2; st!.pointee.st_uid = getuid(); st!.pointee.st_gid = getgid()
        st!.pointee.st_mtimespec = s.st_mtimespec; return 0
    }
    if stat(encPath(p), &s) == 0, s.st_size >= overhead {
        st!.pointee.st_mode = S_IFREG | 0o444; st!.pointee.st_nlink = 1; st!.pointee.st_size = s.st_size - off_t(overhead)
        st!.pointee.st_uid = getuid(); st!.pointee.st_gid = getgid(); st!.pointee.st_mtimespec = s.st_mtimespec; return 0
    }
    return -ENOENT
}
func fsReaddir(_ cpath: UnsafePointer<CChar>?, _ buf: UnsafeMutableRawPointer?, _ fill: fuse_fill_dir_t?, _ off: off_t, _ fi: UnsafeMutablePointer<fuse_file_info>?) -> Int32 {
    let p = String(cString: cpath!)
    guard let items = try? FileManager.default.contentsOfDirectory(atPath: storeDir + p) else { return -ENOENT }
    _ = fill!(buf, ".", nil, 0); _ = fill!(buf, "..", nil, 0)
    for i in items { _ = fill!(buf, i.hasSuffix(".enc") ? String(i.dropLast(4)) : i, nil, 0) }
    return 0
}
func fsOpen(_ cpath: UnsafePointer<CChar>?, _ fi: UnsafeMutablePointer<fuse_file_info>?) -> Int32 {
    let p = String(cString: cpath!)
    guard let blob = FileManager.default.contents(atPath: encPath(p)) else { return -ENOENT }
    if (fi!.pointee.flags & O_ACCMODE) != O_RDONLY { return -EROFS }
    guard ensureGrant() else { return -EACCES }
    guard let plain = try? opened(blob) else { log("DECRYPT FAILED for \(p) (tampered or wrong key)"); return -EIO }
    hlock.lock(); let h = nextHandle; nextHandle += 1; handles[h] = plain; hlock.unlock()
    fi!.pointee.fh = h; return 0
}
func fsRead(_ cpath: UnsafePointer<CChar>?, _ buf: UnsafeMutablePointer<CChar>?, _ n: Int, _ off: off_t, _ fi: UnsafeMutablePointer<fuse_file_info>?) -> Int32 {
    hlock.lock(); let d = handles[fi!.pointee.fh]; hlock.unlock()
    guard let data = d else { return -EBADF }
    if Int(off) >= data.count { return 0 }
    let end = min(data.count, Int(off) + n); let chunk = data[Int(off)..<end]
    chunk.copyBytes(to: UnsafeMutableRawBufferPointer(start: buf, count: chunk.count)); return Int32(chunk.count)
}
func fsRelease(_ cpath: UnsafePointer<CChar>?, _ fi: UnsafeMutablePointer<fuse_file_info>?) -> Int32 {
    hlock.lock(); handles[fi!.pointee.fh] = nil; hlock.unlock(); return 0
}

// MARK: commands
let args = CommandLine.arguments
guard args.count >= 2 else { die("usage: unlockfs serve <mountpoint> | put <srcfile> <relpath> | lock") }

switch args[1] {
case "put":
    guard args.count == 4 else { die("usage: unlockfs put <srcfile> <relpath>") }
    guard let plain = FileManager.default.contents(atPath: args[2]) else { die("cannot read \(args[2])") }
    let rel = args[3].hasPrefix("/") ? args[3] : "/" + args[3]
    let dest = encPath(rel)
    try FileManager.default.createDirectory(atPath: (dest as NSString).deletingLastPathComponent, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    FileManager.default.createFile(atPath: dest, contents: try sealed(plain), attributes: [.posixPermissions: 0o600])
    print("stored \(rel) (\(plain.count) bytes)")
case "lock":
    guard let s = try? String(contentsOfFile: pidFile, encoding: .utf8), let pid = Int32(s.trimmingCharacters(in: .whitespacesAndNewlines)) else { die("not running") }
    kill(pid, SIGUSR1); print("lock signalled")
case "serve":
    guard args.count >= 3 else { die("usage: unlockfs serve <mountpoint>") }
    try? FileManager.default.createDirectory(atPath: (pidFile as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
    try? "\(getpid())".write(toFile: pidFile, atomically: true, encoding: .utf8)
    signal(SIGUSR1, SIG_IGN)
    let sig = DispatchSource.makeSignalSource(signal: SIGUSR1, queue: .global()); sig.setEventHandler { revoke("SIGUSR1") }; sig.resume()
    Thread.detachNewThread {   // revoke on screen lock / sleep
        let dn = DistributedNotificationCenter.default()
        dn.addObserver(forName: Notification.Name("com.apple.screenIsLocked"), object: nil, queue: nil) { _ in revoke("screen locked") }
        NSWorkspace.shared.notificationCenter.addObserver(forName: NSWorkspace.willSleepNotification, object: nil, queue: nil) { _ in revoke("sleep") }
        RunLoop.current.run()
    }
    var ops = fuse_operations()
    ops.getattr = fsGetattr; ops.readdir = fsReaddir; ops.open = fsOpen; ops.read = fsRead; ops.release = fsRelease
    let fargs = ["unlockfs", "-f", "-o", "volname=unlockfs", args[2]]
    var cargs: [UnsafeMutablePointer<CChar>?] = fargs.map { strdup($0) } + [nil]
    log("serving \(storeDir) at \(args[2]) auth=\(authMode) ttl=\(Int(ttl))s")
    exit(fuse_main_real(Int32(fargs.count), &cargs, &ops, MemoryLayout<fuse_operations>.size, nil))
default: die("unknown command \(args[1])")
}
