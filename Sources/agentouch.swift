// agentouch — run a command with a secret, after the user approves that exact command with Touch ID.
//
// Secrets are sealed to a Secure Enclave key that only works after a fingerprint, so
// nothing on disk is usable without the user. A secret is handed to the approved command
// (as an env var or on stdin), is never printed, and is redacted from the command's output.
//
//   Build with ./build.sh, which stamps the git commit into the binary (agentouch --version).
//   The command-line entry point is main.swift; everything else lives here so the checks can
//   be tested without Touch ID (tests/main.swift).
//
//   agentouch init                               create the Secure Enclave key (once)
//   agentouch add NAME --allow PROG[,PROG] (--env VAR | --stdin) [--hosts H[,H]] [--from-clipboard]
//                                                store a secret, after Touch ID (pasted hidden,
//                                                piped in, or taken from the clipboard); --hosts
//                                                pins where curl may send it
//   agentouch list                               names and settings, never values
//   agentouch password [--length N]              new password onto the clipboard, never printed
//   agentouch set-master [--from-clipboard]      store the Bitwarden master password, after Touch ID
//   agentouch login-new --site SITE --username NAME [--folder F] [--task WHY]
//                                                after Touch ID, save a new login with a fresh
//                                                password to Bitwarden; password onto the clipboard
//   agentouch login --site SITE [--username NAME]
//                                                after Touch ID, put an existing Bitwarden login's
//                                                password on the clipboard for 30 s
//   agentouch protect [--review | --all | --apply ID[,ID]]
//                                                after Touch ID, pick items to mark re-prompt in a
//                                                window (--review), or list them / mark by id
//   agentouch clipboard-clear                    clear a password agentouch put on the clipboard
//   agentouch rm NAME                            delete a secret, after Touch ID
//   agentouch run NAME[,NAME] -- PROG [ARGS...]  one Touch ID for the exact command shown
import AppKit
import CryptoKit
import Foundation
import LocalAuthentication

struct Fail: Error { let message: String; init(_ m: String) { message = m } }

struct Secret: Codable {
    var name: String
    var env: String?          // delivered as this env var; nil means on stdin
    var allow: [String]       // program names this secret may be used with
    var hosts: [String]? = nil // if set, the only hosts curl may send it to
    var ephemeralKey: Data
    var sealed: Data
    var added: Date
}

struct Store: Codable {
    var seKey: Data           // Secure Enclave key blob; useless off this Mac or without a fingerprint
    var sePublicKey: Data
    var secrets: [Secret]
}

// Common programs that could simply print, copy or forward a secret, so they can't be allowed.
// This only catches the obvious; the allow-list you approve at add time is the real boundary.
let refusedPrograms: Set<String> = [
    "sh", "bash", "zsh", "fish", "dash", "ksh", "csh", "tcsh", "env", "printenv", "echo", "printf",
    "cat", "tee", "xargs", "osascript", "pbcopy", "nc", "ncat", "socat", "script", "awk", "gawk",
    "sed", "tr", "rev", "base64", "xxd", "od", "hexdump", "strings", "less", "more", "head", "tail",
    "cut", "grep", "egrep", "fgrep", "rg", "jq", "yq", "sort", "uniq", "nl", "fold", "paste", "dd",
    "cp", "mv", "ssh", "scp", "nohup", "time", "sudo", "open", "swift", "expect", "npx", "bunx",
    "deno", "bun", "uv", "uvx", "tsx", "java", "mail", "say", "find", "tar", "rsync", "make", "vi",
    "vim", "nvim", "emacs", "tmux", "screen", "watch", "timeout", "nice", "caffeinate", "stdbuf", "nu",
    "xonsh", "elvish",
]
// Interpreters, including versioned names like python3.13 or perl5.34.
let refusedPrefixes = ["python", "perl", "ruby", "node", "php", "lua", "pwsh", "tclsh"]

// Program names are lower-case ASCII, so `Bash` can't slip past on a case-insensitive disk.
let programPattern = #"^[a-z0-9][a-z0-9._+-]*$"#

func isRefused(_ program: String) -> Bool {
    let name = program.lowercased()
    return refusedPrograms.contains(name) || refusedPrefixes.contains { name.hasPrefix($0) }
}

let dir = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".config/agentouch")
let storeURL = dir.appendingPathComponent("store.json")

func loadStore() throws -> Store {
    guard let data = try? Data(contentsOf: storeURL) else { throw Fail("not set up — run: agentouch init") }
    let decoder = JSONDecoder()
    decoder.dateDecodingStrategy = .iso8601
    return try decoder.decode(Store.self, from: data)
}

func save(_ store: Store) throws {
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    encoder.dateEncodingStrategy = .iso8601
    try encoder.encode(store).write(to: storeURL, options: .atomic)
}

// The name, delivery and allow-list are bound into the ciphertext, so editing them in
// store.json (e.g. to allow `cat`) makes the secret fail to decrypt.
func binding(_ s: Secret) -> Data {
    let hosts = s.hosts.map { "|hosts:" + $0.joined(separator: ",") } ?? ""
    return Data("agentouch v1|\(s.name)|\(s.env ?? "<stdin>")|\(s.allow.joined(separator: ","))\(hosts)".utf8)
}

func symmetricKey(_ shared: SharedSecret, _ ephemeral: Data, _ sePublic: Data) -> SymmetricKey {
    shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: ephemeral + sePublic,
                                   sharedInfo: Data("agentouch secret".utf8), outputByteCount: 32)
}

func seal(_ value: Data, into s: inout Secret, sePublic: Data) throws {
    let ephemeral = P256.KeyAgreement.PrivateKey()
    let shared = try ephemeral.sharedSecretFromKeyAgreement(
        with: P256.KeyAgreement.PublicKey(rawRepresentation: sePublic))
    s.ephemeralKey = ephemeral.publicKey.rawRepresentation
    let key = symmetricKey(shared, s.ephemeralKey, sePublic)
    s.sealed = try ChaChaPoly.seal(value, using: key, authenticating: binding(s)).combined
}

func open(_ s: Secret, with seKey: SecureEnclave.P256.KeyAgreement.PrivateKey, sePublic: Data) throws -> Data {
    let shared = try seKey.sharedSecretFromKeyAgreement(
        with: P256.KeyAgreement.PublicKey(rawRepresentation: s.ephemeralKey))
    return try decrypt(s, shared: shared, sePublic: sePublic)
}

func decrypt(_ s: Secret, shared: SharedSecret, sePublic: Data) throws -> Data {
    let key = symmetricKey(shared, s.ephemeralKey, sePublic)
    do {
        return try ChaChaPoly.open(ChaChaPoly.SealedBox(combined: s.sealed), using: key, authenticating: binding(s))
    } catch {
        throw Fail("'\(s.name)' failed to decrypt — its settings were changed outside agentouch; add it again")
    }
}

// Programs are looked up only in these directories, never via the caller's PATH or a
// relative path, so a look-alike script named `gh` can't stand in for the real one.
let programDirs = ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin"]

func resolve(_ program: String) -> String? {
    programDirs.map { "\($0)/\(program)" }.first { FileManager.default.isExecutableFile(atPath: $0) }
}

// Variables that could quietly redirect where an approved tool sends the secret. PATH is
// pinned too, so a script like bw can't pick up a planted `node`.
let scrubbedPrefixes = ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "SSL_", "CURL_", "GIT_", "GH_",
                        "NODE_", "DYLD_", "LD_", "XDG_CONFIG_HOME", "BW_", "BITWARDENCLI_"]

func scrubbedEnvironment() -> [String: String] {
    var environment = ProcessInfo.processInfo.environment.filter { key, _ in !scrubbedPrefixes.contains { key.uppercased().hasPrefix($0) } }
    environment["PATH"] = programDirs.joined(separator: ":")
    return environment
}

// MARK: Host pinning for curl

let hostPattern = #"^[a-z0-9-]+(\.[a-z0-9-]+)+$"#

// With pinned hosts, curl may only use options that can't send the request (or a copy of it)
// anywhere else or write files, and every URL must be https on a pinned host. curl's config
// files are skipped with -q.
let curlValueOptions: Set<String> = ["-H", "--header", "-d", "--data", "--data-raw", "--data-binary", "--json",
                                     "-X", "--request", "-m", "--max-time", "--connect-timeout", "-A", "--user-agent"]
let curlFlagOptions: Set<String> = ["-s", "-S", "-sS", "-Ss", "--silent", "--show-error", "-f", "--fail",
                                    "--fail-with-body", "-i", "--include", "--compressed"]

func checkCurl(_ args: ArraySlice<String>, hosts: Set<String>) throws {
    var rest = args
    while let arg = rest.popFirst() {
        if curlValueOptions.contains(arg) {
            guard rest.popFirst() != nil else { throw Fail("\(arg) needs a value") }
        } else if arg.hasPrefix("-") {
            guard curlFlagOptions.contains(arg) else { throw Fail("curl \(arg) isn't allowed with a host-pinned secret") }
        } else {
            guard let url = URL(string: arg), url.scheme == "https", url.user == nil, url.password == nil,
                  let host = url.host?.lowercased(), hosts.contains(host) else {
                throw Fail("\(arg): this secret may only go to https://\(hosts.sorted().joined(separator: ", "))")
            }
        }
    }
}

// MARK: Audit log

// One line per approval, decline and outcome, so the user can check what was done in their name.
func audit(_ line: String) {
    let entry = Data("\(Date().ISO8601Format()) [\(agentouchVersion)] \(line)\n".utf8)
    let url = dir.appendingPathComponent("log")
    if let handle = try? FileHandle(forWritingTo: url) {
        _ = try? handle.seekToEnd()
        try? handle.write(contentsOf: entry)
        try? handle.close()
    } else {
        try? entry.write(to: url)
    }
}

func quote(_ arg: String) -> String {
    let plain = "@%+=:,./_-"
    if !arg.isEmpty, arg.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || plain.contains($0)) }) { return arg }
    return "'" + arg.replacingOccurrences(of: "'", with: "'\\''") + "'"
}

// Redacts secrets from a byte stream: as-is, hex, URL-encoded, and base64 at any alignment.
// Best-effort: other encodings, partial prints and files the command writes are not covered.
// It holds back a tail one byte shorter than the longest pattern, so a secret split across
// two reads is still caught.
final class Redactor {
    let patterns: [(Data, Data)]
    let keep: Int
    var buffer = Data()

    init(_ secrets: [(name: String, value: Data)]) {
        patterns = secrets.flatMap { s -> [(Data, Data)] in
            let marker = Data("[redacted \(s.name)]".utf8)
            let hex = s.value.map { String(format: "%02x", $0) }.joined()
            var forms = [s.value, Data(hex.utf8), Data(hex.uppercased().utf8)]
            for format in ["%%%02X", "%%%02x"] {
                let url = s.value.map { b -> String in
                    let c = Character(UnicodeScalar(b))
                    return c.isASCII && (c.isLetter || c.isNumber || "-._~".contains(c)) ? String(c) : String(format: format, b)
                }.joined()
                if url.utf8.count != s.value.count { forms.append(Data(url.utf8)) }
            }
            // The base64 characters that encode whole 3-byte groups are the same wherever
            // the secret sits in the encoded stream, given its offset mod 3.
            for skip in 0..<3 {
                let rest = s.value.dropFirst(skip)
                forms.append(Data(Data(rest.prefix(rest.count / 3 * 3)).base64EncodedString().utf8))
            }
            return forms.map { ($0, marker) }
        }.filter { $0.0.count >= 6 }
        keep = max(0, (patterns.map { $0.0.count }.max() ?? 1) - 1)
    }

    func feed(_ data: Data) -> Data {
        buffer.append(data)
        scrub()
        let n = max(0, buffer.count - keep)
        let out = Data(buffer.prefix(n))
        buffer = Data(buffer.dropFirst(n))
        return out
    }

    func flush() -> Data {
        scrub()
        defer { buffer = Data() }
        return buffer
    }

    private func scrub() {
        for (secret, marker) in patterns {
            while let r = buffer.range(of: secret) { buffer.replaceSubrange(r, with: marker) }
        }
    }
}

// Asks for a fingerprint (no password fallback, no reuse of an earlier touch). The returned
// context is authenticated and can unlock the Secure Enclave key without a second prompt.
func approve(_ reason: String) async throws -> LAContext {
    let context = LAContext()
    context.localizedFallbackTitle = ""
    context.touchIDAuthenticationAllowableReuseDuration = 0
    do {
        try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason)
    } catch {
        audit("declined: \(reason)")
        throw Fail("not approved (\(error.localizedDescription))")
    }
    audit("approved: \(reason)")
    return context
}

func readSecret(name: String, fromClipboard: Bool) throws -> Data {
    var value: Data
    if fromClipboard {
        value = Data((NSPasteboard.general.string(forType: .string) ?? "").utf8)
        while let last = value.last, last == 0x0A || last == 0x0D { value.removeLast() }
    } else if isatty(0) == 1 {
        var buf = [CChar](repeating: 0, count: 16384)
        guard readpassphrase("Paste the secret for '\(name)' (hidden), then Enter: ", &buf, buf.count,
                             RPP_ECHO_OFF | RPP_REQUIRE_TTY) != nil else { throw Fail("could not read the secret") }
        value = Data(String(cString: buf).utf8)
        buf.withUnsafeMutableBufferPointer { $0.update(repeating: 0) }
    } else {
        value = FileHandle.standardInput.readDataToEndOfFile()
        while let last = value.last, last == 0x0A || last == 0x0D { value.removeLast() }
    }
    guard !value.isEmpty else { throw Fail("empty secret, nothing stored") }
    return value
}

func cmdInit() throws {
    guard (try? loadStore()) == nil else { throw Fail("already set up (\(storeURL.path))") }
    guard SecureEnclave.isAvailable else { throw Fail("this Mac has no Secure Enclave") }
    var error: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                       [.privateKeyUsage, .biometryAny], &error) else {
        throw Fail("could not create access control: \(String(describing: error))")
    }
    let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
    try save(Store(seKey: key.dataRepresentation, sePublicKey: key.publicKey.rawRepresentation, secrets: []))
    print("set up — secrets will be sealed to this Mac's Secure Enclave and need your fingerprint")
}

struct AddPlan {
    var name: String, allow: [String], env: String?, fromClipboard: Bool, hosts: [String]?
}

// Checks an add request before any prompt.
func planAdd(_ args: [String]) throws -> AddPlan {
    var rest = args[...]
    guard let name = rest.popFirst(), name.range(of: #"^[A-Za-z0-9._-]+$"#, options: .regularExpression) != nil else {
        throw Fail("usage: agentouch add NAME --allow PROG[,PROG] (--env VAR | --stdin) [--hosts H[,H]] [--from-clipboard]")
    }
    guard !name.hasPrefix("_") else { throw Fail("names starting with _ are reserved (the master password uses: agentouch set-master)") }
    var allow: [String] = [], env: String?, stdin = false, fromClipboard = false, hosts: [String]?
    while let flag = rest.popFirst() {
        switch flag {
        case "--allow": allow = (rest.popFirst() ?? "").split(separator: ",").map(String.init)
        case "--env": env = rest.popFirst()
        case "--stdin": stdin = true
        case "--hosts": hosts = (rest.popFirst() ?? "").lowercased().split(separator: ",").map(String.init)
        case "--from-clipboard": fromClipboard = true
        default: throw Fail("unknown option \(flag)")
        }
    }
    guard !allow.isEmpty else { throw Fail("say which programs may use it: --allow gh,git") }
    if let bad = allow.first(where: { isRefused($0) || $0.range(of: programPattern, options: .regularExpression) == nil }) {
        throw Fail("'\(bad)' can't be allowed: give lower-case program names, and not ones that could just print the secret")
    }
    guard (env == nil) != !stdin else { throw Fail("choose one delivery: --env VAR or --stdin") }
    if let env, env.range(of: #"^[A-Z_][A-Z0-9_]*$"#, options: .regularExpression) == nil {
        throw Fail("--env needs an UPPER_CASE variable name")
    }

    if let hosts {
        guard allow == ["curl"] else { throw Fail("--hosts works with --allow curl only") }
        guard !hosts.isEmpty, hosts.allSatisfy({ $0.range(of: hostPattern, options: .regularExpression) != nil }) else {
            throw Fail("--hosts needs host names like api.example.com")
        }
    }
    return AddPlan(name: name, allow: allow, env: env, fromClipboard: fromClipboard, hosts: hosts)
}

func cmdAdd(_ args: [String]) async throws {
    let plan = try planAdd(args)
    let (name, allow, env, fromClipboard, hosts) = (plan.name, plan.allow, plan.env, plan.fromClipboard, plan.hosts)
    var store = try loadStore()
    // Every add needs a fingerprint, so a prompt-injected agent can't quietly swap in its
    // own value under a name the user trusts. The clipboard is read only after approval.
    let replacing = store.secrets.contains { $0.name == name } ? ", replacing the existing one" : ""
    let source = fromClipboard ? "the text on your clipboard" : "a secret"
    let destination = hosts.map { " to \($0.joined(separator: ", "))" } ?? ""
    _ = try await approve("store \(source) as “\(name)” for \(allow.joined(separator: ", "))\(destination)\(replacing)")

    var secret = Secret(name: name, env: env, allow: allow, hosts: hosts, ephemeralKey: Data(), sealed: Data(), added: Date())
    let value = try readSecret(name: name, fromClipboard: fromClipboard)
    if fromClipboard || isatty(0) == 1 { NSPasteboard.general.clearContents() }
    try seal(value, into: &secret, sePublic: store.sePublicKey)
    store.secrets.removeAll { $0.name == name }
    store.secrets.append(secret)
    try save(store)
    print("stored '\(name)' — usable with: \(allow.joined(separator: ", "))\(destination)")
}

func generatePassword(length: Int) -> String {
    let classes = ["abcdefghijkmnopqrstuvwxyz", "ABCDEFGHJKLMNPQRSTUVWXYZ", "23456789", "!@#$%^&*-_=+?"].map(Array.init)
    let all = classes.flatMap { $0 }
    var rng = SystemRandomNumberGenerator()
    var password: [Character]
    repeat {
        password = (0..<length).map { _ in all[Int(UInt32.random(in: 0..<UInt32(all.count), using: &rng))] }
    } while !classes.allSatisfy { set in password.contains { set.contains($0) } }
    return String(password)
}

// Puts a password on the clipboard, marked so clipboard managers skip it, and clears it
// after `seconds` unless something else was copied since.
func copyToClipboard(_ password: String, seconds: Int = 90) throws {
    let pasteboard = NSPasteboard.general
    pasteboard.clearContents()
    pasteboard.setString(password, forType: .string)
    pasteboard.setString("", forType: NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType"))
    let clearer = Process()
    clearer.executableURL = Bundle.main.executableURL
    clearer.arguments = ["_clear-clipboard", String(pasteboard.changeCount), String(seconds)]
    clearer.standardOutput = FileHandle.nullDevice
    clearer.standardError = FileHandle.nullDevice
    try clearer.run()
}

func cmdPassword(_ args: [String]) throws {
    let length = args.count == 2 && args[0] == "--length" ? Int(args[1]) ?? 0 : (args.isEmpty ? 24 : 0)
    guard (12...128).contains(length) else { throw Fail("usage: agentouch password [--length 12-128]") }
    try copyToClipboard(generatePassword(length: length))
    print("a \(length)-character password is on the clipboard (cleared in 90 s)")
}

// MARK: Saving new logins to Bitwarden

// The Bitwarden master password is stored under this reserved name with an empty allow-list,
// so `run` can never hand it to a program; only `login-new` and `login` use it.
let masterName = "_bitwarden-master"

// A short-lived `bw serve` on a Unix socket in a private (0700) directory. One Node start-up
// instead of one per step (each `bw` command idles ~2 s before it exits), so a save takes ~3 s
// instead of ~13 s. No network port is opened, so neither web pages nor other users can reach
// it, and it is locked and stopped before agentouch returns. On Ctrl-C a signal handler stops
// it; if agentouch is killed outright, a small watcher process (`agentouch _reap`) does.
nonisolated(unsafe) var serverPid: pid_t = 0  // for the signal handler

final class Bitwarden {
    let process = Process()
    let reaper = Process()
    let directory: URL
    let socketPath: String
    let secrets: [(name: String, value: Data)]

    init(redacting secrets: [(name: String, value: Data)]) throws {
        guard let path = resolve("bw") else { throw Fail("bw (Bitwarden CLI) not found") }
        var template = Array(FileManager.default.temporaryDirectory.appendingPathComponent("agentouch.XXXXXX").path.utf8CString)
        guard let made = mkdtemp(&template) else { throw Fail("couldn't create a private directory for bw serve") }
        directory = URL(fileURLWithPath: String(cString: made))
        chmod(directory.path, 0o700)
        socketPath = directory.appendingPathComponent("bw.sock").path
        guard socketPath.utf8.count < 104 else {
            try? FileManager.default.removeItem(at: directory)
            throw Fail("temporary directory path too long for a socket")
        }
        self.secrets = secrets
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = ["serve", "--hostname", "unix://\(socketPath)"]
        process.environment = scrubbedEnvironment().merging(["BW_NOINTERACTION": "true"]) { _, b in b }
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        do { try process.run() } catch {
            try? FileManager.default.removeItem(at: directory)
            throw error
        }
        serverPid = process.processIdentifier
        reaper.executableURL = Bundle.main.executableURL
        reaper.arguments = ["_reap", String(process.processIdentifier), String(getpid()), directory.path]
        reaper.standardOutput = FileHandle.nullDevice
        reaper.standardError = FileHandle.nullDevice
        try? reaper.run()
        for sig in [SIGINT, SIGTERM, SIGHUP] {
            signal(sig) { sig in
                if serverPid > 0 { kill(serverPid, SIGTERM) }
                _exit(128 + sig)
            }
        }
    }

    // Unlocks the vault with the master password, runs body, then locks and stops the server.
    static func unlocked<T>(_ master: Data, redacting secrets: [(name: String, value: Data)],
                            _ body: (Bitwarden) async throws -> T) async throws -> T {
        let bw = try Bitwarden(redacting: secrets)
        do {
            try await bw.waitUntilReady()
            _ = try bw.call("POST", "/unlock", ["password": String(decoding: master, as: UTF8.self)])
            let result = try await body(bw)
            bw.stop()
            return result
        } catch {
            bw.stop()
            throw error
        }
    }

    // Waits for a reply that is really bw's status, from our still-running server.
    func waitUntilReady() async throws {
        for _ in 0..<300 {
            guard process.isRunning else { throw Fail("bw serve exited before it was ready") }
            if let (status, data) = try? request("GET", "/status", nil) {
                if status == 403 {
                    throw Fail("bw serve refused the request (HTTP 403): its Host allow-list may have changed in this Bitwarden CLI version (see README)")
                }
                let reply = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
                let template = ((reply?["data"] as? [String: Any])?["template"] as? [String: Any])
                guard reply?["success"] as? Bool == true, template?["status"] is String, process.isRunning else {
                    throw Fail("something other than bw answered on its socket; nothing was sent")
                }
                return
            }
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        throw Fail("bw serve didn't start within 15 s")
    }

    // Calls the API and returns its "data" object. Errors are shown with the secrets redacted.
    func call(_ method: String, _ path: String, _ body: [String: Any]? = nil) throws -> [String: Any] {
        let (status, data) = try request(method, path, try body.map { try JSONSerialization.data(withJSONObject: $0) })
        let reply = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] ?? [:]
        guard reply["success"] as? Bool == true else {
            let r = Redactor(secrets)
            let text = Data(((reply["message"] as? String) ?? String(decoding: data, as: UTF8.self)).utf8)
            let message = String(decoding: r.feed(text) + r.flush(), as: UTF8.self)
            throw Fail("Bitwarden \(path) failed (HTTP \(status)): \(message.trimmingCharacters(in: .whitespacesAndNewlines))")
        }
        return reply["data"] as? [String: Any] ?? [:]
    }

    func list(_ object: String) throws -> [[String: Any]] {
        try call("GET", "/list/object/\(object)")["data"] as? [[String: Any]] ?? []
    }

    // One HTTP/1.1 request over the socket. bw serve checks the Host header even on a socket and
    // only accepts localhost:<its --port>, 8087 by default (bitwarden/clients#22867).
    func request(_ method: String, _ path: String, _ body: Data?) throws -> (Int, Data) {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw Fail("no socket") }
        defer { close(fd) }
        var timeout = timeval(tv_sec: 60, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            raw.copyBytes(from: socketPath.utf8.prefix(raw.count - 1))
        }
        let connected = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) == 0 }
        }
        guard connected else { throw Fail("couldn't connect to bw serve") }

        var head = "\(method) \(path) HTTP/1.1\r\nHost: localhost:8087\r\nConnection: close\r\n"
        if let body { head += "Content-Type: application/json\r\nContent-Length: \(body.count)\r\n" }
        let message = Data((head + "\r\n").utf8) + (body ?? Data())
        try message.withUnsafeBytes { raw in
            var sent = 0
            while sent < raw.count {
                let n = write(fd, raw.baseAddress! + sent, raw.count - sent)
                guard n > 0 else { throw Fail("couldn't send to bw serve") }
                sent += n
            }
        }

        var response = Data()
        var buffer = [UInt8](repeating: 0, count: 65536)
        while true {
            let n = read(fd, &buffer, buffer.count)
            if n == 0 { break }
            if n < 0 {
                if errno == EINTR { continue }
                throw Fail(errno == EAGAIN ? "bw serve didn't answer within 60 s" : "couldn't read from bw serve")
            }
            response.append(buffer, count: n)
            guard response.count <= 64 << 20 else { throw Fail("bw serve's reply was too large") }
        }
        guard let split = response.range(of: Data("\r\n\r\n".utf8)),
              let statusLine = String(data: response[..<split.lowerBound], encoding: .utf8)?.split(separator: "\r\n").first,
              let status = Int(statusLine.split(separator: " ").dropFirst().first ?? "") else {
            throw Fail("bw serve sent a malformed reply")
        }
        let headers = String(decoding: response[..<split.lowerBound], as: UTF8.self).lowercased()
        var payload = Data(response[split.upperBound...])
        if headers.contains("transfer-encoding: chunked") { payload = dechunk(payload) }
        return (status, payload)
    }

    func stop() {
        _ = try? call("POST", "/lock")
        process.terminate()
        for _ in 0..<30 where process.isRunning { usleep(100_000) }
        if process.isRunning { kill(process.processIdentifier, SIGKILL) }
        process.waitUntilExit()
        serverPid = 0
        if reaper.isRunning { reaper.terminate() }
        try? FileManager.default.removeItem(at: directory)
    }
}

func dechunk(_ data: Data) -> Data {
    var out = Data(), rest = data[...]
    while let lineEnd = rest.range(of: Data("\r\n".utf8)),
          let size = Int(String(decoding: rest[..<lineEnd.lowerBound], as: UTF8.self).split(separator: ";").first ?? "", radix: 16),
          size > 0 {
        let start = lineEnd.upperBound
        guard rest.distance(from: start, to: rest.endIndex) >= size else { break }
        let end = rest.index(start, offsetBy: size)
        out.append(contentsOf: rest[start..<end])
        rest = rest[rest.index(end, offsetBy: min(2, rest.distance(from: end, to: rest.endIndex)))...]
    }
    return out
}

// `agentouch _reap SERVER PARENT DIR`: stops bw serve if agentouch dies without stopping it, and
// after 120 s in any case, then removes its socket directory.
func reap(server: pid_t, parent: pid_t, directory: String) {
    let deadline = Date().addingTimeInterval(120)
    while kill(server, 0) == 0, kill(parent, 0) == 0, Date() < deadline { usleep(200_000) }
    if kill(server, 0) == 0 {
        kill(server, SIGTERM)
        for _ in 0..<20 where kill(server, 0) == 0 { usleep(100_000) }
        if kill(server, 0) == 0 { kill(server, SIGKILL) }
    }
    if isSocketDirectory(directory) { try? FileManager.default.removeItem(atPath: directory) }
}

// Only a directory that bw serve's mkdtemp could have made: agentouch.XXXXXX directly in TMPDIR.
func isSocketDirectory(_ path: String) -> Bool {
    let url = URL(fileURLWithPath: path).standardizedFileURL
    return url.deletingLastPathComponent().path == FileManager.default.temporaryDirectory.standardizedFileURL.path
        && url.lastPathComponent.range(of: #"^agentouch\.[A-Za-z0-9]{6}$"#, options: .regularExpression) != nil
}

// The vault's logins for exactly this site (or its www. form); subdomains, look-alikes and
// deleted items don't count. For use, a URI whose Bitwarden match setting is "Never" (5) doesn't
// count either: that's the user saying not to fill it there.
func logins(in items: [[String: Any]], site: String, forUse: Bool = false) -> [[String: Any]] {
    func bare(_ host: String) -> String { host.hasPrefix("www.") ? String(host.dropFirst(4)) : host }
    return items.compactMap { item in
        guard let login = item["login"] as? [String: Any], item["deletedDate"] == nil || item["deletedDate"] is NSNull else { return nil }
        let uris = (login["uris"] as? [[String: Any]] ?? [])
            .filter { !forUse || ($0["match"] as? Int) != 5 }
            .compactMap { $0["uri"] as? String }
        let matches = uris.contains { uri in
            let host = URL(string: uri)?.host ?? URL(string: "https://\(uri)")?.host
            return host.map { bare($0.lowercased()) == bare(site) } ?? false
        }
        return matches ? item : nil
    }
}

// Whether the vault already has a login for this site and username.
func hasLogin(in items: [[String: Any]], site: String, username: String) -> Bool {
    logins(in: items, site: site).contains {
        (($0["login"] as? [String: Any])?["username"] as? String)?.lowercased() == username.lowercased()
    }
}

// The one login to use for a site: never an item marked "master password re-prompt" (the user
// keeps those for themselves), and if there are several, only the one with the given username.
func pickLogin(in items: [[String: Any]], site: String, username: String?) throws -> (username: String, password: String) {
    var found = logins(in: items, site: site, forUse: true)
    guard !found.isEmpty else { throw Fail("no Bitwarden login for \(site)") }
    found.removeAll { ($0["reprompt"] as? Int ?? 0) != 0 }
    guard !found.isEmpty else { throw Fail("the Bitwarden login for \(site) asks for the master password again; the user logs in themselves") }
    func name(_ item: [String: Any]) -> String { (item["login"] as? [String: Any])?["username"] as? String ?? "" }
    if let username { found.removeAll { name($0).lowercased() != username.lowercased() } }
    guard !found.isEmpty else { throw Fail("no Bitwarden login for \(site) as \(username ?? "")") }
    func password(_ item: [String: Any]) -> String { (item["login"] as? [String: Any])?["password"] as? String ?? "" }
    if Set(found.map { name($0).lowercased() }).count > 1 {
        let names = found.map(name).prefix(5).joined(separator: ", ")
        throw Fail("several Bitwarden logins for \(site): \(names)\(found.count > 5 ? ", …" : ""); run again with --username")
    }
    // The same account saved twice is fine as long as both copies agree.
    guard Set(found.map(password)).count == 1 else {
        throw Fail("different passwords are saved for \(site) as \(name(found[0])); fix them in Bitwarden")
    }
    guard !password(found[0]).isEmpty else { throw Fail("the Bitwarden login for \(site) has no password") }
    return (name(found[0]), password(found[0]))
}

func cmdSetMaster(_ args: [String]) async throws {
    let fromClipboard = args == ["--from-clipboard"]
    guard args.isEmpty || fromClipboard else { throw Fail("usage: agentouch set-master [--from-clipboard]") }
    var store = try loadStore()
    let source = fromClipboard ? "the text on your clipboard" : "your Bitwarden master password"
    _ = try await approve("store \(source) as the Bitwarden master password, used only by login-new and login")
    let value = try readSecret(name: "your Bitwarden master password", fromClipboard: fromClipboard)
    if fromClipboard || isatty(0) == 1 { NSPasteboard.general.clearContents() }

    // Check it by unlocking once, so a typo is caught now rather than at the first sign-up.
    try await Bitwarden.unlocked(value, redacting: [(name: "master password", value: value)]) { _ in }

    var secret = Secret(name: masterName, env: "BW_MASTER", allow: [], ephemeralKey: Data(), sealed: Data(), added: Date())
    try seal(value, into: &secret, sePublic: store.sePublicKey)
    store.secrets.removeAll { $0.name == masterName }
    store.secrets.append(secret)
    try save(store)
    print("stored — agentouch login-new can now save logins to Bitwarden")
}

// Creates a Bitwarden login with a new password for a site, and puts the password on the
// clipboard for the sign-up form. It never edits or deletes vault items, and reads them only
// to avoid a duplicate; nothing from the vault is printed.
// Usernames for new logins must be an address at one of these email-alias services, or a
// plain username, so the user's real address is never used. Edit to suit, then rebuild.
let aliasDomains = ["icloud.com", "privaterelay.appleid.com", "simplelogin.com", "aleeas.com", "slmail.me",
                    "duck.com", "passmail.net", "passinbox.com", "addy.io", "anonaddy.me", "mozmail.com"]

struct LoginPlan { var site: String, username: String, folder: String, task: String }

// Checks a login-new request before any prompt.
func planLoginNew(_ args: [String]) throws -> LoginPlan {
    var options: [String: String] = ["--folder": "Agent sign-ups"]
    var rest = args[...]
    while let flag = rest.popFirst() {
        guard ["--site", "--username", "--folder", "--task"].contains(flag), let value = rest.popFirst() else {
            throw Fail("usage: agentouch login-new --site example.com --username NAME [--folder F] [--task WHY]")
        }
        options[flag] = value
    }
    guard let site = options["--site"]?.lowercased(), let username = options["--username"],
          let folder = options["--folder"] else {
        throw Fail("usage: agentouch login-new --site example.com --username NAME [--folder F] [--task WHY]")
    }
    let task = options["--task"] ?? ""

    // Strict, plain-ASCII inputs keep the prompt honest (no look-alike domains) and stop the
    // user's real address from being used.
    guard site.count <= 253, site.range(of: hostPattern, options: .regularExpression) != nil,
          site.range(of: #"^[0-9.]+$"#, options: .regularExpression) == nil else {
        throw Fail("--site must be a domain like example.com")
    }
    let domains = aliasDomains.map { NSRegularExpression.escapedPattern(for: $0) }.joined(separator: "|")
    guard username.range(of: "^[A-Za-z0-9._+-]+@(\(domains))$|^[A-Za-z0-9._-]{3,64}$", options: .regularExpression) != nil else {
        throw Fail("--username must be an email alias (\(aliasDomains.joined(separator: ", "))) or a plain username")
    }
    for (label, text) in [("--folder", folder), ("--task", task)] where text.count > 100 || !text.allSatisfy({ $0.isASCII && !$0.isNewline }) {
        throw Fail("\(label) must be plain ASCII, one line, at most 100 characters")
    }
    return LoginPlan(site: site, username: username, folder: folder, task: task)
}

func cmdLoginNew(_ args: [String]) async throws {
    let plan = try planLoginNew(args)
    let (site, username, folder, task) = (plan.site, plan.username, plan.folder, plan.task)
    let store = try loadStore()
    guard let masterSecret = store.secrets.first(where: { $0.name == masterName }) else {
        throw Fail("no Bitwarden master password stored — the user runs: agentouch set-master")
    }
    let context = try await approve("create a Bitwarden login for \(site) as \(username) in “\(folder)” and put its new password on the clipboard")
    let seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: store.seKey, authenticationContext: context)
    let master = try open(masterSecret, with: seKey, sePublic: store.sePublicKey)
    context.invalidate()
    let password = generatePassword(length: 24)
    let secrets = [(name: "master password", value: master), (name: "password", value: Data(password.utf8))]

    try await Bitwarden.unlocked(master, redacting: secrets) { bw in
        _ = try bw.call("POST", "/sync")
        // Right after a sync bw can briefly list nothing at all (bitwarden/clients#23283), which
        // would let a duplicate through, so an empty vault is checked again before it's believed
        // (costing ~3 s per sign-up while the vault really is empty).
        var items = try bw.list("items")
        for _ in 0..<4 where items.isEmpty {
            try await Task.sleep(nanoseconds: 750_000_000)
            items = try bw.list("items")
        }
        if hasLogin(in: items, site: site, username: username) {
            throw Fail("Bitwarden already has a login for \(site) as \(username); nothing was created")
        }
        var folderId = try bw.list("folders").first { $0["name"] as? String == folder }?["id"] as? String
        if folderId == nil {
            folderId = try bw.call("POST", "/object/folder", ["name": folder])["id"] as? String
        }
        let date = Date().formatted(date: .abbreviated, time: .omitted)
        let item: [String: Any] = [
            "type": 1, "name": site, "folderId": folderId ?? NSNull(), "favorite": false, "reprompt": 0,
            "notes": "Created by an agent via agentouch on \(date)\(task.isEmpty ? "" : " for: \(task)").",
            "login": ["username": username, "password": password, "totp": NSNull(),
                      "uris": [["match": NSNull(), "uri": "https://\(site)"]]],
        ]
        guard try bw.call("POST", "/object/item", item)["id"] != nil else {
            throw Fail("Bitwarden didn't confirm the new item — check the \(folder) folder")
        }
    }
    try copyToClipboard(password)
    audit("saved login: \(site) as \(username) in \(folder)")
    print("saved “\(site)” (\(username)) to Bitwarden in “\(folder)”; its password is on the clipboard for 90 s")
}

struct LoginUsePlan { var site: String, username: String? }

// Checks a login request before any prompt.
func planLogin(_ args: [String]) throws -> LoginUsePlan {
    var options: [String: String] = [:]
    var rest = args[...]
    while let flag = rest.popFirst() {
        guard ["--site", "--username"].contains(flag), let value = rest.popFirst() else {
            throw Fail("usage: agentouch login --site example.com [--username NAME]")
        }
        options[flag] = value
    }
    guard let site = options["--site"]?.lowercased() else { throw Fail("usage: agentouch login --site example.com [--username NAME]") }
    guard site.count <= 253, site.range(of: hostPattern, options: .regularExpression) != nil,
          site.range(of: #"^[0-9.]+$"#, options: .regularExpression) == nil else {
        throw Fail("--site must be a domain like example.com")
    }
    if let username = options["--username"],
       username.range(of: #"^[A-Za-z0-9._+@-]{1,100}$"#, options: .regularExpression) == nil {
        throw Fail("--username must be plain ASCII without spaces")
    }
    return LoginUsePlan(site: site, username: options["--username"])
}

// Puts the password of an existing Bitwarden login on the clipboard for 30 s and prints its
// username, for logging in to that one site. One touch per use; nothing else leaves the vault.
func cmdLogin(_ args: [String]) async throws {
    let plan = try planLogin(args)
    let store = try loadStore()
    guard let masterSecret = store.secrets.first(where: { $0.name == masterName }) else {
        throw Fail("no Bitwarden master password stored — the user runs: agentouch set-master")
    }
    let who = plan.username.map { " as \($0)" } ?? ""
    let context = try await approve("put your Bitwarden password for \(plan.site)\(who) on the clipboard for 30 s, to log in there")
    let seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: store.seKey, authenticationContext: context)
    let master = try open(masterSecret, with: seKey, sePublic: store.sePublicKey)
    context.invalidate()

    let chosen = try await Bitwarden.unlocked(master, redacting: [(name: "master password", value: master)]) { bw in
        _ = try bw.call("POST", "/sync")
        var items = try bw.list("items")
        for _ in 0..<4 where items.isEmpty {  // bitwarden/clients#23283, as in login-new
            try await Task.sleep(nanoseconds: 750_000_000)
            items = try bw.list("items")
        }
        return try pickLogin(in: items, site: plan.site, username: plan.username)
    }
    try copyToClipboard(chosen.password, seconds: 30)
    audit("password to clipboard: \(plan.site) as \(chosen.username)")
    print("username: \(chosen.username)\nits password is on the clipboard for 30 s (agentouch clipboard-clear clears it now)")
}

// MARK: Marking critical logins "master password re-prompt"

// criticalDomains and criticalWords live in critical.swift.

func host(of uri: String) -> String? {
    (URL(string: uri)?.host ?? URL(string: "https://\(uri)")?.host)?.lowercased()
}

// Personal logins that look critical and aren't marked re-prompt yet.
func criticalCandidates(in items: [[String: Any]]) -> [[String: Any]] {
    items.filter { item in
        guard let login = item["login"] as? [String: Any], (item["reprompt"] as? Int ?? 0) == 0,
              item["deletedDate"] == nil || item["deletedDate"] is NSNull else { return false }
        let hosts = (login["uris"] as? [[String: Any]] ?? []).compactMap { ($0["uri"] as? String).flatMap(host) }
        let name = (item["name"] as? String ?? "").lowercased()
        return hosts.contains { h in criticalDomains.contains { h == $0 || h.hasSuffix("." + $0) } }
            || (hosts + [name]).contains { text in criticalWords.contains { text.contains($0) } }
    }
}

// Every login and secure note not yet marked re-prompt, for `protect --all`.
func unprotectedItems(in items: [[String: Any]]) -> [[String: Any]] {
    items.filter {
        ($0["reprompt"] as? Int ?? 0) == 0 && ($0["deletedDate"] == nil || $0["deletedDate"] is NSNull)
            && ($0["login"] != nil || $0["secureNote"] != nil)
    }
}

// Why an item can't be marked automatically, if it can't: a passkey or attachment (an edit
// through bw could lose it, and neither can be recovered), a shared item (its permissions belong
// to the organisation), or an archived or deleted one.
func protectBlocker(_ item: [String: Any]) -> String? {
    if let passkeys = (item["login"] as? [String: Any])?["fido2Credentials"] as? [Any], !passkeys.isEmpty {
        return "has a passkey"
    }
    if let attachments = item["attachments"] as? [Any], !attachments.isEmpty { return "has attachments" }
    for key in ["archivedDate", "deletedDate"] where !(item[key] == nil || item[key] is NSNull) {
        return key == "archivedDate" ? "is archived" : "is deleted"
    }
    if let org = item["organizationId"] as? String, !org.isEmpty { return "is shared through an organisation" }
    return nil
}

// `protect` lists the logins that look critical (names and sites, never passwords);
// `protect --apply ID[,ID]` marks them "master password re-prompt", after which `login` never
// hands them out. It only ever turns re-prompt on, and checks nothing else changed.
func cmdProtect(_ args: [String]) async throws {
    let apply: [String]?
    var everything = false
    switch args.count {
    case 0: apply = nil
    case 1 where args[0] == "--all": apply = nil; everything = true
    case 1 where args[0] == "--review": apply = nil
    case 2 where args[0] == "--apply":
        apply = args[1].lowercased().split(separator: ",").map(String.init)
        guard let ids = apply, !ids.isEmpty, ids.allSatisfy({ $0.range(of: #"^[0-9a-f-]{8,36}$"#, options: .regularExpression) != nil }) else {
            throw Fail("--apply needs item ids from `agentouch protect`, comma-separated")
        }
    default: throw Fail("usage: agentouch protect [--review | --all | --apply ID[,ID...]]")
    }
    let store = try loadStore()
    guard let masterSecret = store.secrets.first(where: { $0.name == masterName }) else {
        throw Fail("no Bitwarden master password stored — the user runs: agentouch set-master")
    }
    let review = args == ["--review"]
    let reason = review
        ? "review your Bitwarden logins and notes in a window on this Mac, and mark the ones you tick as re-prompt"
        : everything
        ? "list the names and sites of ALL your Bitwarden logins and notes (no usernames or passwords), to pick which to protect"
        : apply.map { "mark \($0.count) Bitwarden login\($0.count == 1 ? "" : "s") as “master password re-prompt” (only adds protection)" }
        ?? "list the names and sites of your Bitwarden logins that look critical (email, banks, government…), to protect them"
    let context = try await approve(reason)
    let seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: store.seKey, authenticationContext: context)
    let master = try open(masterSecret, with: seKey, sePublic: store.sePublicKey)
    context.invalidate()
    if review { return try await protectReview(master) }

    try await Bitwarden.unlocked(master, redacting: [(name: "master password", value: master)]) { bw in
        let items = try await freshItems(bw)
        func label(_ item: [String: Any]) -> String {
            let id = (item["id"] as? String ?? "").prefix(8)
            let hosts = Set(((item["login"] as? [String: Any])?["uris"] as? [[String: Any]] ?? []).compactMap { ($0["uri"] as? String).flatMap(host) })
            return "\(id)  \(item["name"] as? String ?? "?")  (\(hosts.sorted().joined(separator: ", ")))"
        }
        guard let apply else {
            let found = everything ? unprotectedItems(in: items) : criticalCandidates(in: items)
            if found.isEmpty { print("no unprotected logins look critical") }
            for item in found { print(label(item) + (protectBlocker(item).map { "  — \($0): mark it yourself in Bitwarden" } ?? "")) }
            let already = items.filter { ($0["reprompt"] as? Int ?? 0) != 0 }.count
            print("\(found.count) to consider; \(already) already re-prompt. Mark with: agentouch protect --apply ID,ID")
            return
        }
        for prefix in apply {
            let matches = items.filter { ($0["id"] as? String ?? "").lowercased().hasPrefix(prefix) }
            guard matches.count == 1, let id = matches[0]["id"] as? String else {
                print("\(prefix): \(matches.isEmpty ? "no such item" : "matches several items; give more of the id")")
                continue
            }
            let name = label(matches[0])
            switch markReprompt(id, bw) {
            case .marked(let note): print("\(name): marked re-prompt\(note)")
            case .already: print("\(name): already re-prompt")
            case .skipped(let why): print("\(name): skipped, it \(why); mark it yourself in Bitwarden")
            case .failed(let why): print("\(name): failed, \(why)")
            }
        }
    }
}

// Bitwarden's items after a sync. Right after one, bw can briefly list nothing at all
// (bitwarden/clients#23283), so an empty list is checked again before it's believed.
func freshItems(_ bw: Bitwarden) async throws -> [[String: Any]] {
    _ = try bw.call("POST", "/sync")
    var items = try bw.list("items")
    for _ in 0..<4 where items.isEmpty {
        try await Task.sleep(nanoseconds: 750_000_000)
        items = try bw.list("items")
    }
    return items
}

enum MarkOutcome { case marked(String), already, skipped(String), failed(String) }

// Turns re-prompt on for one item, sending it back complete and re-reading it to check nothing
// else changed. One item's failure mustn't stop the rest, so errors are returned, not thrown.
func markReprompt(_ id: String, _ bw: Bitwarden) -> MarkOutcome {
    do {
        let before = try bw.call("GET", "/object/item/\(id)")
        if (before["reprompt"] as? Int ?? 0) != 0 { return .already }
        if let why = protectBlocker(before) { return .skipped(why) }
        var edited = before
        edited["reprompt"] = 1
        _ = try bw.call("PUT", "/object/item/\(id)", edited)
        let after = try bw.call("GET", "/object/item/\(id)")
        guard (after["reprompt"] as? Int ?? 0) == 1 else { return .failed("Bitwarden didn't keep the change") }
        let note = editNote(before: before, after: after)
        audit("marked re-prompt: \(id)\(note)")
        return .marked(note)
    } catch let f as Fail {
        audit("failed to mark re-prompt: \(id): \(f.message)")
        return .failed(f.message)
    } catch {
        return .failed("\(error)")
    }
}

// What else changed when only re-prompt was turned on: nothing, normally. The item key appearing
// (Bitwarden upgrades keyless items on edit) and password history trimmed to its usual 5 are
// expected; anything else is worth a look.
func editNote(before: [String: Any], after: [String: Any]) -> String {
    var a = after, b = before
    for key in ["reprompt", "revisionDate", "key"] { a[key] = nil; b[key] = nil }
    if NSDictionary(dictionary: a).isEqual(to: b) { return "" }
    let historyBefore = b["passwordHistory"] as? [Any] ?? [], historyAfter = a["passwordHistory"] as? [Any] ?? []
    a["passwordHistory"] = nil; b["passwordHistory"] = nil
    if NSDictionary(dictionary: a).isEqual(to: b), historyAfter.count == 5, historyBefore.count > 5 {
        return "; password history trimmed to 5 (normal)"
    }
    return "; WARNING: other fields changed, check this item in Bitwarden"
}

// Clears the clipboard if it holds a concealed item: agentouch's, or a password manager's.
func cmdClipboardClear() {
    let pasteboard = NSPasteboard.general
    if pasteboard.types?.contains(NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")) == true {
        pasteboard.clearContents()
        print("cleared a concealed item from the clipboard")
    } else {
        print("no concealed item on the clipboard")
    }
}

func cmdList() throws {
    let store = try loadStore()
    if store.secrets.isEmpty { print("no secrets yet — add one with: agentouch add NAME --allow PROG --env VAR") }
    for s in store.secrets.sorted(by: { $0.name < $1.name }) {
        let delivery = s.env.map { "env \($0)" } ?? "stdin"
        let hosts = s.hosts.map { " → \($0.joined(separator: ","))" } ?? ""
        print("\(s.name)\t\(delivery)\tallow: \(s.allow.joined(separator: ","))\(hosts)\tadded \(s.added.formatted(date: .abbreviated, time: .omitted))")
    }
}

// Needs Touch ID too, so an injected agent can't quietly delete what the user stored.
func cmdRemove(_ args: [String]) async throws {
    guard args.count == 1 else { throw Fail("usage: agentouch rm NAME") }
    var store = try loadStore()
    guard store.secrets.contains(where: { $0.name == args[0] }) else { throw Fail("no secret named '\(args[0])'") }
    let what = args[0] == masterName ? "the stored Bitwarden master password" : "“\(args[0])”"
    _ = try await approve("delete \(what) from agentouch")
    store.secrets.removeAll { $0.name == args[0] }
    try save(store)
    print("removed '\(args[0])'")
}

struct RunPlan { var secrets: [Secret], path: String, argv: [String], shown: String, prompt: String }

// Checks a run request and builds the exact prompt, before any Touch ID.
func planRun(_ args: [String], store: Store) throws -> RunPlan {
    guard let sep = args.firstIndex(of: "--"), sep == 1, args.count > 2 else {
        throw Fail("usage: agentouch run NAME[,NAME] -- PROG [ARGS...]")
    }
    let names = args[0].split(separator: ",").map(String.init)
    guard Set(names).count == names.count else { throw Fail("a secret is named twice") }
    var argv = Array(args[2...])

    let secrets = try names.map { n in
        guard let s = store.secrets.first(where: { $0.name == n }) else { throw Fail("no secret named '\(n)' — see: agentouch list") }
        return s
    }
    let program = argv[0]
    guard !program.contains("/") else { throw Fail("give the program by name (e.g. gh), not a path") }
    guard program.range(of: programPattern, options: .regularExpression) != nil else {
        throw Fail("give the program's lower-case name (e.g. gh)")
    }
    for s in secrets where !s.allow.contains(program) {
        if s.allow.isEmpty { throw Fail("'\(s.name)' can't be used with run") }
        throw Fail("'\(s.name)' may only be used with: \(s.allow.joined(separator: ", "))")
    }
    guard secrets.filter({ $0.env == nil }).count <= 1 else { throw Fail("only one secret can go on stdin") }
    guard let path = resolve(program) else { throw Fail("\(program): not found in \(programDirs.joined(separator: ", "))") }
    let target = URL(fileURLWithPath: path).resolvingSymlinksInPath().lastPathComponent
    guard !isRefused(target) else { throw Fail("\(path) is really \(target), which can't be used") }

    // The prompt must show exactly what runs: plain ASCII (no look-alike or invisible
    // characters) and short enough that nothing gets cut off.
    if argv.contains(where: { $0.unicodeScalars.contains { !$0.isASCII || $0.properties.generalCategory == .control } }) {
        throw Fail("the command contains non-ASCII or control characters")
    }
    let pinned = secrets.compactMap(\.hosts).map(Set.init)
    if let first = pinned.first {
        let hosts = pinned.dropFirst().reduce(first) { $0.intersection($1) }
        try checkCurl(argv.dropFirst(), hosts: hosts)
        argv.insert("-q", at: 1)
    }
    let shown = ([path] + argv.dropFirst()).map(quote).joined(separator: " ")
    guard shown.count <= 200 else { throw Fail("the command is too long to show in the approval prompt") }

    // Where the secret goes comes first, so a swapped destination stands out.
    let list = names.map { "“\($0)”" }.joined(separator: ", ")
    let urlHosts = argv.compactMap { URL(string: $0)?.host }.filter { _ in !pinned.isEmpty }
    let destination = urlHosts.isEmpty ? "" : " → \(Array(Set(urlHosts)).sorted().joined(separator: ", "))"
    return RunPlan(secrets: secrets, path: path, argv: argv, shown: shown, prompt: "use \(list)\(destination) to run: \(shown)")
}

func cmdRun(_ args: [String]) async throws -> Int32 {
    let store = try loadStore()
    let plan = try planRun(args, store: store)
    let (secrets, path, argv, shown) = (plan.secrets, plan.path, plan.argv, plan.shown)
    let context = try await approve(plan.prompt)
    let seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: store.seKey,
                                                               authenticationContext: context)
    let values = try secrets.map { try open($0, with: seKey, sePublic: store.sePublicKey) }
    context.invalidate()
    let status = try execute(path: path, argv: argv, secrets: secrets, values: values)
    audit("exit \(status): \(shown)")
    return status
}

// Runs the approved command with the secrets delivered, relaying its output with them redacted.
func execute(path: String, argv: [String], secrets: [Secret], values: [Data]) throws -> Int32 {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: path)
    process.arguments = Array(argv.dropFirst())
    var environment = scrubbedEnvironment()
    for (s, v) in zip(secrets, values) { if let env = s.env { environment[env] = String(decoding: v, as: UTF8.self) } }
    process.environment = environment

    let stdinValue = zip(secrets, values).first { $0.0.env == nil }?.1
    let input = stdinValue.map { _ in Pipe() }
    process.standardInput = input ?? FileHandle.standardInput
    let out = Pipe(), err = Pipe()
    process.standardOutput = out
    process.standardError = err
    try process.run()

    // A stdin secret gets a trailing newline, as most tools read a line.
    if let input, let stdinValue {
        try? input.fileHandleForWriting.write(contentsOf: stdinValue + Data("\n".utf8))
        try? input.fileHandleForWriting.close()
    }

    let named = zip(secrets, values).map { (name: $0.0.name, value: $0.1) }
    let group = DispatchGroup()
    for (pipe, fd) in [(out, FileHandle.standardOutput), (err, FileHandle.standardError)] {
        group.enter()
        DispatchQueue.global().async {
            let redactor = Redactor(named)
            while case let chunk = pipe.fileHandleForReading.availableData, !chunk.isEmpty {
                try? fd.write(contentsOf: redactor.feed(chunk))
            }
            try? fd.write(contentsOf: redactor.flush())
            group.leave()
        }
    }
    process.waitUntilExit()
    group.wait()
    return process.terminationReason == .uncaughtSignal ? 128 + process.terminationStatus : process.terminationStatus
}
