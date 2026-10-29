// agentouch entry point; see agentouch.swift.
import AppKit
import Foundation

umask(0o077)
signal(SIGPIPE, SIG_IGN)  // a command that exits without reading stdin must not kill agentouch
let args = Array(CommandLine.arguments.dropFirst())
do {
    switch args.first {
    case "--version", "version": print("agentouch \(agentouchVersion)")
    case "init": try cmdInit()
    case "add": try await cmdAdd(Array(args.dropFirst()))
    case "list": try cmdList()
    case "password": try cmdPassword(Array(args.dropFirst()))
    case "set-master": try await cmdSetMaster(Array(args.dropFirst()))
    case "login-new": try await cmdLoginNew(Array(args.dropFirst()))
    case "login": try await cmdLogin(Array(args.dropFirst()))
    case "clipboard-clear": cmdClipboardClear()
    case "protect": try await cmdProtect(Array(args.dropFirst()))
    case "_reap":
        guard args.count == 4, let server = pid_t(args[1]), let parent = pid_t(args[2]) else { exit(1) }
        reap(server: server, parent: parent, directory: args[3])
    case "_clear-clipboard":
        sleep(UInt32(min(max(Int(args.count > 2 ? args[2] : "") ?? 90, 5), 300)))
        if args.count > 1, String(NSPasteboard.general.changeCount) == args[1] { NSPasteboard.general.clearContents() }
    case "rm": try await cmdRemove(Array(args.dropFirst()))
    case "run": exit(try await cmdRun(Array(args.dropFirst())))
    default:
        print("""
        agentouch — run a command with a secret, after you approve that exact command with Touch ID

          agentouch init                               create the Secure Enclave key (once)
          agentouch add NAME --allow PROG[,PROG] (--env VAR | --stdin) [--hosts H[,H]] [--from-clipboard]
                                                       store a secret, after Touch ID (pasted hidden,
                                                       piped in, or taken from the clipboard); --hosts
                                                       pins where curl may send it
          agentouch list                               names and settings, never values
          agentouch password [--length N]              new password onto the clipboard, never printed
          agentouch set-master [--from-clipboard]      store the Bitwarden master password, after Touch ID
          agentouch login-new --site SITE --username NAME [--folder F] [--task WHY]
                                                       after Touch ID, save a new login with a fresh
                                                       password to Bitwarden; password onto the clipboard
          agentouch login --site SITE [--username NAME]
                                                       after Touch ID, put an existing Bitwarden login's
                                                       password on the clipboard for 30 s
          agentouch protect [--review | --all | --apply ID[,ID]]
                                                       after Touch ID, pick items to mark re-prompt in a
                                                       window (--review), or list them / mark by id
          agentouch clipboard-clear                    clear a password agentouch put on the clipboard
          agentouch rm NAME                            delete a secret, after Touch ID
          agentouch run NAME[,NAME] -- PROG [ARGS...]  one Touch ID for the exact command shown
        """)
        exit(args.isEmpty || ["help", "--help", "-h"].contains(args[0]) ? 0 : 1)
    }
} catch let f as Fail {
    FileHandle.standardError.write(Data("agentouch: \(f.message)\n".utf8))
    exit(1)
} catch {
    FileHandle.standardError.write(Data("agentouch: \(error)\n".utf8))
    exit(1)
}
