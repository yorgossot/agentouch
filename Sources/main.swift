// agentouch entry point; see agentouch.swift.
import AppKit
import Foundation

let help = """
agentouch — let an AI agent use your secrets on this Mac without seeing them; you approve each use with Touch ID

Secrets
  agentouch init                               create the Secure Enclave key (once; ./install.sh does it)
  agentouch add NAME --allow PROG[,PROG] (--env VAR | --stdin) [--hosts H[,H]] [--from-clipboard]
                                               store a secret, after Touch ID; --hosts pins where
                                               curl may send it
  agentouch run NAME[,NAME] -- PROG [ARGS...]  run that exact command with the secret, after Touch ID
  agentouch list                               names and settings, never values
  agentouch rm NAME                            delete a secret, after Touch ID

Bitwarden (optional; needs the Bitwarden CLI, logged in)
  agentouch set-master [--from-clipboard]      store your master password, after Touch ID (once)
  agentouch protect [--suggest ID,ID | --block ID,ID | --reprompt]
                                               choose, in a window, which logins agents may never get
  agentouch signup --site SITE --username NAME [--folder F] [--task WHY]
                                               save a new login with a fresh password; password
                                               onto the clipboard
  agentouch login --site SITE [--username NAME]
                                               put a saved login's password on the clipboard for 30 s
  agentouch clear                              clear a password agentouch put on the clipboard
  agentouch password [--length N]              a new password onto the clipboard, never printed

  agentouch doctor                             check this Mac's setup
  agentouch version
"""

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
    case "signup", "login-new": try await cmdLoginNew(Array(args.dropFirst()))
    case "login": try await cmdLogin(Array(args.dropFirst()))
    case "clear", "clipboard-clear": cmdClipboardClear()
    case "protect": try await cmdProtect(Array(args.dropFirst()))
    case "doctor": exit(cmdDoctor() ? 0 : 1)
    case "_reap":
        guard args.count == 4, let server = pid_t(args[1]), let parent = pid_t(args[2]) else { exit(1) }
        reap(server: server, parent: parent, directory: args[3])
    case "_clear-clipboard":
        sleep(UInt32(min(max(Int(args.count > 2 ? args[2] : "") ?? 90, 5), 300)))
        if args.count > 1, String(NSPasteboard.general.changeCount) == args[1] { NSPasteboard.general.clearContents() }
    case "rm": try await cmdRemove(Array(args.dropFirst()))
    case "run": exit(try await cmdRun(Array(args.dropFirst())))
    case nil, "help", "--help", "-h": print(help)
    case let other?:
        FileHandle.standardError.write(Data("agentouch: unknown command '\(other)'\n\n\(help)\n".utf8))
        exit(1)
    }
} catch let f as Fail {
    FileHandle.standardError.write(Data("agentouch: \(f.message)\n".utf8))
    exit(1)
} catch {
    FileHandle.standardError.write(Data("agentouch: \(error)\n".utf8))
    exit(1)
}
