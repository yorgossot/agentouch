// `agentouch protect --review`: suggest which Bitwarden items to protect and let the user tick
// them in a window on this Mac. Names never leave the Mac: suggestions come from Apple's
// on-device model (when Apple Intelligence is on), the built-in lists and a seed-phrase check,
// and the agent that ran the command only sees counts.
import AppKit
import Foundation
#if canImport(FoundationModels)
import FoundationModels
#endif

func itemID(_ item: [String: Any]) -> String { item["id"] as? String ?? "" }

func itemHosts(_ item: [String: Any]) -> [String] {
    let uris = (item["login"] as? [String: Any])?["uris"] as? [[String: Any]] ?? []
    return Array(Set(uris.compactMap { ($0["uri"] as? String).flatMap(host) })).sorted()
}

// A note that holds 12–25 lower-case words reads like a wallet seed phrase (BIP-39 or Monero).
func looksLikeSeedPhrase(_ text: String) -> Bool {
    let lines = text.split(whereSeparator: \.isNewline).map { $0.split(separator: " ") }
    let candidates = lines + [text.split(whereSeparator: { $0 == " " || $0.isNewline })]
    return candidates.contains { words in
        (12...25).contains(words.count) && words.allSatisfy { $0.count >= 3 && $0.allSatisfy { $0.isASCII && $0.isLowercase } }
    }
}

// Asks the on-device model which items are sensitive. Returns nil (with why) when it can't run.
func onDeviceFlags(_ items: [[String: Any]]) async -> (Set<String>?, String) {
    #if canImport(FoundationModels)
    if #available(macOS 26.0, *) {
        guard case .available = SystemLanguageModel.default.availability else {
            return (nil, "Apple's on-device model isn't available (is Apple Intelligence on?)")
        }
        let instructions = """
        You help a person protect their password manager. An item is SENSITIVE if someone who got into it \
        could take money, take over other accounts, impersonate the person, or cause tax or legal trouble: \
        email and Apple, Google or Microsoft accounts; password managers and authenticators; banks; payments \
        and wallets; brokers; crypto exchanges, wallets, keys and seed phrases (including Monero or XMR); \
        government and tax; health insurance; mobile carriers; domains and hosting; developer accounts; payroll. \
        Shops, forums, streaming, games, newsletters and food delivery are NOT sensitive.
        """
        var flagged = Set<String>(), failures = 0
        for start in stride(from: 0, to: items.count, by: 20) {
            let batch = Array(items[start..<min(start + 20, items.count)])
            let list = batch.enumerated().map { index, item in
                let hosts = itemHosts(item)
                let kind = item["secureNote"] != nil ? "note" : "login"
                return "\(index + 1). \(kind): \(item["name"] as? String ?? "")\(hosts.isEmpty ? "" : " (\(hosts.joined(separator: ", ")))")"
            }.joined(separator: "\n")
            do {
                let session = LanguageModelSession(instructions: instructions)
                let reply = try await session.respond(to: "Items:\n\(list)\n\nReply with only the numbers of the SENSITIVE items, comma-separated, or NONE.")
                for n in reply.content.split(whereSeparator: { !$0.isNumber }).compactMap({ Int($0) })
                where (1...batch.count).contains(n) {
                    flagged.insert(itemID(batch[n - 1]))
                }
            } catch {
                failures += 1
            }
        }
        return (flagged, failures == 0 ? "Apple's on-device model" : "Apple's on-device model (it skipped \(failures) batch\(failures == 1 ? "" : "es"))")
    }
    #endif
    return (nil, "Apple's on-device model needs macOS 26")
}

final class FlippedView: NSView { override var isFlipped: Bool { true } }

// The scrolling list of checkboxes: suggested items first and ticked, blocked ones greyed out.
@MainActor
func reviewList(_ items: [[String: Any]], suggested: Set<String>) -> (NSScrollView, [(NSButton, String)]) {
    func name(_ item: [String: Any]) -> String { item["name"] as? String ?? "?" }
    let sorted = items.sorted {
        let (a, b) = (suggested.contains(itemID($0)), suggested.contains(itemID($1)))
        return a != b ? a : name($0).localizedCaseInsensitiveCompare(name($1)) == .orderedAscending
    }
    let stack = NSStackView()
    stack.orientation = .vertical
    stack.alignment = .leading
    stack.spacing = 4
    var boxes: [(NSButton, String)] = []
    for item in sorted {
        let blocked = protectBlocker(item)
        let hosts = itemHosts(item)
        let kind = item["secureNote"] != nil ? "note: " : ""
        let title = "\(kind)\(name(item))\(hosts.isEmpty ? "" : "  (\(hosts.joined(separator: ", ")))")\(blocked.map { "  — \($0)" } ?? "")"
        let box = NSButton(checkboxWithTitle: title, target: nil, action: nil)
        box.state = suggested.contains(itemID(item)) && blocked == nil ? .on : .off
        box.isEnabled = blocked == nil
        stack.addArrangedSubview(box)
        boxes.append((box, itemID(item)))
    }
    let size = stack.fittingSize
    stack.frame = NSRect(origin: .zero, size: size)
    let document = FlippedView(frame: NSRect(x: 0, y: 0, width: max(size.width, 640), height: size.height))
    document.addSubview(stack)
    let scroll = NSScrollView(frame: NSRect(x: 0, y: 0, width: 660, height: min(440, size.height + 8)))
    scroll.hasVerticalScroller = true
    scroll.borderType = .bezelBorder
    scroll.documentView = document
    return (scroll, boxes)
}

// Shows every unprotected item with the suggested ones ticked. Returns the ids the user leaves
// ticked, or nil if they cancel.
@MainActor
func reviewWindow(_ items: [[String: Any]], suggested: Set<String>, source: String) -> [String]? {
    let app = NSApplication.shared
    app.setActivationPolicy(.accessory)
    app.activate(ignoringOtherApps: true)

    let alert = NSAlert()
    alert.messageText = "Protect Bitwarden items"
    alert.informativeText = """
    Ticked items get “Master password re-prompt”: agentouch login never hands them out, and Bitwarden \
    asks for your master password before showing or filling them. Suggestions: \(source). \
    Greyed-out items can't be changed here; mark those in Bitwarden yourself.
    """
    alert.addButton(withTitle: "Mark ticked items")
    alert.addButton(withTitle: "Cancel")

    let (scroll, boxes) = reviewList(items, suggested: suggested)
    alert.accessoryView = scroll

    guard alert.runModal() == .alertFirstButtonReturn else { return nil }
    return boxes.filter { $0.0.state == .on }.map(\.1)
}

// The review flow. The vault is read, locked again while the window is open, and unlocked once
// more to mark what the user ticked; nothing about the items is printed, only counts.
func protectReview(_ master: Data) async throws {
    let secrets = [(name: "master password", value: master)]
    let items = try await Bitwarden.unlocked(master, redacting: secrets) { bw in try await freshItems(bw) }
    let candidates = unprotectedItems(in: items)
    guard !candidates.isEmpty else { print("nothing to review: every login and note is already re-prompt"); return }

    let listed = Set(criticalCandidates(in: candidates).map(itemID))
    let seeds = Set(candidates.filter { looksLikeSeedPhrase($0["notes"] as? String ?? "") }.map(itemID))
    let (model, modelSource) = await onDeviceFlags(candidates)
    let source = (model == nil ? ["the built-in list"] : [modelSource, "the built-in list"]).joined(separator: " and ")
        + ", plus notes that look like seed phrases"
    let suggested = listed.union(seeds).union(model ?? [])
    if model == nil { print("note: \(modelSource); suggesting from the built-in list only") }

    guard let chosen = await MainActor.run(body: { reviewWindow(candidates, suggested: suggested, source: source) }) else {
        print("cancelled; nothing was changed")
        return
    }
    guard !chosen.isEmpty else { print("nothing ticked; nothing was changed"); return }

    var marked = 0, warnings = 0, skipped = 0, failed = 0
    try await Bitwarden.unlocked(master, redacting: secrets) { bw in
        for id in chosen {
            switch markReprompt(id, bw) {
            case .marked(let note): marked += 1; if note.contains("WARNING") { warnings += 1 }
            case .already: break
            case .skipped: skipped += 1
            case .failed: failed += 1
            }
        }
    }
    print("marked \(marked) of \(chosen.count) ticked item\(chosen.count == 1 ? "" : "s") as re-prompt"
          + (skipped > 0 ? "; \(skipped) skipped (mark them in Bitwarden)" : "")
          + (failed > 0 ? "; \(failed) failed, see ~/.config/agentouch/log" : "")
          + (warnings > 0 ? "; \(warnings) changed more than expected, check them in Bitwarden" : ""))
}
