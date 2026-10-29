// `agentouch protect --review`: suggest which Bitwarden items to protect and let the user tick
// them in a window on this Mac. Names never leave the Mac: suggestions come from the built-in
// lists and a seed-phrase check, and the agent that ran the command only sees counts. (Apple's
// on-device model was tried and dropped: about half its answers were wrong, and it refuses
// items it deems sensitive, which is the point here.)
import AppKit
import Foundation

func itemID(_ item: [String: Any]) -> String { item["id"] as? String ?? "" }

func itemHosts(_ item: [String: Any]) -> [String] {
    let uris = (item["login"] as? [String: Any])?["uris"] as? [[String: Any]] ?? []
    return Array(Set(uris.compactMap { ($0["uri"] as? String).flatMap(host) })).sorted()
}

// Text that holds 12–33 plain words reads like a wallet seed phrase (BIP-39, Monero's 25 words,
// SLIP-39 shares), also when numbered ("1. abandon 2. ability") or capitalised.
func looksLikeSeedPhrase(_ text: String) -> Bool {
    func words(_ chunk: Substring) -> [Substring] {
        chunk.lowercased().split(whereSeparator: { $0 == " " || $0 == "\t" || $0.isNewline })
            .map { $0.drop { $0.isNumber || $0.isPunctuation } }
            .filter { !$0.isEmpty }
            .map { Substring($0) }
    }
    let chunks = text.split(whereSeparator: \.isNewline) + [Substring(text)]
    return chunks.contains { chunk in
        let w = words(chunk)
        return (12...33).contains(w.count) && w.allSatisfy { $0.count >= 3 && $0.allSatisfy { $0.isASCII && $0.isLetter } }
    }
}

// The free text of an item where a seed phrase could hide: its notes and custom field values.
func itemText(_ item: [String: Any]) -> String {
    let fields = (item["fields"] as? [[String: Any]] ?? []).compactMap { $0["value"] as? String }
    return ([item["notes"] as? String ?? ""] + fields).joined(separator: "\n")
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

    alert.window.level = .modalPanel  // in front of the terminal it was started from
    alert.window.orderFrontRegardless()
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
    let seeds = Set(candidates.filter { looksLikeSeedPhrase(itemText($0)) }.map(itemID))
    let source = "the built-in list of sensitive sites, plus items holding something that looks like a seed phrase"
    let suggested = listed.union(seeds)

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
