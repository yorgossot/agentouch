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

// The scrolling list of checkboxes. Ticked items come first, then suggested ones, then the rest;
// items `disabled` explains are greyed out.
@MainActor
func reviewList(_ items: [[String: Any]], ticked: Set<String>, suggested: Set<String>,
                disabled: ([String: Any]) -> String?) -> (NSScrollView, [(NSButton, String)]) {
    func name(_ item: [String: Any]) -> String { item["name"] as? String ?? "?" }
    func rank(_ item: [String: Any]) -> Int { ticked.contains(itemID(item)) ? 0 : suggested.contains(itemID(item)) ? 1 : 2 }
    let sorted = items.sorted {
        rank($0) != rank($1) ? rank($0) < rank($1) : name($0).localizedCaseInsensitiveCompare(name($1)) == .orderedAscending
    }
    let stack = NSStackView()
    stack.orientation = .vertical
    stack.alignment = .leading
    stack.spacing = 4
    var boxes: [(NSButton, String)] = []
    for item in sorted {
        let reason = disabled(item)
        let hosts = itemHosts(item)
        let kind = item["secureNote"] != nil ? "note: " : ""
        let hint = !ticked.contains(itemID(item)) && suggested.contains(itemID(item)) ? "  — suggested" : ""
        let title = "\(kind)\(name(item))\(hosts.isEmpty ? "" : "  (\(hosts.joined(separator: ", ")))")\(reason.map { "  — \($0)" } ?? hint)"
        let box = NSButton(checkboxWithTitle: title, target: nil, action: nil)
        box.state = ticked.contains(itemID(item)) && reason == nil ? .on : .off
        box.isEnabled = reason == nil
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

// Shows the list in a window in front of everything. Returns the ids the user leaves ticked, or
// nil if they cancel.
@MainActor
func reviewWindow(_ items: [[String: Any]], ticked: Set<String>, suggested: Set<String>, title: String,
                  message: String, button: String, disabled: ([String: Any]) -> String? = { _ in nil }) -> [String]? {
    let app = NSApplication.shared
    app.setActivationPolicy(.accessory)
    app.activate(ignoringOtherApps: true)
    let alert = NSAlert()
    alert.messageText = title
    alert.informativeText = message
    alert.addButton(withTitle: button)
    alert.addButton(withTitle: "Cancel")
    let (scroll, boxes) = reviewList(items, ticked: ticked, suggested: suggested, disabled: disabled)
    alert.accessoryView = scroll
    alert.window.level = .modalPanel  // in front of the terminal it was started from
    alert.window.orderFrontRegardless()
    guard alert.runModal() == .alertFirstButtonReturn else { return nil }
    return boxes.filter { $0.0.state == .on }.map(\.1)
}

// Suggestions from the built-in lists and from items holding something like a seed phrase.
func suggestions(_ items: [[String: Any]]) -> Set<String> {
    Set(criticalCandidates(in: items).map(itemID)).union(items.filter { looksLikeSeedPhrase(itemText($0)) }.map(itemID))
}

// `protect`: the window for the blocked list. It lists every login, with the blocked ones
// ticked (on a first run, the suggested ones), plus any ids the caller suggests. Returns the
// new list, or nil if the user cancels. The vault is locked again while the window is open.
func blockWindow(_ master: Data, blocked: [String], firstRun: Bool, suggest: [String]) async throws -> (list: [String], added: Int, removed: Int)? {
    let items = try await Bitwarden.unlocked(master, redacting: [(name: "master password", value: master)]) { bw in
        try await freshItems(bw)
    }
    let logins = items.filter { $0["login"] != nil && ($0["deletedDate"] == nil || $0["deletedDate"] is NSNull) }
    guard !logins.isEmpty else { print("no logins in the vault"); return nil }
    let current = Set(logins.map(itemID).filter { isBlocked($0, blocked) })
    let fromCaller = Set(logins.map(itemID).filter { isBlocked($0, suggest) })
    let suggested = suggestions(logins).union(fromCaller)
    let ticked = firstRun ? suggested : current.union(fromCaller)
    let message = """
    Ticked logins are kept from agents: agentouch login refuses them, and you log in to those \
    sites yourself. Nothing changes in Bitwarden. Ticks start from your current list\
    \(firstRun ? " (on this first run, from the built-in list of sensitive sites)" : "")\
    \(fromCaller.isEmpty ? "" : ", plus \(fromCaller.count) suggested by the script that opened this window").
    """
    guard let chosen = await MainActor.run(body: {
        reviewWindow(logins, ticked: ticked, suggested: suggested, title: "Keep logins away from agents",
                     message: message, button: "Save")
    }) else { return nil }
    // Blocks for logins the window didn't show (trashed, or missing from this listing) are kept.
    let shown = Set(logins.map(itemID))
    let unseen = blocked.filter { b in !shown.contains { isBlocked($0, [b]) } }
    let added = chosen.filter { !current.contains($0) }.count
    let removed = current.subtracting(chosen).count
    return (unseen + chosen, added, removed)
}

// `protect --reprompt`: the same window, but what the user ticks is marked "master password
// re-prompt" in Bitwarden. The vault is read, locked while the window is open, and unlocked
// once more to mark; nothing about the items is printed, only counts.
func protectReview(_ master: Data) async throws {
    let secrets = [(name: "master password", value: master)]
    let items = try await Bitwarden.unlocked(master, redacting: secrets) { bw in try await freshItems(bw) }
    let candidates = unprotectedItems(in: items)
    guard !candidates.isEmpty else { print("nothing to review: every login and note is already re-prompt"); return }
    let suggested = suggestions(candidates)
    let message = """
    Ticked items get “Master password re-prompt” in Bitwarden: agentouch login never hands them out, \
    and Bitwarden asks for your master password before showing or filling them. Suggestions come \
    from the built-in list of sensitive sites and items holding something like a seed phrase. \
    Greyed-out items can't be changed here; mark those in Bitwarden yourself.
    """
    guard let chosen = await MainActor.run(body: {
        reviewWindow(candidates, ticked: suggested, suggested: suggested, title: "Mark Bitwarden items re-prompt",
                     message: message, button: "Mark ticked items", disabled: protectBlocker)
    }) else {
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
          + (failed > 0 ? "; \(failed) failed, see agentouch's log" : "")
          + (warnings > 0 ? "; \(warnings) changed more than expected, check them in Bitwarden" : ""))
}
