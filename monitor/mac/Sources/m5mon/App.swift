// SPDX-License-Identifier: MIT
// "M5 Monitor.app": the same streamer, started from Finder. A small control
// window (shown at launch, and again whenever the app is opened while
// running) and a menu bar icon both carry the controls; on a MacBook with a
// notch the menu bar icon is easily hidden. Built by ../make-app.sh.
import AppKit
import ApplicationServices

let isApp = Bundle.main.bundleURL.pathExtension == "app"

enum Placement: Int, CaseIterable {
    case left, right, above, below
    var title: String {
        ["Left of the main screen", "Right of the main screen", "Above the main screen", "Below the main screen"][rawValue]
    }
}

/// Moves the virtual display next to the main one, bottom- or centre-aligned.
/// Done here because System Settings' Arrange view can be fiddly with a
/// display this small.
func place(_ p: Placement) {
    guard let id = virtualDisplay?.displayID else { return }
    let m = CGDisplayBounds(CGMainDisplayID())
    let w = CGDisplayBounds(id).width, h = CGDisplayBounds(id).height
    let origin: CGPoint
    switch p {
    case .left: origin = CGPoint(x: m.minX - w, y: m.maxY - h)
    case .right: origin = CGPoint(x: m.maxX, y: m.maxY - h)
    case .above: origin = CGPoint(x: m.midX - w / 2, y: m.minY - h)
    case .below: origin = CGPoint(x: m.midX - w / 2, y: m.maxY)
    }
    var cfg: CGDisplayConfigRef?
    CGBeginDisplayConfiguration(&cfg)
    CGConfigureDisplayOrigin(cfg, id, Int32(origin.x), Int32(origin.y))
    let r = CGCompleteDisplayConfiguration(cfg, .forSession)
    log("placed \(p) (\(r == .success ? "ok" : "error \(r.rawValue)")): now at \(CGDisplayBounds(id).origin)")
}

final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate {
    var item: NSStatusItem!
    var window: NSWindow!
    let statusLine = NSMenuItem(title: "", action: nil, keyEquivalent: "")
    let touchItem = NSMenuItem(title: "Touch Controls the Mac", action: #selector(toggleTouch), keyEquivalent: "")
    let statusLabel = NSTextField(labelWithString: "Starting…")
    let touchBox = NSButton(checkboxWithTitle: "Touch on the Core2 controls the Mac", target: nil, action: nil)
    let placeMenu = NSPopUpButton()
    var placed = false

    var placement: Placement {
        get { Placement(rawValue: UserDefaults.standard.integer(forKey: "placement")) ?? .left }
        set { UserDefaults.standard.set(newValue.rawValue, forKey: "placement") }
    }

    func applicationDidFinishLaunching(_ n: Notification) {
        item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        item.button?.image = NSImage(systemSymbolName: "display", accessibilityDescription: "M5 Monitor")
        let menu = NSMenu()
        menu.delegate = self
        statusLine.isEnabled = false
        menu.addItem(statusLine)
        menu.addItem(.separator())
        touchItem.target = self
        menu.addItem(touchItem)
        let show = NSMenuItem(title: "Show Controls…", action: #selector(showWindow), keyEquivalent: "")
        show.target = self
        menu.addItem(show)
        menu.addItem(.separator())
        let q = NSMenuItem(title: "Stop and Remove Display", action: #selector(quit), keyEquivalent: "q")
        q.target = self
        menu.addItem(q)
        item.menu = menu

        buildWindow()
        showWindow()
        Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { [weak self] _ in self?.refresh() }

        var o = Options()
        o.touch = UserDefaults.standard.bool(forKey: "touch")
        Task.detached { await M5Mon.run(o) }
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows: Bool) -> Bool {
        showWindow()
        return true
    }

    func buildWindow() {
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 340, height: 170),
                          styleMask: [.titled, .closable], backing: .buffered, defer: false)
        window.title = "M5 Monitor"
        window.isReleasedWhenClosed = false
        window.level = .floating
        touchBox.target = self
        touchBox.action = #selector(toggleTouch)
        for p in Placement.allCases { placeMenu.addItem(withTitle: p.title) }
        placeMenu.selectItem(at: placement.rawValue)
        placeMenu.target = self
        placeMenu.action = #selector(placeChanged)
        let stop = NSButton(title: "Stop and Remove Display", target: self, action: #selector(quit))
        stop.bezelColor = .systemRed
        let placeRow = NSStackView(views: [NSTextField(labelWithString: "Position:"), placeMenu])
        let stack = NSStackView(views: [statusLabel, touchBox, placeRow, stop])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 12
        stack.edgeInsets = NSEdgeInsets(top: 16, left: 20, bottom: 16, right: 20)
        window.contentView = stack
        // On the main (menu bar) screen, not wherever the mouse is.
        if let f = NSScreen.screens.first?.visibleFrame {
            window.setFrameOrigin(NSPoint(x: f.midX - 170, y: f.midY))
        }
    }

    @objc func showWindow() {
        refresh()
        NSApp.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)
        // macOS may decline to activate an accessory app it did not just
        // see clicked; float the window so it shows anyway.
        window.orderFrontRegardless()
    }

    func refresh() {
        let s = streamer
        statusLabel.stringValue = s?.status ?? "Starting…"
        touchBox.state = s?.touchEnabled == true ? .on : .off
        // Put the display where it was last time, once it exists.
        if !placed, virtualDisplay != nil, s?.stream != nil {
            placed = true
            place(placement)
        }
    }

    func menuWillOpen(_ menu: NSMenu) {
        statusLine.title = streamer?.status ?? "Starting…"
        touchItem.state = streamer?.touchEnabled == true ? .on : .off
    }

    @objc func placeChanged() {
        placement = Placement(rawValue: placeMenu.indexOfSelectedItem) ?? .left
        place(placement)
    }

    @objc func toggleTouch() {
        guard let s = streamer else { return }
        let on = !s.touchEnabled
        if on {
            // macOS shows its own prompt; touch starts working once allowed.
            _ = AXIsProcessTrustedWithOptions([kAXTrustedCheckOptionPrompt.takeUnretainedValue(): true] as CFDictionary)
        }
        s.q.async {
            if !on { s.releaseMouse() }
            s.touchEnabled = on
        }
        UserDefaults.standard.set(on, forKey: "touch")
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) { self.refresh() }
    }

    @objc func quit() {
        streamer?.q.sync { streamer?.releaseMouse() }
        NSApp.terminate(nil)
    }
}

func startApp() -> Never {
    // log() goes to ~/Library/Logs/M5 Monitor.log.
    let logPath = NSHomeDirectory() + "/Library/Logs/M5 Monitor.log"
    freopen(logPath, "a", stdout)
    freopen(logPath, "a", stderr)
    let app = NSApplication.shared
    let delegate = AppDelegate()
    app.delegate = delegate
    app.setActivationPolicy(.accessory)
    app.run()
    exit(0)
}

func appFail(_ s: String) {
    NSApp.activate(ignoringOtherApps: true)
    let a = NSAlert()
    a.messageText = "M5 Monitor"
    a.informativeText = s
    a.runModal()
}
