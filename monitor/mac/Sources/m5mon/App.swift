// SPDX-License-Identifier: MIT
// "M5 Monitor.app": the same streamer, started from Finder, with a menu bar
// icon instead of a terminal. Built by ../make-app.sh.
import AppKit
import ApplicationServices

let isApp = Bundle.main.bundleURL.pathExtension == "app"

final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate {
    var item: NSStatusItem!
    let statusLine = NSMenuItem(title: "", action: nil, keyEquivalent: "")
    let touchItem = NSMenuItem(title: "Touch Controls the Mac", action: #selector(toggleTouch), keyEquivalent: "")

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
        menu.addItem(.separator())
        menu.addItem(NSMenuItem(title: "Quit M5 Monitor", action: #selector(quit), keyEquivalent: "q"))
        menu.items.last?.target = self
        item.menu = menu
        var o = Options()
        o.touch = UserDefaults.standard.bool(forKey: "touch")
        Task.detached { await M5Mon.run(o) }
    }

    func menuWillOpen(_ menu: NSMenu) {
        statusLine.title = streamer?.status ?? "Starting…"
        touchItem.state = streamer?.touchEnabled == true ? .on : .off
    }

    @objc func toggleTouch() {
        guard let s = streamer else { return }
        let on = !s.touchEnabled
        if on && !AXIsProcessTrustedWithOptions([kAXTrustedCheckOptionPrompt.takeUnretainedValue(): true] as CFDictionary) {
            // macOS shows its own prompt; touch starts working once allowed.
        }
        s.q.async {
            if !on { s.releaseMouse() }
            s.touchEnabled = on
        }
        UserDefaults.standard.set(on, forKey: "touch")
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
