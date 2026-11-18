// SPDX-License-Identifier: MIT
// m5mon: use an M5Stack Core2 as a (very) small external monitor.
import ApplicationServices
import CoreGraphics
import Foundation
import ScreenCaptureKit
import VirtualDisplay

let usage = """
usage: m5mon [source] [link] [options]

source (default --virtual):
  --virtual [W]        add a display to macOS and show it on the Core2. W is
                       its width in points (default 320, 4:3, HiDPI); macOS
                       may insist on 800x600, which still fits, just smaller
  --display N          mirror all of display N (0 = main), letterboxed
  --region X,Y,W,H     mirror a rectangle of the main display, in points
  --follow [W]         mirror a W-point-wide 4:3 box that follows the mouse (default 640)

link (default: m5mon.local over WiFi, else the first USB serial port):
  --host HOST          WiFi: hostname or IP of the Core2
  --serial [PORT]      USB serial; PORT defaults to the first /dev/cu.usbserial-*
  --baud N             serial speed for streaming (default 2000000)

options:
  --fps N              capture rate (default 30)
  --lossless           never use JPEG
  --quality Q          JPEG quality 0..1 (default 0.7)
  --no-touch           ignore the touch screen
  --setup-wifi         send this Mac's WiFi network and password (from the
                       Keychain) to the Core2 over USB serial, then exit

touch: tap = click, drag = drag, tap twice = double-click.
buttons under the screen: A scroll up, B right-click, C scroll down.
"""

enum Source {
    case virtual
    case display(Int)
    case region(CGRect)
    case follow(CGFloat)
}

struct Options {
    var source = Source.virtual
    var host: String?
    var serial: String??  // .some(nil): serial, port auto-detected
    var baud = 2_000_000
    var fps = 30
    var lossless = false
    var quality = 0.7
    var touch = true
    var setupWiFi = false
    var virtualWidth = 320
}

func parseOptions() -> Options {
    var o = Options()
    var args = Array(CommandLine.arguments.dropFirst())
    func next() -> String? { args.isEmpty || args[0].hasPrefix("--") ? nil : args.removeFirst() }
    func need(_ flag: String) -> String {
        guard let v = next() else { fail("\(flag) needs a value\n\n\(usage)") }
        return v
    }
    while !args.isEmpty {
        let a = args.removeFirst()
        switch a {
        case "--virtual":
            o.source = .virtual
            if let w = next().flatMap({ Int($0) }) { o.virtualWidth = w }
        case "--display": o.source = .display(Int(need(a)) ?? 0)
        case "--region":
            let v = need(a).split(separator: ",").compactMap { Double($0) }
            guard v.count == 4 else { fail("--region wants X,Y,W,H") }
            o.source = .region(CGRect(x: v[0], y: v[1], width: v[2], height: v[3]))
        case "--follow": o.source = .follow(CGFloat(next().flatMap { Double($0) } ?? 640))
        case "--host": o.host = need(a)
        case "--serial": o.serial = .some(next())
        case "--baud": o.baud = Int(need(a)) ?? o.baud
        case "--fps": o.fps = max(1, min(60, Int(need(a)) ?? 30))
        case "--lossless": o.lossless = true
        case "--quality": o.quality = Double(need(a)) ?? 0.7
        case "--no-touch": o.touch = false
        case "--setup-wifi": o.setupWiFi = true
        case "-h", "--help": print(usage); exit(0)
        default: fail("unknown option \(a)\n\n\(usage)")
        }
    }
    return o
}

func fail(_ s: String) -> Never {
    FileHandle.standardError.write((s + "\n").data(using: .utf8)!)
    exit(1)
}

func log(_ s: String) {
    let t = DateFormatter.localizedString(from: Date(), dateStyle: .none, timeStyle: .medium)
    print("[\(t)] \(s)")
    fflush(stdout)
}

// MARK: - Connecting

/// Sends `msg` and waits for a reply of type `want`.
func request(_ link: Link, _ msg: [UInt8], want: Character, timeout: Double) -> Message? {
    let sem = DispatchSemaphore(value: 0)
    var got: Message?
    let prev = link.onMessage
    link.onMessage = { m in
        if m.type == want.asciiValue! && got == nil { got = m; sem.signal() }
    }
    defer { link.onMessage = prev }
    guard link.send(msg) else { return nil }
    _ = sem.wait(timeout: .now() + timeout)
    return got
}

func serialPort(_ o: Options) -> String {
    if case .some(.some(let p)) = o.serial { return p }
    guard let p = findSerialPort() else { fail("no USB serial port found: is the Core2 plugged in?") }
    return p
}

func connectSerial(_ o: Options) throws -> Link {
    let link = try openSerial(path: serialPort(o))
    link.start()
    // A host that just restarted may find the device still at streaming speed.
    setBaud(link.fd, o.baud)
    if request(link, frame("H"), want: "I", timeout: 0.4) != nil { return link }
    setBaud(link.fd, 115_200)
    guard request(link, frame("H"), want: "I", timeout: 2) != nil else {
        link.close()
        throw LinkError.failed("no answer on \(link.name): is the m5mon firmware flashed?")
    }
    let b = UInt32(o.baud)
    let p = [UInt8(b & 0xff), UInt8(b >> 8 & 0xff), UInt8(b >> 16 & 0xff), UInt8(b >> 24)]
    if request(link, frame("S", p), want: "S", timeout: 1) != nil {
        usleep(20_000)
        setBaud(link.fd, o.baud)
        usleep(20_000)
        if request(link, frame("H"), want: "I", timeout: 1) != nil { return link }
        log("\(o.baud) baud did not work; staying at 115200 (slow). Try --baud 921600.")
        usleep(3_500_000)  // the device falls back to 115200 after 3 s of silence
        setBaud(link.fd, 115_200)
    }
    return link
}

func connect(_ o: Options) throws -> Link {
    if o.serial != nil { return try connectSerial(o) }
    if let h = o.host { return try connectTCP(host: h, port: 5320) }
    do {
        return try connectTCP(host: "m5mon.local", port: 5320)
    } catch {
        if findSerialPort() != nil { return try connectSerial(o) }
        throw error
    }
}

// MARK: - WiFi setup

func setupWiFi(_ o: Options) {
    func run(_ cmd: String, _ args: [String]) -> String {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: cmd)
        p.arguments = args
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = FileHandle.nullDevice
        try? p.run()
        p.waitUntilExit()
        return String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    }
    var ssid = run("/usr/sbin/ipconfig", ["getsummary", "en0"]).split(separator: "\n")
        .first { $0.trimmingCharacters(in: .whitespaces).hasPrefix("SSID : ") }
        .map { String($0.split(separator: ":", maxSplits: 1)[1]).trimmingCharacters(in: .whitespaces) } ?? ""
    if ssid.isEmpty || ssid == "<redacted>" {
        print("WiFi network name (2.4 GHz): ", terminator: "")
        ssid = readLine() ?? ""
    }
    var pass = run("/usr/bin/security", ["find-generic-password", "-D", "AirPort network password", "-wa", ssid])
    if pass.hasSuffix("\n") { pass.removeLast() }
    if pass.isEmpty { pass = String(cString: getpass("Password for '\(ssid)' (not shown): ")) }
    let link: Link
    do { link = try connectSerial(Options(serial: .some(o.serial ?? nil), baud: 115_200)) } catch { fail("\(error)") }
    if request(link, frame("W", Array("\(ssid)\t\(pass)".utf8)), want: "W", timeout: 2) != nil {
        print("Sent '\(ssid)' to the Core2; it restarts and joins. Then run: m5mon")
    } else {
        fail("the Core2 did not confirm")
    }
}

// MARK: - Streaming

final class Streamer: NSObject, SCStreamOutput, SCStreamDelegate {
    let o: Options
    let q = DispatchQueue(label: "m5mon.stream")
    let enc = FrameEncoder()
    var link: Link?
    var stream: SCStream?
    var config = SCStreamConfiguration()
    var display: SCDisplay!
    /// The captured area in the display's own points (top-left origin):
    /// where touches land. Kept display-relative so rearranging displays
    /// does not throw taps off.
    var target = CGRect.zero
    var seq: UInt16 = 0
    var inFlight = 0
    var lastChange = Date()
    var lastSend = Date()
    var haveCapture = false
    var frames = 0, statsStart = Date()
    var touchFreezeUntil = Date.distantPast
    var lastDown = (time: Date.distantPast, point: CGPoint.zero)
    var touchPoint = CGPoint.zero
    var clicks: Int64 = 1
    var connecting = false

    init(o: Options) {
        self.o = o
        enc.jpegQuality = o.quality
        enc.allowJPEG = !o.lossless
    }

    // Link

    func attach(_ l: Link) {
        l.onMessage = { [weak self] m in self?.q.async { self?.handle(m) } }
        l.onClose = { [weak self] in self?.q.async { self?.lost() } }
        q.async {
            self.link = l
            self.inFlight = 0
            self.enc.jpegRatio = l.name.hasPrefix("usb") ? 1.5 : 3
            self.enc.forceFull()
            log("connected over \(l.name)")
            self.pump()
        }
    }

    func lost() {
        guard link != nil else { return }
        log("link lost; reconnecting")
        link?.close()
        link = nil
        reconnect()
    }

    func reconnect() {
        if connecting { return }
        connecting = true
        DispatchQueue.global().async {
            while true {
                if let l = try? connect(self.o) {
                    self.q.async { self.connecting = false }
                    self.attach(l)
                    return
                }
                sleep(2)
            }
        }
    }

    func handle(_ m: Message) {
        switch Character(UnicodeScalar(m.type)) {
        case "A":
            inFlight = max(0, inFlight - 1)
            frames += 1
            pump()
        case "T" where o.touch && m.payload.count == 5:
            let x = CGFloat(Int(m.payload[1]) | Int(m.payload[2]) << 8)
            let y = CGFloat(Int(m.payload[3]) | Int(m.payload[4]) << 8)
            let origin = CGDisplayBounds(display.displayID).origin
            touch(kind: m.payload[0], at: CGPoint(x: origin.x + target.minX + (x + 0.5) * target.width / CGFloat(screenW),
                                                  y: origin.y + target.minY + (y + 0.5) * target.height / CGFloat(screenH)))
        case "B" where o.touch && m.payload.count == 1:
            button(Int(m.payload[0]))
        default:
            break
        }
    }

    /// Sends what changed, if the device has room for another frame.
    func pump() {
        guard let link, haveCapture, inFlight < 2 else { return }
        var updates = enc.dirtyRects().map { enc.encode($0) }
        if updates.isEmpty {
            // Still for a moment: replace JPEG areas with exact pixels.
            if Date().timeIntervalSince(lastChange) > 0.3, let u = enc.sharpen() { updates = [u] }
        } else {
            lastChange = Date()
        }
        guard !updates.isEmpty else { return }
        seq &+= 1
        inFlight += 1
        for (i, u) in updates.enumerated() {
            let r = u.rect
            var p: [UInt8] = []
            p.reserveCapacity(12 + u.data.count)
            for v in [r.x, r.y, r.w, r.h] { p += [UInt8(v & 0xff), UInt8(v >> 8)] }
            p += [u.encoding.rawValue, i == updates.count - 1 ? 1 : 0, UInt8(seq & 0xff), UInt8(seq >> 8)]
            p += u.data
            if !link.send(frame("R", p)) { lost(); return }
        }
        lastSend = Date()
    }

    func tick() {
        guard let link else { return }
        if inFlight > 0 && Date().timeIntervalSince(lastSend) > 2 { inFlight = 0 }  // lost an ack
        pump()
        if Date().timeIntervalSince(lastSend) > 1 {
            _ = link.send(frame("K"))
            lastSend = Date()
        }
        let dt = Date().timeIntervalSince(statsStart)
        if dt >= 10 {
            if frames > 0 {
                log(String(format: "%.1f fps, %.0f KB/s", Double(frames) / dt, Double(enc.stats.bytes) / dt / 1024))
            }
            frames = 0; enc.stats = (0, 0); statsStart = Date()
        }
    }

    // Capture

    func stream(_ stream: SCStream, didOutputSampleBuffer sb: CMSampleBuffer, of type: SCStreamOutputType) {
        guard type == .screen,
              let info = (CMSampleBufferGetSampleAttachmentsArray(sb, createIfNecessary: false) as? [[SCStreamFrameInfo: Any]])?.first,
              let raw = info[.status] as? Int, SCFrameStatus(rawValue: raw) == .complete,
              let pb = CMSampleBufferGetImageBuffer(sb) else { return }
        CVPixelBufferLockBaseAddress(pb, .readOnly)
        if let base = CVPixelBufferGetBaseAddress(pb),
           CVPixelBufferGetWidth(pb) == screenW, CVPixelBufferGetHeight(pb) == screenH {
            enc.load(base: base, stride: CVPixelBufferGetBytesPerRow(pb))
            haveCapture = true
        }
        CVPixelBufferUnlockBaseAddress(pb, .readOnly)
        pump()
    }

    func stream(_ stream: SCStream, didStopWithError error: Error) {
        fail("capture stopped: \(error.localizedDescription)")
    }

    func start(display: SCDisplay, source: CGRect?) async throws {
        self.display = display
        let c = SCStreamConfiguration()
        c.width = screenW
        c.height = screenH
        c.pixelFormat = kCVPixelFormatType_32BGRA
        c.minimumFrameInterval = CMTime(value: 1, timescale: CMTimeScale(o.fps))
        c.showsCursor = true
        c.queueDepth = 3
        c.backgroundColor = .black
        let bounds = CGDisplayBounds(display.displayID)
        let src = source ?? CGRect(origin: .zero, size: bounds.size)
        c.sourceRect = src
        // Keep the picture's shape: letterbox anything that is not 4:3.
        let aspect = src.width / src.height
        if abs(aspect - 4.0 / 3.0) > 0.01 {
            if aspect > 4.0 / 3.0 {
                let h = CGFloat(screenW) / aspect
                c.destinationRect = CGRect(x: 0, y: (CGFloat(screenH) - h) / 2, width: CGFloat(screenW), height: h)
            } else {
                let w = CGFloat(screenH) * aspect
                c.destinationRect = CGRect(x: (CGFloat(screenW) - w) / 2, y: 0, width: w, height: CGFloat(screenH))
            }
            target = CGRect(x: src.minX - (c.destinationRect.minX * src.width / c.destinationRect.width),
                            y: src.minY - (c.destinationRect.minY * src.height / c.destinationRect.height),
                            width: src.width * CGFloat(screenW) / c.destinationRect.width,
                            height: src.height * CGFloat(screenH) / c.destinationRect.height)
        } else {
            target = src
        }
        config = c
        let filter = SCContentFilter(display: display, excludingWindows: [])
        let s = SCStream(filter: filter, configuration: c, delegate: self)
        try s.addStreamOutput(self, type: .screen, sampleHandlerQueue: q)
        try await s.startCapture()
        stream = s
    }

    /// --follow: keep the source box centred on the mouse.
    func follow(width: CGFloat) {
        guard let stream, Date() > touchFreezeUntil, let mouse = CGEvent(source: nil)?.location else { return }
        let b = CGDisplayBounds(display.displayID)
        guard b.contains(mouse) else { return }
        let w = min(width, b.width), h = w * 3 / 4
        let x = min(max(mouse.x - b.minX - w / 2, 0), b.width - w)
        let y = min(max(mouse.y - b.minY - h / 2, 0), b.height - h)
        let r = CGRect(x: x.rounded(), y: y.rounded(), width: w, height: h)
        guard abs(r.minX - config.sourceRect.minX) >= 2 || abs(r.minY - config.sourceRect.minY) >= 2 else { return }
        config.sourceRect = r
        target = r
        stream.updateConfiguration(config) { _ in }
    }

    // Input

    func post(_ type: CGEventType, _ p: CGPoint, button: CGMouseButton = .left, clicks: Int64 = 1) {
        let e = CGEvent(mouseEventSource: nil, mouseType: type, mouseCursorPosition: p, mouseButton: button)
        e?.setIntegerValueField(.mouseEventClickState, value: clicks)
        e?.post(tap: .cghidEventTap)
    }

    func touch(kind: UInt8, at p: CGPoint) {
        touchFreezeUntil = Date().addingTimeInterval(1.5)
        switch kind {
        case 0:
            let now = Date()
            let double = now.timeIntervalSince(lastDown.time) < 0.4 && hypot(p.x - lastDown.point.x, p.y - lastDown.point.y) < 12
            let point = double ? lastDown.point : p  // fingers are imprecise; keep the second tap on the first
            lastDown = (now, point)
            touchPoint = point
            post(.mouseMoved, point)
            clicks = double ? 2 : 1
            post(.leftMouseDown, point, clicks: clicks)
        case 1:
            touchPoint = p
            post(.leftMouseDragged, p)
        default:
            post(.leftMouseUp, touchPoint, clicks: clicks)
        }
    }

    func button(_ i: Int) {
        let at = CGEvent(source: nil)?.location ?? .zero
        switch i {
        case 0, 2:
            let e = CGEvent(scrollWheelEvent2Source: nil, units: .line, wheelCount: 1, wheel1: i == 0 ? 3 : -3, wheel2: 0, wheel3: 0)
            e?.location = at
            e?.post(tap: .cghidEventTap)
        default:
            post(.rightMouseDown, at, button: .right)
            post(.rightMouseUp, at, button: .right)
        }
    }
}

// MARK: - Virtual display

var virtualDisplay: CGVirtualDisplay?

/// Adds a display named "M5 Core2" and asks for the smallest 4:3 HiDPI mode
/// at least `width` points wide. macOS lists modes down to 320x240 but on
/// its own picks 800x600, the smallest it marks usable for the desktop, and
/// may refuse to switch below that.
func makeVirtualDisplay(width: Int) -> CGDirectDisplayID? {
    let d = CGVirtualDisplayDescriptor()
    d.queue = DispatchQueue.main
    d.name = "M5 Core2"
    d.maxPixelsWide = 1600
    d.maxPixelsHigh = 1200
    d.sizeInMillimeters = CGSize(width: 41, height: 31)  // the Core2's 2-inch panel
    d.vendorID = 0x4D35  // "M5"
    d.productID = 0x0140  // 320
    d.serialNum = 2
    d.terminationHandler = { _, _ in log("macOS removed the virtual display") }
    let v = CGVirtualDisplay(descriptor: d)
    let s = CGVirtualDisplaySettings()
    s.hiDPI = 1
    s.modes = [320, 400, 512, 640, 800].map { CGVirtualDisplayMode(width: UInt32($0), height: UInt32($0 * 3 / 4), refreshRate: 30) }
    guard v.apply(s), v.displayID != 0 else { return nil }
    virtualDisplay = v
    let id = v.displayID
    usleep(500_000)
    let opts = [kCGDisplayShowDuplicateLowResolutionModes: true] as CFDictionary
    let modes = (CGDisplayCopyAllDisplayModes(id, opts) as? [CGDisplayMode] ?? [])
        .filter { $0.pixelWidth == 2 * $0.width && $0.width * 3 == $0.height * 4 && $0.width >= width }
        .sorted { $0.width < $1.width }
    for m in modes {
        if CGDisplayCopyDisplayMode(id)?.width == m.width { break }
        var cfg: CGDisplayConfigRef?
        CGBeginDisplayConfiguration(&cfg)
        CGConfigureDisplayWithDisplayMode(cfg, id, m, nil)
        if CGCompleteDisplayConfiguration(cfg, .forSession) == .success { break }
    }
    return id
}

// MARK: - Main

@main
struct M5Mon {
    static func main() async {
        let o = parseOptions()
        if o.setupWiFi { setupWiFi(o); exit(0) }

        if o.touch && !AXIsProcessTrusted() {
            log("touch needs Accessibility access for this terminal app (System Settings > Privacy & Security > Accessibility); until then taps do nothing")
        }

        let s = Streamer(o: o)
        do {
            let l = try connect(o)
            s.attach(l)
        } catch {
            fail("\(error)")
        }

        var wantID: CGDirectDisplayID
        var source: CGRect? = nil
        switch o.source {
        case .virtual:
            guard let id = makeVirtualDisplay(width: o.virtualWidth) else { fail("macOS refused to create the virtual display; try --follow") }
            wantID = id
            log("added display \"M5 Core2\" (id \(id)); arrange it in System Settings > Displays")
        case .display(let n):
            var ids = [CGDirectDisplayID](repeating: 0, count: 16)
            var count: UInt32 = 0
            CGGetActiveDisplayList(16, &ids, &count)
            guard n < count else { fail("there is no display \(n); this Mac has \(count)") }
            wantID = n == 0 ? CGMainDisplayID() : ids[n]
        case .region(let r):
            wantID = CGMainDisplayID()
            source = r
        case .follow(let w):
            wantID = CGMainDisplayID()
            source = CGRect(x: 0, y: 0, width: w, height: w * 3 / 4)
        }

        // A new display takes a moment to show up for capture.
        var display: SCDisplay?
        for _ in 0..<30 {
            do {
                let content = try await SCShareableContent.excludingDesktopWindows(false, onScreenWindowsOnly: true)
                display = content.displays.first { $0.displayID == wantID }
            } catch {
                fail("cannot capture the screen (\(error.localizedDescription)). Allow Screen Recording for this terminal app in System Settings > Privacy & Security, then run again.")
            }
            if display != nil { break }
            try? await Task.sleep(nanoseconds: 200_000_000)
        }
        guard let display else { fail("display \(wantID) is not available for capture") }
        if case .virtual = o.source {
            let b = CGDisplayBounds(wantID)
            log("virtual display is \(Int(b.width))x\(Int(b.height)) points at (\(Int(b.minX)),\(Int(b.minY)))")
        }
        do {
            try await s.start(display: display, source: source)
        } catch {
            fail("cannot start capture: \(error.localizedDescription)")
        }
        log("streaming; Ctrl-C to stop")

        let timer = DispatchSource.makeTimerSource(queue: s.q)
        timer.schedule(deadline: .now(), repeating: .milliseconds(50))
        timer.setEventHandler {
            s.tick()
            if case .follow(let w) = o.source { s.follow(width: w) }
        }
        timer.resume()
        signal(SIGINT) { _ in exit(0) }
        while true { try? await Task.sleep(nanoseconds: 3_600_000_000_000) }
    }
}
