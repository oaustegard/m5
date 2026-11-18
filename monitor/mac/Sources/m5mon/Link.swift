// SPDX-License-Identifier: MIT
// Byte transports to the Core2 (TCP or USB serial) and the message framing
// that runs over both. See ../../../main/main.cpp for the wire format.
import Foundation

struct Message {
    let type: UInt8
    let payload: [UInt8]
}

func frame(_ type: Character, _ payload: [UInt8] = []) -> [UInt8] {
    let n = UInt32(payload.count)
    return [0x5A, 0xA5, type.asciiValue!, 0,
            UInt8(n & 0xff), UInt8(n >> 8 & 0xff), UInt8(n >> 16 & 0xff), UInt8(n >> 24)] + payload
}

enum LinkError: Error, CustomStringConvertible {
    case failed(String)
    var description: String { if case .failed(let s) = self { return s }; return "" }
}

/// A file descriptor carrying the framed protocol. Reads run on their own
/// thread and arrive through `onMessage`.
class Link {
    let fd: Int32
    let name: String
    var onMessage: ((Message) -> Void)?
    var onClose: (() -> Void)?
    private let writeLock = NSLock()
    private var closed = false

    init(fd: Int32, name: String) {
        self.fd = fd
        self.name = name
    }

    func start() {
        let t = Thread { [weak self] in self?.readLoop() }
        t.name = "m5mon.read"
        t.start()
    }

    func send(_ bytes: [UInt8]) -> Bool {
        writeLock.lock(); defer { writeLock.unlock() }
        var off = 0
        while off < bytes.count {
            let r = bytes.withUnsafeBytes { write(fd, $0.baseAddress! + off, bytes.count - off) }
            if r < 0 {
                if errno == EINTR || errno == EAGAIN { usleep(500); continue }
                return false
            }
            off += r
        }
        return true
    }

    func close() {
        if closed { return }
        closed = true
        Darwin.close(fd)
    }

    private func readLoop() {
        var buf = [UInt8](repeating: 0, count: 4096)
        var pending: [UInt8] = []
        while true {
            let r = buf.withUnsafeMutableBytes { read(fd, $0.baseAddress!, 4096) }
            if r < 0 && (errno == EINTR || errno == EAGAIN) { usleep(1000); continue }
            if r <= 0 { break }
            pending.append(contentsOf: buf[0..<r])
            // Scan for A5 5A; everything else is console log text from the
            // device (on the serial port) and is skipped.
            var i = 0
            while pending.count - i >= 8 {
                if pending[i] != 0xA5 || pending[i + 1] != 0x5A { i += 1; continue }
                let len = Int(pending[i + 4]) | Int(pending[i + 5]) << 8 | Int(pending[i + 6]) << 16 | Int(pending[i + 7]) << 24
                if len > 4096 { i += 1; continue }
                if pending.count - i < 8 + len { break }
                let m = Message(type: pending[i + 2], payload: Array(pending[(i + 8)..<(i + 8 + len)]))
                i += 8 + len
                onMessage?(m)
            }
            pending.removeFirst(i)
        }
        if !closed { onClose?() }
    }
}

// MARK: - TCP

func connectTCP(host: String, port: Int) throws -> Link {
    var hints = addrinfo(ai_flags: 0, ai_family: AF_INET, ai_socktype: SOCK_STREAM, ai_protocol: 0,
                         ai_addrlen: 0, ai_canonname: nil, ai_addr: nil, ai_next: nil)
    var res: UnsafeMutablePointer<addrinfo>?
    let rc = getaddrinfo(host, String(port), &hints, &res)
    guard rc == 0, let ai = res else {
        throw LinkError.failed("cannot resolve \(host): \(String(cString: gai_strerror(rc)))")
    }
    defer { freeaddrinfo(res) }
    let fd = socket(ai.pointee.ai_family, ai.pointee.ai_socktype, ai.pointee.ai_protocol)
    guard connect(fd, ai.pointee.ai_addr, ai.pointee.ai_addrlen) == 0 else {
        let e = String(cString: strerror(errno))
        Darwin.close(fd)
        throw LinkError.failed("cannot connect to \(host):\(port): \(e)")
    }
    var one: Int32 = 1
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, socklen_t(MemoryLayout<Int32>.size))
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
    var addr = [CChar](repeating: 0, count: 64)
    ai.pointee.ai_addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
        var a = $0.pointee.sin_addr
        inet_ntop(AF_INET, &a, &addr, 64)
    }
    return Link(fd: fd, name: "wifi \(String(cString: addr))")
}

// MARK: - Serial

private let IOSSIOSPEED: UInt = 0x8008_5402  // _IOW('T', 2, speed_t)
private let TIOCMBIC_: UInt = 0x8004_746b    // _IOW('t', 107, int)

func setBaud(_ fd: Int32, _ baud: Int) {
    var speed = speed_t(baud)
    _ = ioctl(fd, IOSSIOSPEED, &speed)
}

func openSerial(path: String) throws -> Link {
    let fd = open(path, O_RDWR | O_NOCTTY | O_NONBLOCK)
    guard fd >= 0 else { throw LinkError.failed("cannot open \(path): \(String(cString: strerror(errno)))") }
    var t = termios()
    tcgetattr(fd, &t)
    cfmakeraw(&t)
    t.c_cflag |= tcflag_t(CLOCAL | CREAD)
    t.c_cflag &= ~tcflag_t(HUPCL)  // do not drop DTR on close: that can reset the ESP32
    cfsetspeed(&t, speed_t(B115200))
    tcsetattr(fd, TCSANOW, &t)
    // DTR and RTS drive the ESP32's reset and boot pins; leave both released.
    var bits: Int32 = TIOCM_DTR | TIOCM_RTS
    _ = ioctl(fd, TIOCMBIC_, &bits)
    _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK)
    tcflush(fd, TCIOFLUSH)
    return Link(fd: fd, name: "usb \(path)")
}

/// Finds the Core2's USB serial port (CP2104 or CH9102).
func findSerialPort() -> String? {
    let names = (try? FileManager.default.contentsOfDirectory(atPath: "/dev")) ?? []
    return names.filter { $0.hasPrefix("cu.usbserial") || $0.hasPrefix("cu.wchusbserial") || $0.hasPrefix("cu.SLAB_USBtoUART") }
        .sorted().first.map { "/dev/" + $0 }
}
