// SPDX-License-Identifier: MIT
// Turns 320x240 BGRA captures into rectangle updates: only rows bands that
// changed are sent, each as raw-deflated RGB565 (lossless, small for UI) or
// JPEG (for photos and video), whichever is smaller by enough.
import Compression
import CoreGraphics
import Foundation
import ImageIO
import UniformTypeIdentifiers

let screenW = 320, screenH = 240

struct Rect: Equatable {
    var x, y, w, h: Int
    var isEmpty: Bool { w <= 0 || h <= 0 }
    func union(_ o: Rect) -> Rect {
        if isEmpty { return o }
        if o.isEmpty { return self }
        let x0 = min(x, o.x), y0 = min(y, o.y)
        return Rect(x: x0, y: y0, w: max(x + w, o.x + o.w) - x0, h: max(y + h, o.y + o.h) - y0)
    }
    static let zero = Rect(x: 0, y: 0, w: 0, h: 0)
}

enum Encoding: UInt8 { case raw = 0, deflate = 1, jpeg = 2 }

struct Update {
    let rect: Rect
    let encoding: Encoding
    let data: [UInt8]
}

final class FrameEncoder {
    /// What the device is showing, as RGB565.
    private var shown = [UInt16](repeating: 0, count: screenW * screenH)
    private var current = [UInt16](repeating: 0, count: screenW * screenH)
    private var bgra = [UInt8](repeating: 0, count: screenW * screenH * 4)
    private var first = true
    /// Area last sent as JPEG, which a later lossless pass sharpens.
    private(set) var lossy = Rect.zero
    var jpegQuality: Double = 0.7
    var allowJPEG = true
    var jpegRatio = 3.0
    var stats = (bytes: 0, rects: 0)

    func forceFull() { first = true }

    /// Loads a capture. `base` points at BGRA rows of `stride` bytes.
    func load(base: UnsafeRawPointer, stride: Int) {
        for y in 0..<screenH {
            let row = base + y * stride
            memcpy(&bgra[y * screenW * 4], row, screenW * 4)
            let p = row.assumingMemoryBound(to: UInt8.self)
            for x in 0..<screenW {
                let b = UInt16(p[x * 4]), g = UInt16(p[x * 4 + 1]), r = UInt16(p[x * 4 + 2])
                current[y * screenW + x] = (r >> 3) << 11 | (g >> 2) << 5 | (b >> 3)
            }
        }
    }

    /// Changed areas as a few rectangles: rows are grouped into 16-pixel
    /// bands, consecutive changed bands merge, and each run is trimmed to
    /// the columns that changed.
    func dirtyRects() -> [Rect] {
        if first {
            first = false
            return [Rect(x: 0, y: 0, w: screenW, h: screenH)]
        }
        let band = 16
        var rects: [Rect] = []
        var run: Rect? = nil
        for by in Swift.stride(from: 0, to: screenH, by: band) {
            var x0 = screenW, x1 = -1, y0 = screenH, y1 = -1
            for y in by..<min(by + band, screenH) {
                let o = y * screenW
                var rowChanged = false
                for x in 0..<screenW where current[o + x] != shown[o + x] {
                    if x < x0 { x0 = x }
                    if x > x1 { x1 = x }
                    rowChanged = true
                }
                if rowChanged { y0 = min(y0, y); y1 = y }
            }
            if x1 >= 0 {
                let r = Rect(x: x0, y: y0, w: x1 - x0 + 1, h: y1 - y0 + 1)
                // A run only continues through consecutive changed bands.
                run = run.map { $0.union(r) } ?? r
            } else if let cur = run {
                rects.append(cur)
                run = nil
            }
        }
        if let cur = run { rects.append(cur) }
        return rects
    }

    /// Encodes one rectangle from the current capture and marks it shown.
    func encode(_ r: Rect, lossless: Bool = false) -> Update {
        var raw = [UInt8](repeating: 0, count: r.w * r.h * 2)
        var i = 0
        for y in r.y..<(r.y + r.h) {
            for x in r.x..<(r.x + r.w) {
                let v = current[y * screenW + x]
                raw[i] = UInt8(v >> 8); raw[i + 1] = UInt8(v & 0xff)
                i += 2
                shown[y * screenW + x] = v
            }
        }
        let z = deflate(raw)
        var best = Update(rect: r, encoding: .raw, data: raw)
        if let z, z.count < raw.count { best = Update(rect: r, encoding: .deflate, data: z) }
        // JPEG costs sharpness and takes the ESP32 longer to decode than
        // inflate does, so it has to be a lot smaller to win: `jpegRatio`
        // times (3 over WiFi, 1.5 over the much slower serial link).
        if !lossless && allowJPEG && best.data.count > 6000, let j = jpeg(r),
           Double(j.count) * jpegRatio < Double(best.data.count) {
            best = Update(rect: r, encoding: .jpeg, data: j)
            lossy = lossy.union(r)
        }
        stats.bytes += best.data.count
        stats.rects += 1
        return best
    }

    /// The lossless re-send of what went out as JPEG, once things are still.
    func sharpen() -> Update? {
        guard !lossy.isEmpty else { return nil }
        let r = lossy
        lossy = .zero
        return encode(r, lossless: true)
    }

    private func deflate(_ src: [UInt8]) -> [UInt8]? {
        var dst = [UInt8](repeating: 0, count: src.count + 1024)
        // COMPRESSION_ZLIB is raw DEFLATE (no zlib header), which is what
        // the ESP32 ROM's tinfl expects with flags 0.
        let n = compression_encode_buffer(&dst, dst.count, src, src.count, nil, COMPRESSION_ZLIB)
        return n > 0 ? Array(dst[0..<n]) : nil
    }

    private func jpeg(_ r: Rect) -> [UInt8]? {
        var crop = [UInt8](repeating: 0, count: r.w * r.h * 4)
        for y in 0..<r.h {
            let src = ((r.y + y) * screenW + r.x) * 4
            crop.replaceSubrange((y * r.w * 4)..<((y + 1) * r.w * 4), with: bgra[src..<(src + r.w * 4)])
        }
        guard let provider = CGDataProvider(data: Data(crop) as CFData),
              let img = CGImage(width: r.w, height: r.h, bitsPerComponent: 8, bitsPerPixel: 32, bytesPerRow: r.w * 4,
                                space: CGColorSpaceCreateDeviceRGB(),
                                bitmapInfo: CGBitmapInfo(rawValue: CGImageAlphaInfo.noneSkipFirst.rawValue | CGBitmapInfo.byteOrder32Little.rawValue),
                                provider: provider, decode: nil, shouldInterpolate: false, intent: .defaultIntent)
        else { return nil }
        let out = NSMutableData()
        guard let dest = CGImageDestinationCreateWithData(out, UTType.jpeg.identifier as CFString, 1, nil) else { return nil }
        // Baseline, 4:2:0: what the device's TJpgDec decodes.
        CGImageDestinationAddImage(dest, img, [kCGImageDestinationLossyCompressionQuality: jpegQuality] as CFDictionary)
        guard CGImageDestinationFinalize(dest) else { return nil }
        return [UInt8](out as Data)
    }
}
