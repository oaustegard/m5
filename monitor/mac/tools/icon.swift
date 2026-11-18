// Draws the app icon: a small monitor on an M5-orange tile. Writes icon_1024.png.
import AppKit
let size = 1024.0
let img = NSImage(size: NSSize(width: size, height: size))
img.lockFocus()
NSColor(red: 0.96, green: 0.45, blue: 0.13, alpha: 1).setFill()
NSBezierPath(roundedRect: NSRect(x: 100, y: 100, width: 824, height: 824), xRadius: 185, yRadius: 185).fill()
NSColor(white: 0.15, alpha: 1).setFill()
NSBezierPath(roundedRect: NSRect(x: 232, y: 380, width: 560, height: 420), xRadius: 40, yRadius: 40).fill()
NSColor(red: 0.2, green: 0.45, blue: 0.95, alpha: 1).setFill()
NSBezierPath(rect: NSRect(x: 268, y: 416, width: 488, height: 348)).fill()
NSColor(white: 0.15, alpha: 1).setFill()
NSBezierPath(rect: NSRect(x: 472, y: 290, width: 80, height: 92)).fill()
NSBezierPath(roundedRect: NSRect(x: 382, y: 250, width: 260, height: 50), xRadius: 25, yRadius: 25).fill()
img.unlockFocus()
let rep = NSBitmapImageRep(data: img.tiffRepresentation!)!
try! rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: CommandLine.arguments[1]))
