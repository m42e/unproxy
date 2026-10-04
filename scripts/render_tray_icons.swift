import AppKit
import Foundation

let output = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)

let palettes: [(String, [String: NSColor])] = [
    ("service", [
        "running": NSColor(hex: 0x34D399), "stopped": NSColor(hex: 0x64748B), "failed": NSColor(hex: 0xFB7185),
    ]),
    ("pac", [
        "loaded": NSColor(hex: 0x38BDF8), "unloaded": NSColor(hex: 0xFB7185), "unknown": NSColor(hex: 0x64748B),
    ]),
    ("upstream", [
        "ok": NSColor(hex: 0x34D399), "error": NSColor(hex: 0xFB7185), "unknown": NSColor(hex: 0x64748B),
    ]),
    ("auth", [
        "authenticated": NSColor(hex: 0x34D399), "rejected": NSColor(hex: 0xFB7185),
        "configured": NSColor(hex: 0xFBBF24), "disabled": NSColor(hex: 0x64748B),
    ]),
]

func combinations(_ groups: [[String]]) -> [[String]] {
    groups.reduce([[]]) { partial, group in
        partial.flatMap { prefix in group.map { prefix + [$0] } }
    }
}

for states in combinations(palettes.map { Array($0.1.keys).sorted() }) {
    let key = states.joined(separator: "-")
    let image = NSBitmapImageRep(
        bitmapDataPlanes: nil,
        pixelsWide: 128,
        pixelsHigh: 128,
        bitsPerSample: 8,
        samplesPerPixel: 4,
        hasAlpha: true,
        isPlanar: false,
        colorSpaceName: .deviceRGB,
        bytesPerRow: 0,
        bitsPerPixel: 0
    )!
    NSGraphicsContext.saveGraphicsState()
    let graphics = NSGraphicsContext(bitmapImageRep: image)!
    NSGraphicsContext.current = graphics
    graphics.imageInterpolation = .high
    graphics.cgContext.scaleBy(x: 2, y: 2)
    let flip = NSAffineTransform()
    flip.translateX(by: 0, yBy: 64)
    flip.scaleX(by: 1, yBy: -1)
    flip.concat()

    let tile = NSBezierPath(roundedRect: NSRect(x: 2, y: 2, width: 60, height: 60), xRadius: 16, yRadius: 16)
    NSGradient(colors: [NSColor(hex: 0x20386F), NSColor(hex: 0x111D3D)])!.draw(in: tile, angle: 135)

    let route = NSBezierPath()
    route.lineWidth = 5.5
    route.lineCapStyle = .round
    route.lineJoinStyle = .round
    route.move(to: NSPoint(x: 19, y: 13))
    route.line(to: NSPoint(x: 19, y: 26))
    route.curve(to: NSPoint(x: 32, y: 41), controlPoint1: NSPoint(x: 19, y: 35), controlPoint2: NSPoint(x: 24, y: 41))
    route.curve(to: NSPoint(x: 45, y: 26), controlPoint1: NSPoint(x: 40, y: 41), controlPoint2: NSPoint(x: 45, y: 35))
    route.line(to: NSPoint(x: 45, y: 15))
    NSGradient(colors: [NSColor(hex: 0xF5FBFF), NSColor(hex: 0xA9D8FF)])!.draw(in: route, angle: 135)

    let arrow = NSBezierPath()
    arrow.lineWidth = 4.5
    arrow.lineCapStyle = .round
    arrow.lineJoinStyle = .round
    arrow.move(to: NSPoint(x: 38, y: 16))
    arrow.line(to: NSPoint(x: 45, y: 9))
    arrow.line(to: NSPoint(x: 52, y: 16))
    NSColor(hex: 0x55E1C1).setStroke()
    arrow.stroke()
    NSColor(hex: 0x55E1C1).setFill()
    NSBezierPath(ovalIn: NSRect(x: 15.8, y: 9.8, width: 6.4, height: 6.4)).fill()

    let centers: [CGFloat] = [9.5, 24.5, 39.5, 54.5]
    let statusY: CGFloat = 51.5
    for (index, center) in centers.enumerated() {
        NSColor(hex: 0xEAF4FF).setStroke()
        let badge = NSBezierPath(ovalIn: NSRect(x: center - 6.4, y: statusY - 6.4, width: 12.8, height: 12.8))
        badge.lineWidth = 1.4
        badge.stroke()
        palettes[index].1[states[index]]!.setFill()
        NSBezierPath(ovalIn: NSRect(x: center - 5.7, y: statusY - 5.7, width: 11.4, height: 11.4)).fill()
    }

    NSGraphicsContext.restoreGraphicsState()
    let png = image.representation(using: .png, properties: [:])!
    try png.write(to: output.appendingPathComponent("\(key).png"), options: .atomic)
}

extension NSColor {
    convenience init(hex: UInt32) {
        self.init(
            calibratedRed: CGFloat((hex >> 16) & 0xFF) / 255,
            green: CGFloat((hex >> 8) & 0xFF) / 255,
            blue: CGFloat(hex & 0xFF) / 255,
            alpha: 1
        )
    }
}
