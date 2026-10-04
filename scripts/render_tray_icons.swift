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

    let symbolColor = NSColor(hex: 0xEAF4FF)
    let arrows = NSBezierPath()
    arrows.lineWidth = 4.2
    arrows.lineCapStyle = .round
    arrows.lineJoinStyle = .round
    arrows.move(to: NSPoint(x: 6.5, y: 25))
    arrows.line(to: NSPoint(x: 23.5, y: 25))
    arrows.move(to: NSPoint(x: 17, y: 18.5))
    arrows.line(to: NSPoint(x: 23.5, y: 25))
    arrows.line(to: NSPoint(x: 17, y: 31.5))
    arrows.move(to: NSPoint(x: 40.5, y: 25))
    arrows.line(to: NSPoint(x: 57.5, y: 25))
    arrows.move(to: NSPoint(x: 51, y: 18.5))
    arrows.line(to: NSPoint(x: 57.5, y: 25))
    arrows.line(to: NSPoint(x: 51, y: 31.5))
    symbolColor.setStroke()
    arrows.stroke()

    let square = NSBezierPath(
        roundedRect: NSRect(x: 23.5, y: 16.5, width: 17, height: 17),
        xRadius: 3,
        yRadius: 3
    )
    square.lineWidth = 4.2
    symbolColor.setStroke()
    square.stroke()

    let centers: [CGFloat] = [10, 24.7, 39.3, 54]
    let statusY: CGFloat = 50.5
    for (index, center) in centers.enumerated() {
        NSColor(hex: 0xEAF4FF).setStroke()
        let badge = NSBezierPath(
            ovalIn: NSRect(x: center - 6.5, y: statusY - 8.9, width: 13, height: 17.8)
        )
        badge.lineWidth = 0.8
        badge.stroke()
        palettes[index].1[states[index]]!.setFill()
        NSBezierPath(
            ovalIn: NSRect(x: center - 6.3, y: statusY - 8.5, width: 12.6, height: 17)
        ).fill()
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
