// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "m5mon",
    platforms: [.macOS(.v14)],
    targets: [
        // Declarations for CoreGraphics' private CGVirtualDisplay classes, the
        // same ones DeskPad and BetterDisplay use to add a display macOS
        // treats as real hardware.
        .target(name: "VirtualDisplay", path: "Sources/VirtualDisplay"),
        .executableTarget(
            name: "m5mon",
            dependencies: ["VirtualDisplay"],
            path: "Sources/m5mon",
            linkerSettings: [
                .linkedFramework("ScreenCaptureKit"),
                .linkedFramework("CoreGraphics"),
                .linkedFramework("ImageIO"),
                .linkedFramework("ApplicationServices"),
            ]),
    ]
)
