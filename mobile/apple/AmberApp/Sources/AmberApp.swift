import SwiftUI

@main
struct AmberApp: App {
    var body: some Scene {
        WindowGroup {
            AmberRootView()
                .preferredColorScheme(.light)
        }
        #if os(macOS)
        .defaultSize(width: 1_080, height: 760)
        #endif
    }
}
