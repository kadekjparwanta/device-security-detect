import Foundation
import UIKit
import LocalAuthentication

@objc public class DeviceSecurityDetect: NSObject {
    @objc public func isJailBreak() -> Bool {
        log("Checking if device is jailbroken")
        return hasCydiaInstalled() || isContainsSuspiciousApps() || isSuspiciousSystemPathsExists() || canEditSystemFiles() ||
            canWriteOutsideSandbox() || checkDYLD()
    }

    @objc public func pinCheck() -> Bool {
        log("Checking if PIN or biometric authentication is enabled")
        let context = LAContext()
        var error: NSError?

        if context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) {
            return true
        } else {
            log("Error checking PIN/Biometric authentication: \(error?.localizedDescription ?? "Unknown error")")
            return false
        }
    }
    
    func hasCydiaInstalled() -> Bool {
        return UIApplication.shared.canOpenURL(URL(string: "cydia://")!) ||
               UIApplication.shared.canOpenURL(URL(string: "sileo://")!) ||
               UIApplication.shared.canOpenURL(URL(string: "zbra://")!)
    }
    
    func isContainsSuspiciousApps() -> Bool {
        for path in suspiciousAppsPathToCheck {
            if FileManager.default.fileExists(atPath: path) {
                return true
            }
        }
        return false
    }
    
    func isSuspiciousSystemPathsExists() -> Bool {
        for path in suspiciousSystemPathsToCheck {
            if FileManager.default.fileExists(atPath: path) {
                return true
            }
        }
        return false
    }
    
    func canEditSystemFiles() -> Bool {
        let jailBreakText = "Developer Insider"
        let path = "/private/" + jailBreakText
        
        do {
            try jailBreakText.write(toFile: path, atomically: true, encoding: .utf8)
            try FileManager.default.removeItem(atPath: path)
            return true
        } catch {
            return false
        }
    }

    func canWriteOutsideSandbox() -> Bool {
        do {
            try "sandbox_test".write(toFile: "/private/sandbox_test", atomically: true, encoding: .utf8)
            try FileManager.default.removeItem(atPath: "/private/sandbox_test")
            return true
        } catch {
            return false
        }
    }

    // Alternative to fork() check - checks for suspicious dylibs
    func checkDYLD() -> Bool {
        let suspiciousLibraries = [
            "SubstrateLoader.dylib",
            "libhooker.dylib",
            "SubstrateBootstrap.dylib",
            "libsubstitute.dylib",
            "libellekit.dylib"
        ]
        
        for library in suspiciousLibraries {
            if let _ = dlopen(library, RTLD_NOW) {
                return true
            }
        }
        return false
    }

    var suspiciousAppsPathToCheck: [String] {
        return [
            // Traditional jailbreaks
            "/Applications/Cydia.app",
            "/Applications/blackra1n.app",
            "/Applications/FakeCarrier.app",
            "/Applications/Icy.app",
            "/Applications/IntelliScreen.app",
            "/Applications/MxTube.app",
            "/Applications/RockApp.app",
            "/Applications/SBSettings.app",
            "/Applications/WinterBoard.app",
            
            // Modern jailbreaks
            "/Applications/Palera1n.app",
            "/Applications/Sileo.app",
            "/Applications/Zebra.app",
            "/Applications/TrollStore.app",
            "/var/containers/Bundle/Application/TrollStore.app",
            
            // Checkra1n
            "/Applications/checkra1n.app",
            
            // Rootless jailbreak paths
            "/var/jb/Applications/Cydia.app",
            "/var/jb/Applications/Sileo.app",
            "/var/jb/Applications/Zebra.app"
        ]
    }
        
    var suspiciousSystemPathsToCheck: [String] {
        return [
            // Traditional paths
            "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
            "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
            "/private/var/lib/apt",
            "/private/var/lib/cydia",
            "/private/var/mobile/Library/SBSettings/Themes",
            "/private/var/stash",
            "/private/var/tmp/cydia.log",
            "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
            "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
            "/usr/bin/sshd",
            "/usr/libexec/sftp-server",
            "/usr/sbin/sshd",
            "/etc/apt",
            "/bin/bash",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            
            // Modern jailbreak paths
            "/var/jb", // Rootless jailbreak root
            "/var/binpack", // Checkm8 jailbreak
            "/var/containers/Bundle/tweaksupport",
            "/var/mobile/Library/palera1n",
            "/var/mobile/Library/xyz.willy.Zebra",
            "/var/lib/undecimus",
            
            // Palera1n specific
            "/var/jb/basebin",
            "/var/jb/usr",
            "/var/jb/etc",
            "/var/jb/Library",
            "/var/jb/.installed_palera1n",
            "/var/binpack/Applications",
            "/var/binpack/usr",
            
            // TrollStore
            "/var/containers/Bundle/Application/trollstorehelper",
            "/var/containers/Bundle/trollstore",
            
            // Bootstrap files
            "/var/jb/preboot",
            "/var/jb/var"
        ]
    }
}
