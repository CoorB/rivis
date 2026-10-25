import AppKit
import WebKit

private final class ErrorBuffer: @unchecked Sendable {
    private let lock = NSLock()
    private var data = Data()

    func store(_ value: Data) { lock.lock(); data = value; lock.unlock() }
    func read() -> Data { lock.lock(); defer { lock.unlock() }; return data }
}

final class RivisApp: NSObject, NSApplicationDelegate, WKNavigationDelegate, WKUIDelegate, WKDownloadDelegate {
    private var window: NSWindow!
    private var webView: WKWebView!
    private var cli: String?
    var allowedPort: Int?
    private var generation = 0
    private var downloads: [ObjectIdentifier: URL] = [:]

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        let configuration = WKWebViewConfiguration()
        configuration.defaultWebpagePreferences.allowsContentJavaScript = true
        webView = WKWebView(frame: .zero, configuration: configuration)
        webView.navigationDelegate = self
        webView.uiDelegate = self
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1280, height: 820),
                          styleMask: [.titled, .closable, .miniaturizable, .resizable],
                          backing: .buffered, defer: false)
        window.title = "Rivis"
        window.minSize = NSSize(width: 900, height: 600)
        window.contentView = webView
        window.center()
        window.setFrameAutosaveName("RivisMainWindow")
        buildMenu()
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        loadLogin()
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows: Bool) -> Bool {
        if !hasVisibleWindows {
            window.makeKeyAndOrderFront(nil)
            loadLogin()
        }
        return true
    }

    nonisolated private func findCLI() -> String? {
        let manager = FileManager.default
        if let override = ProcessInfo.processInfo.environment["RIVIS_CLI"],
           manager.isExecutableFile(atPath: override) { return override }
        // `rivis app` passes RIVIS_CLI; otherwise the installer's launcher, a source checkout's ~/bin link, Homebrew
        for candidate in ["~/.local/bin/rivis", "~/bin/rivis", "/opt/homebrew/bin/rivis", "/usr/local/bin/rivis"] {
            let path = (candidate as NSString).expandingTildeInPath
            if manager.isExecutableFile(atPath: path) { return path }
        }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/zsh")
        process.arguments = ["-lc", "whence -p rivis"]   // the file on PATH, even when rivis is also an alias
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()
        do {
            try process.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            let path = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            return process.terminationStatus == 0 && manager.isExecutableFile(atPath: path) ? path : nil
        } catch { return nil }
    }

    nonisolated func runCLI(_ args: [String], using cli: String) -> (Int32, String, String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: cli)
        process.arguments = args
        let output = Pipe(), errors = Pipe()
        process.standardOutput = output
        process.standardError = errors
        do {
            try process.run()
            let errorGroup = DispatchGroup()
            errorGroup.enter()
            let stderr = ErrorBuffer()
            DispatchQueue.global(qos: .userInitiated).async {
                stderr.store(errors.fileHandleForReading.readDataToEndOfFile())
                errorGroup.leave()
            }
            let stdout = output.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            errorGroup.wait()
            return (process.terminationStatus,
                    String(data: stdout, encoding: .utf8) ?? "",
                    String(data: stderr.read(), encoding: .utf8) ?? "")
        } catch { return (1, "", error.localizedDescription) }
    }

    private func loadLogin() {
        generation += 1
        let current = generation
        requestLogin(current, retries: 0)
    }

    private func requestLogin(_ current: Int, retries: Int) {
        let currentCLI = cli
        DispatchQueue.global(qos: .userInitiated).async {
            let selectedCLI = currentCLI ?? self.findCLI()
            let result = selectedCLI.map { self.runCLI(["ui", "--new", "--url"], using: $0) }
                ?? (1, "", "Rivis CLI was not found. Set RIVIS_CLI or install rivis in ~/.local/bin.")
            DispatchQueue.main.async {
                guard self.generation == current else { return }
                self.cli = selectedCLI
                if result.0 == 0, let url = URL(string: result.1.trimmingCharacters(in: .whitespacesAndNewlines)),
                   self.isLocal(url), url.path.hasPrefix("/proxy/bootstrap/") {
                    self.allowedPort = url.port
                    self.window.contentView = self.webView
                    self.webView.load(URLRequest(url: url))
                } else if result.2.contains("not running") && retries == 0 {
                    self.showProblem("Rivis is not running.", canStart: true)
                } else if result.2.contains("not running") && retries < 30 {
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1) { [weak self] in
                        guard let self = self, self.generation == current else { return }
                        self.requestLogin(current, retries: retries + 1)
                    }
                } else {
                    self.showProblem(result.2.isEmpty ? "Could not get the Rivis login link: \(result.1)" : result.2, canStart: false)
                }
            }
        }
    }

    private func showProblem(_ message: String, canStart: Bool) {
        let stack = NSStackView()
        stack.orientation = .vertical
        stack.alignment = .centerX
        stack.spacing = 16
        let label = NSTextField(wrappingLabelWithString: message)
        label.alignment = .center
        label.maximumNumberOfLines = 0
        stack.addArrangedSubview(label)
        if canStart {
            let button = NSButton(title: "Start Rivis", target: self, action: #selector(startRivis(_:)))
            stack.addArrangedSubview(button)
        }
        let box = NSView(frame: window.contentView?.bounds ?? .zero)
        stack.translatesAutoresizingMaskIntoConstraints = false
        box.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.centerXAnchor.constraint(equalTo: box.centerXAnchor),
            stack.centerYAnchor.constraint(equalTo: box.centerYAnchor),
            stack.widthAnchor.constraint(lessThanOrEqualTo: box.widthAnchor, multiplier: 0.8)
        ])
        window.contentView = box
    }

    @objc private func startRivis(_ sender: Any?) {
        guard let cli else { return }
        let log = ("~/Library/Logs/Rivis-app.log" as NSString).expandingTildeInPath
        do {
            try FileManager.default.createDirectory(at: URL(fileURLWithPath: log).deletingLastPathComponent(),
                                                    withIntermediateDirectories: true)
            if !FileManager.default.fileExists(atPath: log) { FileManager.default.createFile(atPath: log, contents: nil) }
            let handle = try FileHandle(forWritingTo: URL(fileURLWithPath: log))
            handle.seekToEndOfFile()
            let process = Process()
            process.executableURL = URL(fileURLWithPath: cli)
            process.arguments = ["start"]
            process.standardOutput = handle
            process.standardError = handle
            try process.run()
            generation += 1
            requestLogin(generation, retries: 1)
        } catch { showProblem("Could not start Rivis: \(error.localizedDescription)", canStart: true) }
    }

    private func isLocal(_ url: URL) -> Bool {
        url.scheme == "http" && (url.host == "127.0.0.1" || url.host == "localhost") && url.port != nil
    }

    private func isAllowed(_ url: URL) -> Bool { isLocal(url) && url.port == allowedPort }

    func canChooseFile(from url: URL?) -> Bool { url.map(isAllowed) ?? false }

    func shouldDownloadResponse(disposition: String, canShowMIMEType: Bool) -> Bool {
        disposition.trimmingCharacters(in: .whitespacesAndNewlines).lowercased().hasPrefix("attachment")
            || !canShowMIMEType
    }

    func isAllowedBlob(_ url: URL) -> Bool {
        guard url.scheme == "blob", url.absoluteString.hasPrefix("blob:"),
              let origin = URL(string: String(url.absoluteString.dropFirst(5))) else { return false }
        return isAllowed(origin)
    }

    func canOpenExternalLink(_ url: URL, activated: Bool) -> Bool {
        activated && (url.scheme == "http" || url.scheme == "https")
    }

    private func openExternalLink(_ url: URL) {
        NSWorkspace.shared.open(url)
    }

    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction,
                 decisionHandler: @escaping @MainActor @Sendable (WKNavigationActionPolicy) -> Void) {
        guard let url = navigationAction.request.url else { decisionHandler(.cancel); return }
        // the page saves HAR files and code through <a download> on a blob: URL
        if isAllowedBlob(url) || (navigationAction.shouldPerformDownload && isAllowed(url)) {
            decisionHandler(.download); return
        }
        if isAllowed(url) { decisionHandler(.allow); return }
        if navigationAction.targetFrame?.isMainFrame == true
            && canOpenExternalLink(url, activated: navigationAction.navigationType == .linkActivated) {
            openExternalLink(url)
        }
        decisionHandler(.cancel)
    }

    func webView(_ webView: WKWebView, decidePolicyFor navigationResponse: WKNavigationResponse,
                 decisionHandler: @escaping @MainActor @Sendable (WKNavigationResponsePolicy) -> Void) {
        let disposition = (navigationResponse.response as? HTTPURLResponse)?.value(forHTTPHeaderField: "Content-Disposition") ?? ""
        if shouldDownloadResponse(disposition: disposition, canShowMIMEType: navigationResponse.canShowMIMEType) {
            decisionHandler(.download)
        }
        else { decisionHandler(.allow) }
    }

    // <input type="file"> (HAR import, Map Local files): WebKit shows no picker unless the app opens one
    func webView(_ webView: WKWebView, runOpenPanelWith parameters: WKOpenPanelParameters,
                 initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping @MainActor @Sendable ([URL]?) -> Void) {
        let panel = NSOpenPanel()
        guard canChooseFile(from: frame.request.url) else { completionHandler(nil); return }
        panel.allowsMultipleSelection = parameters.allowsMultipleSelection
        panel.canChooseDirectories = parameters.allowsDirectories
        panel.canChooseFiles = true
        panel.beginSheetModal(for: window) { [weak panel] result in
            completionHandler(result == .OK ? panel?.urls : nil)
        }
    }

    func webView(_ webView: WKWebView, createWebViewWith configuration: WKWebViewConfiguration,
                 for navigationAction: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? {
        if let url = navigationAction.request.url {
            if isAllowed(url) || isAllowedBlob(url) { webView.load(URLRequest(url: url)) }
            else if canOpenExternalLink(url, activated: navigationAction.navigationType == .linkActivated) {
                openExternalLink(url)
            }
        }
        return nil
    }

    func webView(_ webView: WKWebView, navigationAction: WKNavigationAction,
                 didBecome download: WKDownload) { download.delegate = self }

    func webView(_ webView: WKWebView, navigationResponse: WKNavigationResponse,
                 didBecome download: WKDownload) { download.delegate = self }

    func download(_ download: WKDownload, decideDestinationUsing response: URLResponse,
                  suggestedFilename: String, completionHandler: @escaping @MainActor @Sendable (URL?) -> Void) {
        guard let folder = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first,
              (try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)) != nil else {
            completionHandler(nil)
            return
        }
        let target = destination(for: suggestedFilename, in: folder, reserved: Array(downloads.values))
        downloads[ObjectIdentifier(download)] = target
        completionHandler(target)
    }

    func destination(for suggestedFilename: String, in folder: URL, reserved: [URL]) -> URL {
        let candidate = suggestedFilename.isEmpty ? "" : URL(fileURLWithPath: suggestedFilename).lastPathComponent
        let safeName = candidate.isEmpty || candidate == "." || candidate == ".." ? "Download" : candidate
        let base = (safeName as NSString).deletingPathExtension
        let ext = (safeName as NSString).pathExtension
        var target = folder.appendingPathComponent(safeName)
        var index = 2
        while FileManager.default.fileExists(atPath: target.path) || reserved.contains(target) {
            let name = ext.isEmpty ? "\(base) \(index)" : "\(base) \(index).\(ext)"
            target = folder.appendingPathComponent(name)
            index += 1
        }
        return target
    }

    func downloadDidFinish(_ download: WKDownload) {
        if let url = downloads.removeValue(forKey: ObjectIdentifier(download)) {
            NSWorkspace.shared.activateFileViewerSelecting([url])
        }
    }

    func download(_ download: WKDownload, didFailWithError error: Error, resumeData: Data?) {
        downloads.removeValue(forKey: ObjectIdentifier(download))
        let alert = NSAlert()
        alert.messageText = "Download failed"
        alert.informativeText = error.localizedDescription
        alert.beginSheetModal(for: window)
    }

    private func menu(_ title: String) -> NSMenu {
        let root = NSMenuItem()
        let submenu = NSMenu(title: title)
        root.submenu = submenu
        NSApp.mainMenu?.addItem(root)
        return submenu
    }

    private func add(_ title: String, to menu: NSMenu, action: Selector, key: String = "",
                     modifiers: NSEvent.ModifierFlags = [.command], represented: String? = nil) {
        let item = NSMenuItem(title: title, action: action, keyEquivalent: key)
        item.keyEquivalentModifierMask = modifiers
        item.target = represented == nil ? nil : self
        item.representedObject = represented
        menu.addItem(item)
    }

    private func command(_ title: String, _ id: String, to menu: NSMenu, key: String = "",
                         modifiers: NSEvent.ModifierFlags = [.command]) {
        add(title, to: menu, action: #selector(sendCommand(_:)), key: key, modifiers: modifiers, represented: id)
    }

    @objc private func sendCommand(_ sender: NSMenuItem) {
        guard let id = sender.representedObject as? String else { return }
        webView.evaluateJavaScript("document.dispatchEvent(new CustomEvent('rivis-command',{detail:'\(id)'}))")
    }

    @objc private func reload(_ sender: Any?) { webView.reload() }
    @objc private func actualSize(_ sender: Any?) { webView.pageZoom = 1 }
    @objc private func zoomIn(_ sender: Any?) { webView.pageZoom += 0.1 }
    @objc private func zoomOut(_ sender: Any?) { webView.pageZoom = max(0.5, webView.pageZoom - 0.1) }
    @objc private func help(_ sender: Any?) {
        guard let cli else { return }
        let real = URL(fileURLWithPath: cli).resolvingSymlinksInPath()
        let readme = real.deletingLastPathComponent().appendingPathComponent("README.md")
        if FileManager.default.fileExists(atPath: readme.path) { NSWorkspace.shared.open(readme) }
    }

    private func buildMenu() {
        NSApp.mainMenu = NSMenu()
        let app = menu("Rivis")
        add("About Rivis", to: app, action: #selector(NSApplication.orderFrontStandardAboutPanel(_:)))
        app.addItem(.separator())
        add("Hide Rivis", to: app, action: #selector(NSApplication.hide(_:)), key: "h")
        add("Quit Rivis", to: app, action: #selector(NSApplication.terminate(_:)), key: "q")

        let edit = menu("Edit")
        add("Undo", to: edit, action: Selector(("undo:")), key: "z")
        add("Redo", to: edit, action: Selector(("redo:")), key: "z", modifiers: [.command, .shift])
        edit.addItem(.separator())
        add("Cut", to: edit, action: #selector(NSText.cut(_:)), key: "x")
        add("Copy", to: edit, action: #selector(NSText.copy(_:)), key: "c")
        add("Paste", to: edit, action: #selector(NSText.paste(_:)), key: "v")
        add("Select All", to: edit, action: #selector(NSText.selectAll(_:)), key: "a")

        let view = menu("View")
        add("Reload Page", to: view, action: #selector(reload(_:)), key: "r", represented: "reload")
        command("Classic View", "classic", to: view)
        view.addItem(.separator())
        add("Actual Size", to: view, action: #selector(actualSize(_:)), key: "0", represented: "zoom")
        add("Zoom In", to: view, action: #selector(zoomIn(_:)), key: "+", represented: "zoom")
        let zoomEquals = NSMenuItem(title: "Zoom In", action: #selector(zoomIn(_:)), keyEquivalent: "=")
        zoomEquals.target = self; zoomEquals.isAlternate = false; zoomEquals.isHidden = true; zoomEquals.allowsKeyEquivalentWhenHidden = true
        view.addItem(zoomEquals)
        add("Zoom Out", to: view, action: #selector(zoomOut(_:)), key: "-", represented: "zoom")
        add("Enter Full Screen", to: view, action: #selector(NSWindow.toggleFullScreen(_:)), key: "f", modifiers: [.command, .control])

        let capture = menu("Capture")
        command("Record/Pause", "record", to: capture)
        command("Clear", "clear", to: capture, key: String(UnicodeScalar(0x7f)!), modifiers: [.command, .shift])
        command("Auto-select Latest", "follow", to: capture, key: "l", modifiers: [.command, .shift])
        command("Filter", "filter", to: capture, key: "f", modifiers: [.command, .option])
        command("Add Source", "sources", to: capture, key: "k")

        let tools = menu("Tools")
        command("Map Local", "map", to: tools, key: "l", modifiers: [.command, .option])
        command("Map Remote", "remote", to: tools, key: "r", modifiers: [.command, .option])
        command("Breakpoint", "bp", to: tools, key: "b", modifiers: [.command, .option])
        command("Block List", "block", to: tools, key: "x", modifiers: [.command, .option])
        command("No Caching", "nocache", to: tools, key: "n", modifiers: [.command, .option])
        command("Scripting", "scripts", to: tools)
        command("Network", "net", to: tools)
        command("Allow List", "allow", to: tools, key: "a", modifiers: [.command, .option])

        let windows = menu("Window")
        add("Minimize", to: windows, action: #selector(NSWindow.performMiniaturize(_:)), key: "m")
        add("Zoom", to: windows, action: #selector(NSWindow.performZoom(_:)))
        add("Bring All to Front", to: windows, action: #selector(NSApplication.arrangeInFront(_:)))
        let helpMenu = menu("Help")
        add("Rivis Help", to: helpMenu, action: #selector(help(_:)), represented: "help")
    }
}

#if !RIVIS_TEST
let app = NSApplication.shared
let delegate = RivisApp()
app.delegate = delegate
app.run()
#endif
