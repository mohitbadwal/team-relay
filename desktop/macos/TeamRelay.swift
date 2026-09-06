import AppKit
import ServiceManagement

// A native, local-only UI. The helper receives structured input over stdin;
// neither invitations nor approval credentials appear in arguments or URLs.
final class RelayApp: NSObject, NSApplicationDelegate, NSMenuDelegate {
    var item: NSStatusItem!
    var setupWindow: NSWindow?
    var textWindows: [String: NSWindow] = [:]
    var popup: NSPanel?
    var displayedRequestID: String?
    var timer: Timer?
    var polling = false
    var running = false
    var busy = false
    var enrolled = false
    var pending: [[String: Any]] = []
    var seen = Set<String>()
    var info: [String: Any] = [:]
    var setupBusy = false
    var menuTracking = false
    var menuSignature = ""
    var joinPage: NSStackView?
    var agentPage: NSStackView?
    var advancedPage: NSStackView?

    let serverField = NSTextField(string: "")
    let inviteField = NSSecureTextField(string: "")
    let nameField = NSTextField(string: "")
    let runtimeChoice = NSPopUpButton()
    let folderField = NSTextField(string: "")
    let permissionChoice = NSPopUpButton()
    let modelField = NSTextField(string: "")
    let filesCheck = NSButton(checkboxWithTitle: "Let my agent send files from this folder", target: nil, action: nil)
    let loginCheck = NSButton(checkboxWithTitle: "Open Team Relay at login", target: nil, action: nil)
    let connectButton = NSButton(title: "Connect", target: nil, action: nil)
    let setupMessage = NSTextField(wrappingLabelWithString: "")

    var helper: String { Bundle.main.resourceURL!.appendingPathComponent("team-relay").path }
    var serviceConfig: String { Bundle.main.object(forInfoDictionaryKey: "TeamRelayServiceConfig") as? String ?? "" }

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Finder/open should reveal the existing app, not create another poller.
        if let other = NSRunningApplication.runningApplications(withBundleIdentifier: Bundle.main.bundleIdentifier ?? "io.teamrelay.desktop").first(where: { $0.processIdentifier != ProcessInfo.processInfo.processIdentifier }) {
            other.activate(options: [.activateAllWindows]); NSApp.terminate(nil); return
        }
        NSApp.setActivationPolicy(.accessory)
        item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        item.button?.title = "TR"
        item.button?.toolTip = "Team Relay"
        let mainMenu = NSMenu(), applicationMenu = NSMenu(), rootItem = NSMenuItem()
        let quitItem = NSMenuItem(title: "Quit Team Relay", action: #selector(quit), keyEquivalent: "q")
        quitItem.target = self; applicationMenu.addItem(quitItem); rootItem.submenu = applicationMenu; mainMenu.addItem(rootItem)
        NSApp.mainMenu = mainMenu
        rebuildMenu()
        call(["info"]) { result in
            switch result {
            case .success(let data):
                self.info = data as? [String: Any] ?? [:]
                self.enrolled = self.info["enrolled"] as? Bool ?? false
                self.rebuildMenu()
                if !self.enrolled || !UserDefaults.standard.bool(forKey: "setupCompleted") { self.showSetup() }
                self.refresh()
            case .failure(let error): self.showError(error.localizedDescription)
            }
        }
        timer = Timer.scheduledTimer(withTimeInterval: 4, repeats: true) { _ in self.refresh() }
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if let notice = pending.first { showApproval(notice) }
        else if enrolled && UserDefaults.standard.bool(forKey: "setupCompleted") { item.button?.performClick(nil) }
        else { showSetup() }
        return true
    }

    func call(_ arguments: [String], input: [String: Any]? = nil, completion: @escaping (Result<Any, Error>) -> Void) {
        let executable = helper, configuration = serviceConfig
        DispatchQueue.global(qos: .userInitiated).async {
            let process = Process(), output = Pipe(), stdin = Pipe()
            process.executableURL = URL(fileURLWithPath: executable)
            process.arguments = ["app", "--service-config", configuration] + arguments
            process.standardOutput = output; process.standardError = output
            process.standardInput = stdin
            // Finder does not inherit a shell's PATH. Keep common agent install
            // locations available without executing a login shell or rc files.
            var env = ProcessInfo.processInfo.environment.filter { !$0.key.hasPrefix("TEAM_RELAY_") }
            let home = FileManager.default.homeDirectoryForCurrentUser.path
            env["PATH"] = [home+"/.local/bin", "/opt/homebrew/bin", "/usr/local/bin", env["PATH"] ?? "/usr/bin:/bin:/usr/sbin:/sbin"].joined(separator: ":")
            process.environment = env
            do {
                try process.run()
                if let input = input { stdin.fileHandleForWriting.write(try JSONSerialization.data(withJSONObject: input)) }
                try stdin.fileHandleForWriting.close()
                let payload = output.fileHandleForReading.readDataToEndOfFile()
                process.waitUntilExit()
                guard let reply = try? JSONSerialization.jsonObject(with: payload) as? [String: Any] else {
                    throw NSError(domain: "TeamRelay", code: 1, userInfo: [NSLocalizedDescriptionKey: String(data: payload, encoding: .utf8) ?? "Team Relay could not read the helper response."])
                }
                guard reply["ok"] as? Bool == true else {
                    throw NSError(domain: "TeamRelay", code: 1, userInfo: [NSLocalizedDescriptionKey: reply["error"] as? String ?? "Team Relay could not complete the action."])
                }
                DispatchQueue.main.async { completion(.success(reply["data"] ?? [:])) }
            } catch { DispatchQueue.main.async { completion(.failure(error)) } }
        }
    }

    func refresh() {
        // A removed disposable test bundle or uninstalled app must not remain
        // behind as a menu-bar poller with no working helper.
        if !FileManager.default.fileExists(atPath: helper) { NSApp.terminate(nil); return }
        guard enrolled && !polling && !setupBusy else { return }
        polling = true
        call(["status"]) { result in
            guard case .success(let value) = result, let status = value as? [String: Any] else {
                self.polling = false; self.running = false; self.rebuildMenu(); return
            }
            self.running = status["running"] as? Bool ?? false
            if !self.running { self.polling = false; self.busy = false; self.pending = []; self.popup?.close(); self.rebuildMenu(); return }
            self.call(["pending"]) { result in
                self.polling = false
                switch result {
                case .success(let value):
                    self.busy = false
                    let records = (value as? [String: Any])?["requests"] as? [[String: Any]] ?? []
                    self.pending = records.compactMap { $0["notice"] as? [String: Any] }.filter { $0["status"] as? String == "awaiting_approval" }
                    if let shown = self.displayedRequestID, !self.pending.contains(where: { $0["request_id"] as? String == shown }) { self.popup?.close(); self.displayedRequestID = nil }
                    if self.popup?.isVisible != true, let notice = self.pending.first(where: { !self.seen.contains($0["request_id"] as? String ?? "") }) {
                        self.seen.insert(notice["request_id"] as? String ?? "")
                        self.showApproval(notice)
                    }
                    if self.pending.isEmpty { self.popup?.close() }
                case .failure(let error):
                    // The daemon intentionally locks sensitive approval reads
                    // during execution; don't bypass that guard for the UI.
                    self.busy = error.localizedDescription.contains("while a teammate runtime is active")
                    if self.busy { self.pending = []; self.popup?.close() }
                }
                self.rebuildMenu()
            }
        }
    }

    func rebuildMenu() {
        guard !menuTracking else { return }
        let signature = "\(running)/\(busy)/\(pending.count)/\(enrolled)"
        guard signature != menuSignature else { return }
        menuSignature = signature
        item.button?.title = busy ? "TR · 1" : (pending.isEmpty ? "TR" : "TR · \(pending.count)")
        let menu = NSMenu()
        let status = busy ? "Working on a teammate request" : (running ? "Connection running" : (enrolled ? "Connection stopped" : "Not connected to a team"))
        menu.addItem(withTitle: status, action: nil, keyEquivalent: "")
        menu.addItem(NSMenuItem.separator())
        add(menu, "Requests\(pending.isEmpty ? "" : " (\(pending.count))")…", #selector(showRequests))
        add(menu, "Teammates…", #selector(showTeammates))
        add(menu, "How to send a request…", #selector(showSendHelp))
        add(menu, "Approvals I’ve saved…", #selector(showGrants))
        menu.addItem(NSMenuItem.separator())
        add(menu, running ? "Stop connection…" : "Start connection", running ? #selector(stopConnection) : #selector(startConnection))
        add(menu, "Restart connection…", #selector(restartConnection))
        add(menu, "Activity and logs…", #selector(showLogs))
        add(menu, "Check setup…", #selector(checkSetup))
        add(menu, enrolled ? "Setup and repair…" : "Connect to your team…", #selector(showSetup))
        menu.addItem(NSMenuItem.separator())
        add(menu, "Quit menu-bar app", #selector(quit))
        menu.items.last?.keyEquivalent = "q"
        menu.delegate = self
        item.menu = menu
        // Expose the same controls to keyboard/accessibility users when a
        // regular window is open, not only through the tiny status-bar icon.
        if let appMenu = NSApp.mainMenu?.items.first { appMenu.submenu = menu.copy() as? NSMenu }
    }

    func menuWillOpen(_ menu: NSMenu) { menuTracking = true }
    func menuDidClose(_ menu: NSMenu) {
        menuTracking = false
        DispatchQueue.main.async { self.rebuildMenu() }
    }

    func add(_ menu: NSMenu, _ title: String, _ action: Selector) {
        let entry = NSMenuItem(title: title, action: action, keyEquivalent: "")
        entry.target = self; menu.addItem(entry)
    }

    func label(_ value: String, size: CGFloat = 13, weight: NSFont.Weight = .regular, secondary: Bool = false) -> NSTextField {
        let text = NSTextField(wrappingLabelWithString: value)
        text.font = NSFont.systemFont(ofSize: size, weight: weight)
        text.textColor = secondary ? .secondaryLabelColor : .labelColor
        text.isSelectable = true
        return text
    }

    func stack(_ views: [NSView], spacing: CGFloat = 12) -> NSStackView {
        let result = NSStackView(views: views)
        result.orientation = .vertical; result.alignment = .leading; result.spacing = spacing
        for view in views { view.widthAnchor.constraint(equalTo: result.widthAnchor).isActive = true }
        return result
    }

    func row(_ views: [NSView], spacing: CGFloat = 10) -> NSStackView {
        let result = NSStackView(views: views)
        result.orientation = .horizontal; result.alignment = .centerY; result.spacing = spacing
        return result
    }

    func field(_ name: String, _ view: NSView, hint: String = "") -> NSStackView {
        var views: [NSView] = [label(name, weight: .medium), view]
        if !hint.isEmpty { views.append(label(hint, size: 11, secondary: true)) }
        return stack(views, spacing: 5)
    }

    func mount(_ content: NSView, in window: NSWindow, inset: CGFloat = 24) {
        let parent = NSView()
        window.contentView = parent; content.translatesAutoresizingMaskIntoConstraints = false
        parent.addSubview(content)
        NSLayoutConstraint.activate([
            content.leadingAnchor.constraint(equalTo: parent.leadingAnchor, constant: inset),
            content.trailingAnchor.constraint(equalTo: parent.trailingAnchor, constant: -inset),
            content.topAnchor.constraint(equalTo: parent.topAnchor, constant: inset),
            content.bottomAnchor.constraint(lessThanOrEqualTo: parent.bottomAnchor, constant: -inset)
        ])
    }

    @objc func showSetup() {
        if let window = setupWindow { NSApp.activate(ignoringOtherApps: true); window.makeKeyAndOrderFront(nil); return }
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 570, height: 680), styleMask: [.titled, .closable], backing: .buffered, defer: false)
        window.title = "Team Relay"; window.isReleasedWhenClosed = false
        serverField.placeholderString = "https://relay.your-team.com or http://192.168.1.4:8080"
        inviteField.placeholderString = "Paste the invitation your admin sent you"
        nameField.stringValue = info["name"] as? String ?? NSFullUserName()
        folderField.placeholderString = "Choose the folder your agent usually works in"
        folderField.isEditable = false
        modelField.placeholderString = "Agent default (optional override)"
        runtimeChoice.removeAllItems(); runtimeChoice.addItems(withTitles: ["Choose your agent", "Claude Code", "Codex"])
        runtimeChoice.target = self; runtimeChoice.action = #selector(runtimeChanged)
        permissionChoice.addItems(withTitles: ["Choose permissions", "Read-only tools", "Guarded tools (files, shell and supported MCPs)"])
        loginCheck.state = .on
        let browse = NSButton(title: "Choose…", target: self, action: #selector(chooseFolder)); browse.bezelStyle = .rounded
        connectButton.target = self; connectButton.action = #selector(connect); connectButton.bezelStyle = .rounded; connectButton.bezelColor = .systemBlue
        connectButton.keyEquivalent = "\r"; connectButton.controlSize = .large
        setupMessage.font = .systemFont(ofSize: 12); setupMessage.textColor = .secondaryLabelColor; setupMessage.maximumNumberOfLines = 5
        setupMessage.stringValue = "Connect installs the MCP and both skills in your agent and starts your connection. You approve incoming work here."
        let next = ActionButton("Continue") { [weak self] in
            guard let self = self else { return }
            if self.serverField.stringValue.trimmingCharacters(in: .whitespaces).isEmpty || self.inviteField.stringValue.trimmingCharacters(in: .whitespaces).isEmpty {
                self.showError("Paste the relay address and invitation your admin sent you."); return
            }
            self.joinPage?.isHidden = true; self.agentPage?.isHidden = false
            self.connectButton.keyEquivalent = "\r"
        }
        next.bezelStyle = .rounded; next.bezelColor = .systemBlue; next.controlSize = .large
        let first = stack([
            label("Join your team", size: 25, weight: .semibold),
            label("Your admin runs the relay. You just connect your agent.", secondary: true),
            field("Relay address", serverField),
            field("Invitation", inviteField),
            field("Your name", nameField),
            label("No Docker, server setup or extra account needed on your computer.", secondary: true), next
        ], spacing: 18)
        joinPage = first
        let advanced = stack([field("Model", modelField), filesCheck], spacing: 10)
        advanced.isHidden = true; advancedPage = advanced
        let advancedToggle = ActionButton("Model and file-sharing options…") { [weak self] in self?.advancedPage?.isHidden.toggle() }
        advancedToggle.bezelStyle = .rounded
        let back = ActionButton("Back") { [weak self] in self?.agentPage?.isHidden = true; self?.joinPage?.isHidden = false; self?.connectButton.keyEquivalent = "" }; back.bezelStyle = .rounded
        let second = stack([
            label(enrolled ? "Your agent connection" : "Make it your agent", size: 25, weight: .semibold),
            label("Send requests from your usual chat. Approve incoming work from the TR menu.", secondary: true),
            field("Agent for sending and receiving", runtimeChoice),
            field("Working folder", row([folderField, browse])),
            field("Tools for teammate requests", permissionChoice, hint: "You still approve incoming work. Guarded tools are not an OS sandbox. Codex requires guarded tools; its receiving sessions cannot inherit local MCPs yet."),
            advancedToggle, advanced, loginCheck,
            setupMessage, row(enrolled ? [connectButton] : [back, connectButton])
        ], spacing: 12)
        agentPage = second; second.isHidden = !enrolled; first.isHidden = enrolled
        if !enrolled { connectButton.keyEquivalent = "" }
        mount(stack([first, second], spacing: 0), in: window)
        setupWindow = window
        if enrolled { applyEnrolledState() }
        window.center(); NSApp.activate(ignoringOtherApps: true); window.makeKeyAndOrderFront(nil)
    }

    func applyEnrolledState() {
        joinPage?.isHidden = true; agentPage?.isHidden = false
        serverField.stringValue = info["server"] as? String ?? serverField.stringValue
        folderField.stringValue = info["work_dir"] as? String ?? folderField.stringValue
        runtimeChoice.selectItem(at: (info["runtime"] as? String == "codex") ? 2 : 1)
        if let runtime = info["runtime"] as? String, runtime != "codex" && runtime != "claude-code" {
            runtimeChoice.addItem(withTitle: "External adapter (configured outside the app)")
            runtimeChoice.selectItem(at: runtimeChoice.numberOfItems - 1)
        }
        inviteField.stringValue = ""; inviteField.placeholderString = "Already joined — no new invitation needed"
        for control in [serverField, inviteField, nameField, folderField, modelField] { control.isEnabled = false }
        runtimeChoice.isEnabled = false; permissionChoice.isEnabled = false; filesCheck.isEnabled = false
        permissionChoice.selectItem(at: (info["permission"] as? String == "read_only") ? 1 : 2)
        modelField.stringValue = info["model"] as? String ?? ""
        connectButton.title = "Finish setup / repair integration"
        if info["runtime"] as? String == "external" { connectButton.title = "Check receiving agent" }
        setupMessage.stringValue = "Your enrollment is saved. Finish setup checks the agent, installs missing MCP/skills and starts the connection. Existing integrations and customized skills are not overwritten. Runtime settings remain in config.yaml for this preview."
    }

    @objc func runtimeChanged() {
        let index = runtimeChoice.indexOfSelectedItem
        permissionChoice.item(at: 1)?.isEnabled = index != 2
        // A switch to Codex must not silently grant broader tool authority.
        if index == 2 && permissionChoice.indexOfSelectedItem == 1 { permissionChoice.selectItem(at: 0) }
        let id = index == 1 ? "claude-code" : "codex"
        let available = (info["runtimes"] as? [[String: String]] ?? []).first { $0["id"] == id }?["executable"] ?? ""
        if index > 0 && available.isEmpty { setupMessage.stringValue = "Install and sign into \(index == 1 ? "Claude Code" : "Codex") first, then reopen Team Relay. Your subscription stays with your agent." }
    }

    @objc func chooseFolder() {
        guard !enrolled else { return }
        let picker = NSOpenPanel(); picker.canChooseDirectories = true; picker.canChooseFiles = false; picker.allowsMultipleSelection = false
        picker.prompt = "Use this folder"
        if picker.runModal() == .OK, let url = picker.url { folderField.stringValue = url.path }
    }

    @objc func connect() {
        guard !setupBusy else { return }
        if enrolled && info["runtime"] as? String == "external" { checkSetup(); return }
        if !enrolled && (runtimeChoice.indexOfSelectedItem == 0 || permissionChoice.indexOfSelectedItem == 0 || folderField.stringValue.isEmpty) {
            setupMessage.stringValue = "Choose your agent, working folder and tool permissions first."; return
        }
        if !enrolled && serverField.stringValue.lowercased().hasPrefix("http://") {
            if !confirm("Use an unencrypted connection?", "HTTP sends invitation tokens, messages and files without encryption. Use this only on a trusted test LAN. Use HTTPS for a shared deployment.", button: "Use this test connection") { return }
        }
        setupBusy = true; connectButton.isEnabled = false
        setupMessage.stringValue = "Connecting your agent… Enrolling, installing MCP and skills, checking the runtime, and starting your connection."
        let input: [String: Any] = ["server": serverField.stringValue, "invite": inviteField.stringValue, "name": nameField.stringValue,
            "runtime": runtimeChoice.indexOfSelectedItem == 1 ? "claude-code" : "codex", "work_dir": folderField.stringValue,
            "permission": permissionChoice.indexOfSelectedItem == 1 ? "read_only" : "guarded_write", "model": modelField.stringValue,
            "share_files": filesCheck.state == .on]
        call([enrolled ? "finish" : "join"], input: enrolled ? nil : input) { result in
            self.setupBusy = false; self.connectButton.isEnabled = true
            switch result {
            case .success:
                self.inviteField.stringValue = ""
                UserDefaults.standard.set(true, forKey: "setupCompleted")
                if self.loginCheck.state == .on {
                    do { try SMAppService.mainApp.register() } catch { self.showError("Connected, but opening at login needs attention in System Settings → General → Login Items. \(error.localizedDescription)") }
                }
                self.setupWindow?.close(); self.showSendHelp()
            case .failure(let error): self.setupMessage.stringValue = error.localizedDescription; self.showError(error.localizedDescription)
            }
            // Enrollment may have succeeded even if runtime or integration
            // failed. Re-discover it so Retry never consumes another invite.
            self.call(["info"]) { result in
                if case .success(let value) = result, let info = value as? [String: Any] {
                    self.info = info; self.enrolled = info["enrolled"] as? Bool ?? false
                    if self.enrolled { self.applyEnrolledState() }
                    self.refresh(); self.rebuildMenu()
                }
            }
        }
    }

    func showApproval(_ notice: [String: Any]) {
        popup?.close()
        displayedRequestID = notice["request_id"] as? String
        let panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 410, height: 350), styleMask: [.titled, .closable, .nonactivatingPanel], backing: .buffered, defer: false)
        panel.title = "Team Relay request"; panel.level = .floating; panel.isReleasedWhenClosed = false
        let name = notice["requester_display_name"] as? String ?? "A teammate"
        let title = notice["title"] as? String ?? "Request for your agent"
        let preview = label(notice["prompt_preview"] as? String ?? "Open the full request to read more.")
        preview.maximumNumberOfLines = 4
        let scope = ActionPopup(); scope.addItems(withTitles: ["Ask every time", "Allow this conversation for 30 minutes", "Always allow this teammate", "Always allow everyone in my team"])
        let allow = PrimaryButton("Allow once") { [weak self] in
            let levels = ["ask_always", "conversation_30m", "teammate_always", "all_always"]
            let level = levels[scope.indexOfSelectedItem]
            if level != "ask_always", !(self?.confirm("Save this allowance?", "\(scope.titleOfSelectedItem ?? ""). Future matching requests can start without another approval. You can revoke this from Approvals I’ve saved.", button: "Allow and save") ?? false) { return }
            allowAction(self, notice, level)
        }
        allow.bezelStyle = .rounded; allow.bezelColor = .systemBlue; allow.controlSize = .large
        scope.onChange = { [weak scope, weak allow] in allow?.title = scope?.indexOfSelectedItem == 0 ? "Allow once" : "Allow and save" }
        let deny = ActionButton("Deny") { [weak self] in self?.decide(notice, action: ["deny", notice["request_id"] as? String ?? ""]) }
        deny.bezelStyle = .rounded
        let inspect = ActionButton("Read full request…") { [weak self] in self?.inspect(notice) }; inspect.bezelStyle = .rounded
        let attachments = notice["attachments"] as? [Any] ?? []
        let body = stack([label("\(name) is asking your agent", size: 17, weight: .semibold), label(title, weight: .medium), preview,
            label("\(attachments.count) file(s) · Your local tool rules still apply", size: 11, secondary: true), inspect, scope, row([deny, allow])])
        mount(body, in: panel, inset: 18)
        if let button = item.button, let window = button.window, let screen = window.screen {
            let rect = window.convertToScreen(button.frame)
            panel.setFrameOrigin(NSPoint(x: min(max(rect.midX-205, screen.visibleFrame.minX+8), screen.visibleFrame.maxX-418), y: screen.visibleFrame.maxY-358))
        } else { panel.center() }
        popup = panel; panel.orderFrontRegardless()
    }

    func decide(_ notice: [String: Any], action: [String]) {
        popup?.close()
        call(action) { result in
            if case .failure(let error) = result { self.showError(error.localizedDescription) }
            self.refresh()
        }
    }

    func inspect(_ notice: [String: Any]) {
        call(["inspect", notice["request_id"] as? String ?? ""]) { result in
            switch result {
            case .success(let data):
                let proposal = data as? [String: Any] ?? [:]
                let files = (proposal["attachments"] as? [[String: Any]] ?? []).map { $0["name"] as? String ?? "File" }.joined(separator: "\n")
                let access = (proposal["requested_access"] as? [[String: Any]] ?? []).map { "\($0["workspace_alias"] as? String ?? "Workspace"): \($0["mode"] as? String ?? "local policy")" }.joined(separator: "\n")
                self.showText("Full request", "From: \(proposal["requester_display_name"] as? String ?? "Teammate")\n\(proposal["title"] as? String ?? "")\n\n\(proposal["prompt"] as? String ?? "")\n\nRequested workspaces\n\(access.isEmpty ? "Your configured default folder and policy" : access)\n\nFiles\n\(files.isEmpty ? "None" : files)\n\nNo file contents are downloaded until you approve.")
            case .failure(let error): self.showError(error.localizedDescription)
            }
        }
    }

    @objc func showRequests() {
        if let notice = pending.first { showApproval(notice) }
        else { showText("Requests", busy ? "Your agent is working on an approved request. Open Activity and logs to follow it. Further approval controls are locked until the active runtime finishes." : "No requests waiting. When a teammate asks your agent for help, a compact approval window appears below the TR icon.") }
    }
    @objc func showSendHelp() {
        showText("Send your first request", "Team Relay sends requests from your usual agent chat.\n\nAfter setup, start a NEW chat in your selected Claude Code or Codex client so it loads the MCP and skills.\n\nTry:\n\n  Find my available teammates using Team Relay.\n\nThen:\n\n  Ask <teammate>’s agent to explain how their repository handles authentication. Ask for a short summary and relevant file paths.\n\nYour agent finds the exact teammate and sends the request through the Team Relay MCP. Your teammate approves it here; the answer and any returned files come back to your agent.\n\nYou do not need to run a separate sender command or install a server.\n\nStopping the connection stops incoming work. Your agent’s outgoing MCP remains available. Quitting this menu-bar app leaves the connection running.")
    }
    @objc func showTeammates() {
        call(["teammates"]) { result in
            switch result {
            case .success(let value):
                let agents = (value as? [String: Any])?["agents"] as? [[String: Any]] ?? []
                let text = agents.map { "\($0["display_name"] as? String ?? "Teammate") — \(($0["online"] as? Bool ?? false) ? "online" : "offline")\n  \($0["device_name"] as? String ?? "")\n" }.joined(separator: "\n")
                self.showText("Teammates", text.isEmpty ? "No other teammates are registered yet. Ask your admin to invite someone. Your own agent is hidden to prevent self-requests." : text+"\nSend requests from your agent chat, not this list.")
            case .failure(let error): self.showError(error.localizedDescription)
            }
        }
    }
    @objc func showGrants() {
        call(["approval-grants"]) { result in
            switch result {
            case .success(let data):
                let grants = (data as? [String: Any])?["grants"] as? [[String: Any]] ?? []
                if grants.isEmpty { self.showText("Saved approvals", "No saved allowances. You are asked for each incoming request."); return }
                let menu = NSMenu()
                for grant in grants {
                    let id = grant["id"] as? String ?? grant["grant_id"] as? String ?? ""
                    let entry = NSMenuItem(title: "Revoke \(grant["level"] as? String ?? "allowance") · \(grant["requester_display_name"] as? String ?? "team")", action: #selector(self.revokeGrant(_:)), keyEquivalent: "")
                    entry.target = self; entry.representedObject = id; menu.addItem(entry)
                }
                menu.popUp(positioning: nil, at: NSEvent.mouseLocation, in: nil)
            case .failure(let error): self.showError(error.localizedDescription)
            }
        }
    }
    @objc func revokeGrant(_ sender: NSMenuItem) {
        guard let id = sender.representedObject as? String, !id.isEmpty else { return }
        if confirm("Revoke this allowance?", "New matching requests will need approval again. Work already running is not cancelled.", button: "Revoke") {
            call(["revoke-approval-grant", id]) { result in if case .failure(let error) = result { self.showError(error.localizedDescription) } }
        }
    }
    @objc func showLogs() { presentAction("logs", title: "Activity and logs") }
    @objc func checkSetup() { presentAction("doctor", title: "Setup check") }
    func presentAction(_ action: String, title: String) {
        call([action]) { result in
            switch result {
            case .success(let value): self.showText(title, (value as? [String: Any])?["text"] as? String ?? self.pretty(value), refresh: { self.presentAction(action, title: title) })
            case .failure(let error): self.showError(error.localizedDescription)
            }
        }
    }
    @objc func startConnection() { performService("start") }
    @objc func stopConnection() { if confirm("Stop incoming requests?", "This stops the local connection and may interrupt active work. Your outgoing MCP remains installed. You can start it again from this menu.", button: "Stop connection") { performService("stop") } }
    @objc func restartConnection() { if confirm("Restart your connection?", "Any active teammate work may be interrupted. Saved enrollment and permissions are kept.", button: "Restart") { performService("restart") } }
    func performService(_ action: String) {
        call([action]) { result in if case .failure(let error) = result { self.showError(error.localizedDescription) }; self.refresh() }
    }
    @objc func quit() { NSApp.terminate(nil) }

    func pretty(_ value: Any) -> String {
        guard let data = try? JSONSerialization.data(withJSONObject: value, options: [.prettyPrinted, .sortedKeys]) else { return String(describing: value) }
        return String(data: data, encoding: .utf8) ?? ""
    }
    func showText(_ title: String, _ text: String, refresh: (() -> Void)? = nil) {
        let window = textWindows[title] ?? NSWindow(contentRect: NSRect(x: 0, y: 0, width: 680, height: 510), styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
        window.title = title; window.isReleasedWhenClosed = false
        let scroll = NSScrollView(); scroll.hasVerticalScroller = true; scroll.borderType = .bezelBorder
        let view = NSTextView(); view.isEditable = false; view.isRichText = false; view.font = .systemFont(ofSize: 13)
        view.string = text; view.textContainerInset = NSSize(width: 14, height: 14)
        view.isVerticallyResizable = true; view.isHorizontallyResizable = false
        view.autoresizingMask = [.width]; view.textContainer?.widthTracksTextView = true
        scroll.documentView = view
        scroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 390).isActive = true
        var elements: [NSView] = [scroll]
        if let refresh = refresh { let button = ActionButton("Refresh", action: refresh); button.bezelStyle = .rounded; elements.append(button) }
        mount(stack(elements), in: window)
        if textWindows[title] == nil { window.center() }
        textWindows[title] = window
        NSApp.activate(ignoringOtherApps: true); window.makeKeyAndOrderFront(nil)
    }
    func showError(_ text: String) {
        let alert = NSAlert(); alert.messageText = "Team Relay needs attention"; alert.informativeText = text; alert.alertStyle = .warning
        NSApp.activate(ignoringOtherApps: true); alert.runModal()
    }
    func confirm(_ title: String, _ body: String, button: String) -> Bool {
        let alert = NSAlert(); alert.messageText = title; alert.informativeText = body
        alert.addButton(withTitle: button); alert.addButton(withTitle: "Cancel")
        NSApp.activate(ignoringOtherApps: true); return alert.runModal() == .alertFirstButtonReturn
    }
}

private func allowAction(_ app: RelayApp?, _ notice: [String: Any], _ level: String) {
    app?.decide(notice, action: ["approve", notice["request_id"] as? String ?? "", level])
}

class ActionButton: NSButton {
    let handler: () -> Void
    init(_ title: String, action: @escaping () -> Void) {
        handler = action; super.init(frame: .zero); self.title = title; self.target = self; self.action = #selector(invokeAction)
    }
    required init?(coder: NSCoder) { fatalError("not supported") }
    @objc func invokeAction() { handler() }
}

// AppKit dims ordinary default-button bezels in a non-activating panel. Draw
// this explicit action ourselves so approval remains blue without taking focus
// or assigning Return to an unsolicited incoming request.
final class PrimaryButton: ActionButton {
    override var intrinsicContentSize: NSSize {
        let size = super.intrinsicContentSize
        return NSSize(width: max(110, size.width + 24), height: 32)
    }
    override func draw(_ dirtyRect: NSRect) {
        (isHighlighted ? NSColor.systemBlue.blended(withFraction: 0.16, of: .black)! : NSColor.systemBlue).setFill()
        NSBezierPath(roundedRect: bounds.insetBy(dx: 1, dy: 1), xRadius: 7, yRadius: 7).fill()
        let text = NSAttributedString(string: title, attributes: [.font: NSFont.systemFont(ofSize: 13, weight: .semibold), .foregroundColor: NSColor.white])
        let size = text.size()
        text.draw(at: NSPoint(x: (bounds.width-size.width)/2, y: (bounds.height-size.height)/2))
    }
}

final class ActionPopup: NSPopUpButton {
    var onChange: (() -> Void)?
    init() { super.init(frame: .zero, pullsDown: false); target = self; action = #selector(changed) }
    required init?(coder: NSCoder) { fatalError("not supported") }
    @objc func changed() { onChange?() }
}

let application = NSApplication.shared
let delegate = RelayApp()
application.delegate = delegate
application.run()
