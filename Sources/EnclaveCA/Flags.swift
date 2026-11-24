public struct UsageError: Error, CustomStringConvertible {
    public let description: String

    public init(description: String) {
        self.description = description
    }
}

/// `switches` take no value.
public func parseFlags(_ args: some Sequence<String>, switches: Set<String> = []) throws -> [String: String] {
    var flags: [String: String] = [:]
    var it = args.makeIterator()
    while let arg = it.next() {
        guard arg.hasPrefix("--"), arg.count > 2 else { throw UsageError(description: "unexpected argument \"\(arg)\"") }
        let name = String(arg.dropFirst(2))
        guard flags[name] == nil else { throw UsageError(description: "\(arg) given twice") }
        if switches.contains(name) {
            flags[name] = ""
            continue
        }
        guard let value = it.next() else { throw UsageError(description: "\(arg) needs a value") }
        flags[name] = value
    }
    return flags
}

public func take(_ flags: inout [String: String], _ name: String) throws -> String {
    guard let v = flags.removeValue(forKey: name) else { throw UsageError(description: "missing --\(name)") }
    return v
}

public func takeSwitch(_ flags: inout [String: String], _ name: String) -> Bool {
    flags.removeValue(forKey: name) != nil
}

public func rejectUnknown(_ flags: [String: String]) throws {
    if let k = flags.keys.sorted().first { throw UsageError(description: "unknown flag --\(k)") }
}
