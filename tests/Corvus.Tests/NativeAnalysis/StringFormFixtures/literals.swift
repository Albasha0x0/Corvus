// Literals of up to 15 UTF-8 bytes are small strings: two immediates, no data.
@inline(never) @_optimize(none)
func show(_ s: String) -> Int { s.utf8.count }

@main
struct Literals {
    static func main() {
        let n = show("/bin/sh") &+ show("Content-Type") &+ show("naïve") &+ show("/etc/hosts")
        print(n)
    }
}
