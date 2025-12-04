// Package apis exposes the Sudoku tunnel (HTTP mask + Sudoku obfuscation + AEAD) as a small Go API.
// It supports both pure Sudoku downlink and the bandwidth-optimized packed downlink, plus UDP-over-TCP (UoT),
// so the same primitives used by the CLI can be embedded by other projects.
//
// Key entry points:
//   - ProtocolConfig / DefaultConfig: describe all required parameters.
//   - Dial: client-side helper that connects to a Sudoku server and sends the target address.
//   - DialUDPOverTCP: client-side helper that primes a UoT tunnel.
//   - ServerHandshake: server-side helper that upgrades an accepted TCP connection and returns
//     the decrypted tunnel plus the requested target address (TCP mode).
//   - ServerHandshakeFlexible: server-side helper that upgrades connections and lets callers
//     detect UoT or read the target address themselves.
//   - HandshakeError: wraps errors while preserving bytes already consumed so callers can
//     gracefully fall back to raw TCP/HTTP handling if desired.
//
// The configuration mirrors the CLI behavior: build a Sudoku table via
// sudoku.NewTable(seed, "prefer_ascii"|"prefer_entropy"), pick an AEAD (chacha20-poly1305 is
// the default and required when using packed downlink), keep the key and padding settings
// consistent across client/server, and apply an optional handshake timeout on the server side.
package apis
