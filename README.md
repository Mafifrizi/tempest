<h1 align="center">
<br>
<img src="tempest_banner.jpg" width="400">
<br>
Tempest
</h1>

A native Linux runtime companion built to protect active Kerberos sessions and keyring boundaries after initial authentication. <br>
Designed as a companion layer for [Tanuki](https://github.com/Mafifrizi/tanuki). <br>

### Operatives
- **Souei**: watches kernel keyrings, UNIX socket peers, and credential file activity in silence.
- **Chronoa**: guards ticket lifetimes against expiration, weak ciphers, and clock drift.
- **Ranga**: isolates process session keyrings and wipes leftover credential artifacts on exit.

### NOTE
This project targets real Linux runtime problems around post-auth identity hygiene and lifecycle drift. <br>
Each operative runs independently and stays out of your way until an identity boundary is put at risk. <br>
Integration into the main Tanuki toolchain is intentionally decoupled so both codebases stay clean. <br>
Full architecture, kernel primitives, and CLI contracts live in [Architecture](docs/ARCHITECTURE.md) and [CLI Reference](docs/CLI.md).


