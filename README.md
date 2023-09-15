Steps to reproduce error:
```bash
# optionally to regenerate key
# $ cargo run --example=new_key

# pkcs8 0.7.6 decryption
$ cargo run -q --example=decrypt_key_07
Public Key: [e1, 82, 21, 31, 80, c0, fb, 3e, 3e, 8f, 60, 6a, dd, 63, 7a, 33, 84, 0, 6, 15, 7c, ec, ae, a6, da, cb, d2, 55, 50, 20, 3c, f2]

# pkcs8 0.10.2 decryption
$ cargo run -q --example=decrypt_key
thread 'main' panicked at 'called `Result::unwrap()` on an `Err` value: Error { kind: Noncanonical { tag: Tag(0xa1: CONTEXT-SPECIFIC [1] (constructed)) }, position: None }', examples/decrypt_key.rs:4:71
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
```


