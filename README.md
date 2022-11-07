# speck

This is a Rust implementation of the [Speck cipher](https://eprint.iacr.org/2013/404.pdf). I built it as a quick experiment to see how I'd implement it with `#[no_std]` Rust and have no intention of putting it into production use. It does pass the test vectors from the paper, [after they were converted to little-endian](https://en.wikipedia.org/wiki/Speck_(cipher)#Endianness).

## Example

```rust
let id = 456789;
let cipher = Speck64_128::new([0, 1, 3, 4]);
let mut data = id.to_le_bytes();
cipher.seal_in_place(&mut data).unwrap();
let encrypted_id = u64::from_le_bytes(data)
// => 6883383884621847717
```
