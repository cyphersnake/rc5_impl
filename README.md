# RC5 implementation
RC5 is a symmetric key block cipher that was designed by Ron Rivest in 1995. It is a fast and secure cipher, with a variable key size and block size. The key size can be anywhere from 0 to 2^40 bits, and the block size can be 64 or 128 bits.

This library is an implementation of the RC5 encryption algorithm in Rust. It is designed to be easy to use, with a simple API and no dependencies.

## Features
- Type-Safe Variable key size (up to 2^40 bits)
- Variable block size (64 or 128 bits)
- Easy to use API

## Usage
In your Cargo.toml:
```toml
rc5_cypher = "0.0.1"
```

In your rust code:
```rust
use rc5_cypher::*;
```

## Encryption
```rust
use rc5_cypher::*;

fn main() {
    // The key must be an array of static size so that the library
    // can check the validity of such a key by its data type
    let key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    ];
    let pt = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
    println!("{:?}", &pt.encode_rc5(key).unwrap());
}
```

## Decryption
```rust
use rc5_cypher::*;

fn main() {
    // The key must be an array of static size so that the library
    // can check the validity of such a key by its data type
    let key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    ];
    let ct = vec![0x2D, 0xDC, 0x14, 0x9B, 0xCF, 0x08, 0x8B, 0x9E];
    println!("{:?}", &ct.decode_rc5(key).unwrap());
}
```

## Secrecy-Feaute
If [cargo-feature secrecy](Cargo.toml#L9) enabled, then you can re-import and use [secrecy](https://crates.io/crates/secrecy) crate in your project
```rust
use rc5_cypher::*;

fn main() {
    let key = secrecy::Secret::new([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    ]);
    let pt = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
    println!("{:?}", &pt.encode_rc5(key).unwrap());
}
```

## Example
The example provides a cli utility for rc5 encryption using hex input. Run to find out more:
```bash
cargo run --example cli -- --help
```


# Mintlayer recruitment test

The purpose of this test is to implement a simple cipher in the form of rc5. 

Rivest describes the rc5 cipher here https://www.grc.com/r&d/rc5.pdf and includes a c reference implementation.

For this test we ask that you implement rc5 in rust. Specifically rc5-32/12/16 for which we have included some test case, 
feel free to expand and implement other versions of rc5 too if you wish. The test cases provided should pass. 
Further test cases can be found here https://datatracker.ietf.org/doc/html/draft-krovetz-rc6-rc5-vectors-00#section-4

Feel free to change the function stubs to accept different arguments or to return something else but remember to change the
test cases if you do so. The code provided here is just a starting block.

We'll be looking at your code to see how well you can follow a specification, to see if you can write idiomatic rust and to see if you can write bug-free maintainable code.
Make sure you handle error sensibly and design some nice abstractions. 
