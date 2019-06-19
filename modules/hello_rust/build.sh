#!/bin/bash
if [[ "$1" == "x86_64" ]]; then
    ARCH=x86_64
    if [[ `uname` == "Darwin" ]]; then
        PREFIX=x86_64-elf-
    fi
elif [[ "$1" == "aarch64" ]]; then
    ARCH=aarch64
    PREFIX=aarch64-elf-
else
    echo "Not supported target"
    exit 1
fi

echo "Step 1. Fetching dependencies according to cargo."
cargo xbuild --target=../../kernel/targets/$ARCH.json --release

echo "Step 2. Compile the library"
rustc --edition=2018 --crate-name hello_rust src/lib.rs \
--color always --crate-type cdylib  -C debuginfo=2 \
--out-dir ./target/$ARCH/release/objs \
--target ../../kernel/targets/$ARCH.json \
-L dependency=target/$ARCH/release/deps \
-L dependency=target/release/deps \
--emit=obj --sysroot target/sysroot \
-L all=../../kernel/target/$ARCH/release/deps

echo "Step 3. Packing the library into kernel module."
${PREFIX}ld -shared -o target/$ARCH/release/hello_rust.ko target/$ARCH/release/objs/*.o
