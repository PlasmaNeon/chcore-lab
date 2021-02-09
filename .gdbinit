set architecture aarch64
target remote localhost:1234
file ./build/kernel.img

# Customize part
source /home/plasma/.gdbinit-gef.py

