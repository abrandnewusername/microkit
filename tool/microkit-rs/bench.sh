
nix-shell -p poop --run "poop './target/release/microkit-rs hello.system' '/home/ivanv/ts/microkit//release/microkit-sdk-1.2.6/bin/microkit /home/ivanv/ts/microkit/example/qemu_virt_aarch64/hello/hello.system --search-path /home/ivanv/ts/microkit/tmp_build --board qemu_virt_aarch64 --config debug -o /home/ivanv/ts/microkit/tmp_build/loader.img -r /home/ivanv/ts/microkit/tmp_build/report.txt'"

