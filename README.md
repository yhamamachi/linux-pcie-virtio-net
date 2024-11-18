# Linux PCIe virtio-net

## kernel

- base envrionment
  - https://github.com/yhamamachi/linux-pcie-virtio-net/tree/release20230922-v6.4.rc7-next
    - Based on https://github.com/ShunsukeMie/linux/tree/release20230922
- renesas-devel base
  - https://github.com/yhamamachi/linux-pcie-virtio-net/tree/renesas-devel-2023-06-26-v6.4-wip3
  - https://github.com/yhamamachi/linux-pcie-virtio-net/tree/renesas-devel-2024-09-16-v6.11-wip
## Buildroot

### First build

```
wget https://buildroot.org/downloads/buildroot-2024.02.4.tar.gz
tar xf buildroot-2024.02.4.tar.xz
cp buildroot_files/config ./buildroot-2024.02.4/.config
cd ./buildroot-2024.02.4
make
cp ../buildroot_files/S90endpoint ./output/target/etc/init.d
make
```

### Endpoint function setup

Please refer to the [buildroot_files/S90endpoint](buildroot_files/S90endpoint)

