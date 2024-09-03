# Linux PCIe virtio-net

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

