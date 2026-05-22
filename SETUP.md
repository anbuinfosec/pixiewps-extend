# 🛠️ Setup Guide - Pixiewps v1.4.4

Complete installation guide for all platforms: Linux, macOS, Termux, and Raspberry Pi.

---

## 📋 System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **CPU** | Dual-core 1.2 GHz | Quad-core 2.0 GHz+ |
| **RAM** | 256 MB | 1 GB+ |
| **Disk** | 100 MB | 500 MB+ |
| **OS** | Linux 2.6+, macOS 10.13+, Android 9+ | Latest LTS |

---

## 🐧 Linux Installation

### Ubuntu / Debian

```bash
# Update system packages
sudo apt-get update
sudo apt-get upgrade -y

# Install build dependencies
sudo apt-get install -y \
  build-essential \
  cmake \
  git \
  libpcap-dev \
  aircrack-ng \
  pixiewps

# Clone repository
git clone https://github.com/anbuinfosec/pixiewps-extend
cd pixiewps-extend

# Build from source
mkdir -p build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build . -j$(nproc)

# Install globally
sudo cmake --install .

# Verify installation
pixiewps -V
```

### Fedora / RHEL / CentOS

```bash
# Install dependencies
sudo dnf install -y \
  gcc \
  cmake \
  libpcap-devel \
  aircrack-ng

# Clone and build
git clone https://github.com/anbuinfosec/pixiewps-extend
cd pixiewps-extend
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
sudo make install
```

### Arch Linux

```bash
# Install from AUR (if available)
yay -S pixiewps-extend

# Or build manually
sudo pacman -S base-devel cmake libpcap aircrack-ng
git clone https://github.com/anbuinfosec/pixiewps-extend
cd pixiewps-extend && mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release .. && make -j$(nproc)
sudo make install
```

---

## 🍎 macOS Installation

### Using Homebrew (Recommended)

```bash
# Install Homebrew if not present
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install cmake libpcap aircrack-ng

# Clone and build
git clone https://github.com/anbuinfosec/pixiewps-extend
cd pixiewps-extend
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build . -j$(sysctl -n hw.ncpu)

# Install
sudo cmake --install .
pixiewps -V
```

### Manual Build (M1/M2 Apple Silicon)

```bash
# Install Xcode command line tools
xcode-select --install

# Install dependencies via MacPorts or Homebrew
brew install cmake libpcap

# Clone repository
git clone https://github.com/anbuinfosec/pixiewps-extend
cd pixiewps-extend

# Build with ARM64 optimizations
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_OSX_ARCHITECTURES=arm64 \
      ..
make -j$(sysctl -n hw.ncpu)

# Install
sudo make install
```

---

## 🤖 Termux (Android) Installation

### Prerequisites
- Termux app installed from F-Droid or GitHub Releases
- Minimum 500 MB free storage
- Wireless adapter support (some devices don't support monitor mode)

### Step-by-Step Installation

```bash
# Update Termux packages
pkg update && pkg upgrade

# Install required packages
pkg install -y \
  build-essential \
  cmake \
  git \
  libpcap \
  aircrack-ng \
  libcap

# Optional: Install pixiewps (if available in Termux repos)
pkg install -y pixiewps

# Clone repository
git clone https://github.com/anbuinfosec/pixiewps-extend
cd pixiewps-extend

# Create build directory
mkdir -p build && cd build

# Configure for Termux
cmake -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_C_FLAGS="-O3 -march=native" \
      ..

# Build
make -j$(nproc)

# Install to Termux prefix
make install

# Verify installation
pixiewps -V
```

### Wireless Adapter Setup in Termux

```bash
# Check available interfaces
ifconfig -a
# or
ip link show

# Enable monitor mode (device-dependent)
# For Nexus 6P / other devices:
adb shell su -c "iwconfig wlan0 mode Monitor"

# Or use airmon-ng if available:
sudo airmon-ng start wlan0
```

---

## 🔴 Raspberry Pi Installation

### Raspberry Pi OS (Recommended)

```bash
# Update system
sudo apt-get update && sudo apt-get upgrade -y

# Install dependencies for Raspberry Pi
sudo apt-get install -y \
  build-essential \
  cmake \
  libpcap-dev \
  aircrack-ng \
  wireless-tools \
  git

# For Raspberry Pi 4/5 (better performance)
export CFLAGS="-O3 -march=native"
export CXXFLAGS="-O3 -march=native"

# Clone repository
git clone https://github.com/anbuinfosec/pixiewps-extend
cd pixiewps-extend

# Build with optimizations
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_C_FLAGS="-O3 -march=native" \
      ..
make -j$(nproc)

# Install
sudo make install

# Verify
pixiewps -V
```

### Using Pre-built Binaries (Faster)

```bash
# Download ARM binary for your Pi version
# Raspberry Pi 3/Zero W (ARMv7)
wget https://github.com/anbuinfosec/pixiewps-extend/releases/download/v1.4.4/pixiewps-armv7
chmod +x pixiewps-armv7
sudo mv pixiewps-armv7 /usr/local/bin/pixiewps

# Raspberry Pi 4/5 (ARMv8/ARM64)
wget https://github.com/anbuinfosec/pixiewps-extend/releases/download/v1.4.4/pixiewps-arm64
chmod +x pixiewps-arm64
sudo mv pixiewps-arm64 /usr/local/bin/pixiewps

# Verify
pixiewps -V
```

---

## 🔧 Build Configuration Options

### CMake Options

```bash
cd build

# Default build (Release mode)
cmake -DCMAKE_BUILD_TYPE=Release ..

# Debug build (with symbols for GDB)
cmake -DCMAKE_BUILD_TYPE=Debug ..

# With OpenSSL support (better performance)
cmake -DCMAKE_BUILD_TYPE=Release -DENABLE_OPENSSL=ON ..

# With libnl3 support (for modern kernels)
cmake -DCMAKE_BUILD_TYPE=Release -DENABLE_LIBNL3=ON ..

# With Link-Time Optimization (LTO)
cmake -DCMAKE_BUILD_TYPE=Release -DENABLE_LTO=ON ..

# All optimizations enabled
cmake -DCMAKE_BUILD_TYPE=Release \
      -DENABLE_OPENSSL=ON \
      -DENABLE_LTO=ON \
      -DENABLE_LIBNL3=ON \
      ..
```

### Make/Makefile Build (Alternative)

```bash
cd pixiewps-extend

# Standard build
make

# With OpenSSL
make OPENSSL=1

# Install
sudo make install

# Install to custom location
make install PREFIX=$HOME/.local

# Clean build artifacts
make clean
```

---

## 📦 Docker Installation

### Using Docker Container

```bash
# Build Docker image
docker build -t pixiewps-extend:1.4.4 .

# Run container
docker run -it --network host \
  --device /dev/null \
  pixiewps-extend:1.4.4 \
  pixiewps -V

# Interactive shell
docker run -it --network host pixiewps-extend:1.4.4 /bin/bash
```

### Docker Compose (for lab environments)

```yaml
version: '3.8'
services:
  pixiewps:
    build:
      context: .
      dockerfile: Dockerfile
    image: pixiewps-extend:1.4.4
    container_name: pixiewps-lab
    network_mode: host
    devices:
      - /dev/null
    volumes:
      - ./results:/output
    working_dir: /work
    command: /bin/bash
```

---

## ✅ Post-Installation Setup

### 1. Verify Installation

```bash
# Check version
pixiewps -V

# Check capabilities
pixiewps --help

# Test pixiewps (should show usage)
pixiewps
```

### 2. Wireless Interface Configuration

```bash
# List available interfaces
iwconfig
# or
iw dev

# Check interface mode
iwconfig wlan0 | grep Mode

# Enable monitor mode (using airmon-ng)
sudo airmon-ng start wlan0

# Or manually with ip command
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up

# Verify monitor mode
iwconfig wlan0 | grep Mode
# Should show: Mode:Monitor
```

### 3. Privilege Configuration

```bash
# For running without sudo (via capability)
sudo setcap cap_net_raw+ep /usr/local/bin/pixiewps

# Or add user to group
sudo usermod -aG wireshark $USER
newgrp wireshark

# Add passwordless sudo (less secure)
echo "$USER ALL=(ALL) NOPASSWD: /usr/local/bin/pixiewps" | sudo tee -a /etc/sudoers
```

### 4. Create Aliases (Optional)

```bash
# Add to ~/.bashrc or ~/.zshrc
alias pixiewps-start='sudo /usr/local/bin/pixiewps'
alias pixie-scan='sudo airmon-ng start wlan0'
alias pixie-revert='sudo airmon-ng stop wlan0mon'

# For Termux, add to ~/.bashrc
alias pixiewps='/data/data/com.termux/files/usr/bin/pixiewps'
```

---

## 🐛 Troubleshooting Installation

### CMake Not Found

```bash
# Install CMake
# Ubuntu/Debian
sudo apt-get install cmake

# macOS
brew install cmake

# Termux
pkg install cmake
```

### Build Fails with "libpcap not found"

```bash
# Ubuntu/Debian
sudo apt-get install libpcap-dev

# Fedora/RHEL
sudo dnf install libpcap-devel

# macOS
brew install libpcap

# Termux
pkg install libpcap
```

### Permission Denied When Installing

```bash
# Use sudo for global installation
sudo cmake --install .

# Or install to user directory
cmake --install . --prefix $HOME/.local
export PATH=$HOME/.local/bin:$PATH
```

### Compilation Errors on ARM Devices

```bash
# Reduce optimization if errors occur
cmake -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_C_FLAGS="-O2" \
      ..
make -j1  # Use single thread if parallel fails
```

### Monitor Mode Issues

```bash
# Check if nl80211 driver is supported
iw list | head -20

# Check kernel version (need 2.6.27+)
uname -r

# Try alternative monitor mode setup
sudo airmon-ng check kill
sudo airmon-ng start wlan0
```

---

## 📍 Installation Locations

| Component | Path |
|-----------|------|
| **Binary** | `/usr/local/bin/pixiewps` |
| **Libraries** | `/usr/local/lib/libpixiewps.*` |
| **Headers** | `/usr/local/include/pixiewps/` |
| **Man Page** | `/usr/local/share/man/man1/pixiewps.1` |
| **Termux Binary** | `$PREFIX/bin/pixiewps` |
| **User Install** | `~/.local/bin/pixiewps` |

---

## 🔄 Updating Installation

```bash
# Check for updates
git -C pixiewps-extend pull origin master

# Rebuild if updated
cd pixiewps-extend/build
cmake ..
make -j$(nproc)
sudo make install
```

---

## 🗑️ Uninstallation

```bash
# Using CMake
cd build
sudo cmake --install . --strip

# Or manual removal
sudo rm /usr/local/bin/pixiewps
sudo rm -rf /usr/local/include/pixiewps
sudo rm /usr/local/share/man/man1/pixiewps.1

# Termux
pkg remove pixiewps-extend
```

---

## ✨ Next Steps

1. **Read [USAGE.md](USAGE.md)** - Learn how to run attacks
2. **Check [FEATURES.md](FEATURES.md)** - Understand available features
3. **See [REAL_ATTACK_ANALYSIS.md](REAL_ATTACK_ANALYSIS.md)** - Study real examples
4. **Read [STATIC_PKE_EXPLOITATION.md](STATIC_PKE_EXPLOITATION.md)** - Learn advanced techniques

---

**Status:** ✅ Installation guide for v1.4.4 complete  
**Last Updated:** May 23, 2026  
**Platform Support:** Linux, macOS, Raspberry Pi, Termux
