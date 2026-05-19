FROM registry.openanolis.cn/openanolis/anolisos:23

LABEL description="Kernel CVE Livepatch Agent - Anolis OS Build Environment"
LABEL version="0.2.0"

# --- Step 1: Install build tools + kernel build dependencies ---
RUN dnf install -y --setopt=tsflags=nodocs \
    gcc gcc-c++ make git patch diffutils binutils \
    elfutils-libelf-devel openssl-devel kmod \
    python3 python3-pip python3-devel \
    bc bison flex ncurses-devel \
    kernel-devel \
    && dnf clean all

# --- Step 2: Install kpatch + kpatch-build ---
# Try dnf first; fall back to building from source
RUN dnf install -y --setopt=tsflags=nodocs kpatch kpatch-build 2>/dev/null || \
    (git clone --depth=1 https://github.com/dynup/kpatch.git /tmp/kpatch && \
     cd /tmp/kpatch && make && make install && rm -rf /tmp/kpatch)

# --- Step 3: Configure pip mirror ---
RUN pip3 config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple

# --- Step 4: Set working directory ---
WORKDIR /app
COPY . .

# --- Step 5: Install Python dependencies ---
RUN pip3 install --no-cache-dir -r requirements.txt pytest

# --- Step 6: Prepare directories ---
RUN mkdir -p /tmp/test_workspace /kernel-src

# --- Step 7: Entrypoint ---
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["test"]
