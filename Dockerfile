FROM registry.openanolis.cn/openanolis/anolisos:23

LABEL description="Kernel CVE Livepatch Agent - Anolis OS Build Environment"
LABEL version="0.2.0"

# --- Step 1: Install build tools + kernel build dependencies ---
RUN dnf install -y --setopt=tsflags=nodocs \
    gcc gcc-c++ make git curl patch diffutils binutils \
    elfutils-libelf-devel openssl openssl-devel kmod \
    python3 python3-pip python3-devel \
    bc bison flex ncurses-devel \
    kernel-devel \
    && dnf clean all

# Match the compiler recorded in the target Anolis kernel's vmlinux.
# kpatch rejects compiler drift because it introduces unrelated object diffs.
ARG TARGET_GCC_RELEASE=12.3.0-16.an23
ARG ANOLIS_PACKAGE_BASE=https://mirrors.openanolis.cn/anolis/23.4/os/x86_64/os/Packages
RUN dnf downgrade -y --setopt=tsflags=nodocs \
    ${ANOLIS_PACKAGE_BASE}/gcc-${TARGET_GCC_RELEASE}.x86_64.rpm \
    ${ANOLIS_PACKAGE_BASE}/gcc-c++-${TARGET_GCC_RELEASE}.x86_64.rpm \
    ${ANOLIS_PACKAGE_BASE}/cpp-${TARGET_GCC_RELEASE}.x86_64.rpm \
    ${ANOLIS_PACKAGE_BASE}/libgcc-${TARGET_GCC_RELEASE}.x86_64.rpm \
    ${ANOLIS_PACKAGE_BASE}/libgomp-${TARGET_GCC_RELEASE}.x86_64.rpm \
    ${ANOLIS_PACKAGE_BASE}/libstdc++-${TARGET_GCC_RELEASE}.x86_64.rpm \
    ${ANOLIS_PACKAGE_BASE}/libstdc++-devel-${TARGET_GCC_RELEASE}.x86_64.rpm \
    && gcc --version \
    && dnf clean all

# --- Step 2: Install kpatch + a CONFIG_CALL_PADDING-capable kpatch-build ---
# The Anolis kpatch-build package rejects valid 16-byte __pfx_ function
# entries from this target kernel.  Keep the vendor runtime package, but use
# the upstream build tools whose prefix-symbol handling generated a module for
# the exact VM-matching baseline.
ARG KPATCH_BUILD_REF=6e58fedec8d04fd5e7963c89eb2f906dba21a949
ENV KPATCH_BUILD_REF=${KPATCH_BUILD_REF}
RUN dnf install -y --setopt=tsflags=nodocs kpatch kpatch-build \
    && mkdir -p /tmp/kpatch-upstream \
    && curl --fail --location --retry 3 --retry-all-errors \
       https://codeload.github.com/dynup/kpatch/tar.gz/${KPATCH_BUILD_REF} \
       -o /tmp/kpatch-upstream.tar.gz \
    && tar -xzf /tmp/kpatch-upstream.tar.gz -C /tmp/kpatch-upstream --strip-components=1 \
    && make -C /tmp/kpatch-upstream/kpatch-build \
    && make -C /tmp/kpatch-upstream/kpatch-build install \
    && make -C /tmp/kpatch-upstream/kmod install \
    && rm -rf /tmp/kpatch-upstream /tmp/kpatch-upstream.tar.gz \
    && dnf clean all

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
RUN sed -i 's/\r$//' /usr/local/bin/docker-entrypoint.sh && \
    chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["test"]
