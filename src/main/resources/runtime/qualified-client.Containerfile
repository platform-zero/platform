# SOURCE RECIPE ONLY. Do not build, pull, acquire, install or execute in this run.
# TOOLCHAIN_BASE must be a separately acquired/reviewed immutable linux/amd64 image
# @sha256:<real manifest> containing real Chromium, NSS certutil, Java21/keytool,
# Python3, Android emulator/platform/build tools and API34+API36 x86_64 system images.
# No tag, network installer, unverified APK, generic browser process or dummy holder.
ARG TOOLCHAIN_BASE
FROM ${TOOLCHAIN_BASE}
ARG ENTRY_SHA256
ARG CHROMIUM_SHA256
ARG CERTUTIL_SHA256
ARG JAVA_SHA256
ARG KEYTOOL_SHA256
ARG ADB_SHA256
ARG APKSIGNER_SHA256
ARG EMULATOR_SHA256
ARG API34_SYSTEM_SHA256
ARG API36_SYSTEM_SHA256
# Only a reviewed, signed haiwen/seafile v9.0.15 binary/ELF/Python closure.
# Producer signer, signature, closure JSON and exact tool bytes are image inputs; no
# download, pip, apt or unpinned native program is permitted in this recipe.
ARG SEAF_CLI_SHA256
ARG SEAF_DAEMON_SHA256
ARG SEAFILE_INIT_SHA256
ARG SEAFILE_RPC_SHA256
ARG PYSEARPC_INIT_SHA256
ARG SEAF_CLOSURE_SHA256
ARG SEAF_PRODUCER_KEY_SHA256
ARG SEAF_PRODUCER_SIGNATURE_SHA256
ARG OPENSSL_SHA256
COPY --chown=1000:1000 qualified-client-entry.py /opt/p0v3/qualified-client-entry.py
RUN python3 - <<'PY'
import hashlib, os, re
pins = {
    'ENTRY_SHA256': '/opt/p0v3/qualified-client-entry.py',
    'CHROMIUM_SHA256': '/mnt/media/p0-v3/cache/ms-playwright/chromium-1187/chrome-linux/chrome',
    'CERTUTIL_SHA256': '/opt/qualified-tools/bin/certutil',
    'JAVA_SHA256': '/opt/qualified-tools/bin/java',
    'KEYTOOL_SHA256': '/opt/qualified-tools/bin/keytool',
    'ADB_SHA256': '/opt/android-sdk/platform-tools/adb',
    'APKSIGNER_SHA256': '/opt/android-sdk/build-tools/36.0.0/apksigner',
    'EMULATOR_SHA256': '/opt/android-sdk/emulator/emulator',
    'API34_SYSTEM_SHA256': '/opt/android-sdk/system-images/android-34/google_apis/x86_64/system.img',
    'API36_SYSTEM_SHA256': '/opt/android-sdk/system-images/android-36/google_apis/x86_64/system.img',
    'SEAF_CLI_SHA256': '/opt/qualified-tools/seafile-v9.0.15/app/seaf-cli',
    'SEAF_DAEMON_SHA256': '/opt/qualified-tools/seafile-v9.0.15/bin/seaf-daemon',
    'SEAFILE_INIT_SHA256': '/opt/qualified-tools/seafile-v9.0.15/python/seafile/__init__.py',
    'SEAFILE_RPC_SHA256': '/opt/qualified-tools/seafile-v9.0.15/python/seafile/rpcclient.py',
    'PYSEARPC_INIT_SHA256': '/opt/qualified-tools/seafile-v9.0.15/python/pysearpc/__init__.py',
    'SEAF_CLOSURE_SHA256': '/opt/qualified-tools/seafile-v9.0.15/signed-producer-closure.json',
    'SEAF_PRODUCER_KEY_SHA256': '/opt/qualified-tools/seafile-v9.0.15/signed-producer-key.pem',
    'SEAF_PRODUCER_SIGNATURE_SHA256': '/opt/qualified-tools/seafile-v9.0.15/signed-producer-closure.sig',
    'OPENSSL_SHA256': '/usr/bin/openssl',
}
for name, path in pins.items():
    expected = os.environ.get(name)
    if not expected or not re.fullmatch('[a-f0-9]{64}', expected):
        raise SystemExit('Missing verified tool pin: ' + name)
    with open(path, 'rb') as source:
        digest = hashlib.file_digest(source, 'sha256').hexdigest()
    if digest != expected:
        raise SystemExit('Tool source differs from acquired pin: ' + name)
for api in (34, 36):
    for role in ('', '-reader'):
        name = f'p0v3-api{api}{role}'
        path = f'/opt/android-avd/{name}.avd/config.ini'
        with open(path, encoding='ascii') as source:
            config = source.read()
        if 'image.sysdir.1=system-images/android-' + str(api) + '/google_apis/x86_64/' not in config:
            raise SystemExit('Wrong official Android system image/AVD: ' + name)
PY
ENV ANDROID_HOME=/opt/android-sdk ANDROID_SDK_ROOT=/opt/android-sdk \
    ANDROID_AVD_HOME=/opt/android-avd JAVA_HOME=/opt/qualified-tools \
    HOME=/tmp XDG_RUNTIME_DIR=/tmp
USER 1000:1000
WORKDIR /opt/p0v3/acceptance
ENTRYPOINT ["/usr/bin/python3", "/opt/p0v3/qualified-client-entry.py"]
