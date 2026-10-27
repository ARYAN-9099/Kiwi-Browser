#!/usr/bin/env bash
set -e

echo "=== Step 1: Installing dependencies ==="
sudo apt-get update
sudo apt-get install -y zipalign apksigner curl jq

echo "Installing apktool..."
sudo curl -sSL -o /usr/local/bin/apktool.jar https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.3.jar
printf '#!/bin/bash\nexec java -jar /usr/local/bin/apktool.jar "$@"\n' | sudo tee /usr/local/bin/apktool > /dev/null
sudo chmod +x /usr/local/bin/apktool
apktool --version

echo "=== Step 2: Downloading official Kiwi Dev ARM64 APK ==="
curl -L -o base.apk "https://github.com/kiwibrowser/src.next/releases/download/14310011181/com.kiwibrowser.browser.dev-arm64-14310011181-github.apk"
ls -lh base.apk

echo "=== Step 3: Disassembling APK ==="
apktool d -f base.apk -o apk_unpacked

echo "=== Step 4: Compiling EMudhraPinChecker ==="
cat << 'EOF' > EMudhraPinChecker.java
package org.chromium.net;

import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class EMudhraPinChecker {
    private static final String[] BLOCKED_SPKI_HEX = {
        "43bffa19d6ef651451f6841e019931e96f6f2eaeff28ab4b6f1ce4576de2717b",
        "49dd353dc2b919a3770645117d0e60c16115e7d1bc259eefe734b00ea434fe5f",
        "5c0660a2b164910d8ff589c18e14552e9e0ec237dcefe2cb736d41a4811f81a0",
        "63ecefee431d49523bc1136c4e72d0206a477086caf606cd5cf025686c109cf8",
        "92c063d67e8f14db71d288e11266ffdaf69cbf115f7bab14f3bc2f68d25e0e30",
        "e0254c7fcdc265e2f0f8a428dabb75ab4ae039b4872d62f5ee57f0877d5a8a41",
        "ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105",
        "ec4ffa1ad0ac88081314b7aaffef6a91f97cd57291bb5ba686c5415f5eb4f6b6"
    };

    public static boolean isCompromised(byte[][] certChainBytes) {
        if (certChainBytes == null) return false;
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            for (byte[] bytes : certChainBytes) {
                if (bytes == null || bytes.length == 0) continue;
                X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(bytes));
                byte[] spki = cert.getPublicKey().getEncoded();
                byte[] digest = md.digest(spki);
                StringBuilder sb = new StringBuilder();
                for (byte b : digest) {
                    sb.append(String.format("%02x", b));
                }
                String spkiHex = sb.toString();
                for (String blocked : BLOCKED_SPKI_HEX) {
                    if (blocked.equalsIgnoreCase(spkiHex)) {
                        return true;
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return false;
    }
}
EOF

javac -source 8 -target 8 -d . EMudhraPinChecker.java
$ANDROID_HOME/build-tools/34.0.0/d8 org/chromium/net/EMudhraPinChecker.class --output d8_out
curl -sSL -o baksmali.jar https://repo1.maven.org/maven2/org/smali/baksmali/2.5.2/baksmali-2.5.2.jar
java -jar baksmali.jar d d8_out/classes.dex -o d8_smali
mkdir -p apk_unpacked/smali/org/chromium/net/
cp -r d8_smali/org/chromium/net/EMudhraPinChecker* apk_unpacked/smali/org/chromium/net/

echo "=== Step 5: Injecting hook into X509Util.smali ==="
python3 - << 'PYEOF'
import os

target_file = None
for root, dirs, files in os.walk("apk_unpacked"):
    if "X509Util.smali" in files:
        target_file = os.path.join(root, "X509Util.smali")
        break

if not target_file:
    raise Exception("X509Util.smali not found!")

print(f"Found target file: {target_file}")
with open(target_file, "r") as f:
    lines = f.readlines()

out_lines = []
in_check_server_trusted = False
hook_injected = False

hook = """
    invoke-static {p0}, Lorg/chromium/net/EMudhraPinChecker;->isCompromised([[B)Z
    move-result v0
    if-eqz v0, :cond_emudhra_safe
    new-instance v0, Ljava/security/cert/CertificateException;
    const-string v1, "Compromised eMudhra intermediate CA rejected (Bugzilla 2083449)"
    invoke-direct {v0, v1}, Ljava/security/cert/CertificateException;-><init>(Ljava/lang/String;)V
    throw v0
    :cond_emudhra_safe
"""

for line in lines:
    out_lines.append(line)
    if "checkServerTrusted([[BLjava/lang/String;Ljava/lang/String;)" in line:
        in_check_server_trusted = True
    elif in_check_server_trusted and not hook_injected and (".locals" in line or ".registers" in line):
        out_lines.append(hook)
        hook_injected = True
        in_check_server_trusted = False

if not hook_injected:
    raise Exception("Failed to inject hook into checkServerTrusted!")

with open(target_file, "w") as f:
    f.writelines(out_lines)

print("Successfully injected eMudhra revocation hook into X509Util.smali!")
PYEOF

echo "=== Step 6: Repacking and Signing APK ==="
apktool b apk_unpacked -o unaligned.apk
zipalign -p -f -v 4 unaligned.apk kiwi-browser-dev-arm64-patched.apk

keytool -genkey -v -keystore debug.keystore -storepass android -alias androiddebugkey -keypass android -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=Android Debug,O=Android,C=US"
apksigner sign --ks debug.keystore --ks-pass pass:android --key-pass pass:android kiwi-browser-dev-arm64-patched.apk
apksigner verify kiwi-browser-dev-arm64-patched.apk

ls -lh kiwi-browser-dev-arm64-patched.apk

echo "=== Step 7: Publishing Release to GitHub Releases ==="
TAG="v105.0.5195.33-emudhra-patch"
gh release delete "$TAG" --yes || true
git tag -d "$TAG" || true

gh release create "$TAG" kiwi-browser-dev-arm64-patched.apk \
  --title "Kiwi Browser Dev ARM64 - eMudhra Compromise Security Patch" \
  --notes "## Kiwi Browser Security Patch: eMudhra Intermediate CA Revocation (Bugzilla #2083449)

This patched Kiwi Browser Dev build blocks all 8 compromised eMudhra intermediate TLS CA keys (and Sectigo AAA cross-signed variants) from the October 2026 security incident.

### Test Instructions
1. Download the attached \`kiwi-browser-dev-arm64-patched.apk\` to your Android phone.
2. Install it (installs alongside existing Kiwi as \`com.kiwibrowser.browser.dev\`).
3. Open the browser and visit the incident test matrix:
   **https://emudhra.we-have-a-problem.com/**
4. Confirm that all compromised intermediate tests are blocked with an SSL Certificate Error, while normal websites load without issue."

echo "=== Done! Release published successfully! ==="
