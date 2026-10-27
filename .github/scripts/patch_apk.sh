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
import java.security.cert.CertificateException;
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

    public static void checkCompromised(byte[][] certChainBytes) throws CertificateException {
        if (certChainBytes == null) return;
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
                        throw new CertificateException("Compromised eMudhra intermediate CA rejected (Bugzilla #2083449): " + spkiHex);
                    }
                }
            }
        } catch (CertificateException e) {
            throw e;
        } catch (Throwable ignored) {
        }
    }
}
EOF

javac -source 8 -target 8 -d . EMudhraPinChecker.java
mkdir -p d8_out
$ANDROID_HOME/build-tools/34.0.0/d8 org/chromium/net/EMudhraPinChecker.class --output d8_out

echo "Downloading baksmali..."
curl -sSL -o baksmali.jar https://bitbucket.org/JesusFreke/smali/downloads/baksmali-2.5.2.jar || curl -sSL -o baksmali.jar https://repo1.maven.org/maven2/org/smali/baksmali/2.5.2/baksmali-2.5.2.jar
java -jar baksmali.jar d d8_out/classes.dex -o d8_smali

echo "=== Step 5: Finding X509 verification class and injecting hook ==="
python3 - << 'PYEOF'
import os
import re
import shutil

target_file = None
# Scan all smali files to locate the class containing cr_X509Util or checkServerTrusted
for root, dirs, files in os.walk("apk_unpacked"):
    for file in files:
        if file.endswith(".smali"):
            path = os.path.join(root, file)
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    if "cr_X509Util" in content or "checkServerTrusted([[B" in content or "checkServerTrusted" in content:
                        if "AndroidCertVerifyResult" in content:
                            target_file = path
                            print(f"Matched target verification smali file: {target_file}")
                            break
            except Exception as e:
                pass
    if target_file:
        break

if not target_file:
    raise Exception("Certificate verification smali file not found in apk_unpacked!")

dest_dir = os.path.join("apk_unpacked", "smali", "org", "chromium", "net")
os.makedirs(dest_dir, exist_ok=True)
for root, dirs, files in os.walk("d8_smali"):
    for file in files:
        if file.startswith("EMudhraPinChecker"):
            src = os.path.join(root, file)
            dst = os.path.join(dest_dir, file)
            shutil.copy(src, dst)
            print(f"Copied {src} -> {dst}")

with open(target_file, "r", encoding="utf-8") as f:
    lines = f.readlines()

out_lines = []
in_target_method = False
hook_injected = False
hook = "    invoke-static {p0}, Lorg/chromium/net/EMudhraPinChecker;->checkCompromised([[B)V\n"

for line in lines:
    out_lines.append(line)
    # Match any method taking [[B (cert chain) and returning AndroidCertVerifyResult or checkServerTrusted
    if re.search(r'\.method.*(checkServerTrusted|\([[BLjava/lang/String;).*AndroidCertVerifyResult;', line):
        in_target_method = True
        print(f"Found target method signature: {line.strip()}")
    elif in_target_method and not hook_injected and (".locals" in line or ".registers" in line):
        out_lines.append(hook)
        hook_injected = True
        in_target_method = False

if not hook_injected:
    raise Exception(f"Failed to inject hook into target method in {target_file}!")

with open(target_file, "w", encoding="utf-8") as f:
    f.writelines(out_lines)

print("Successfully injected eMudhra revocation hook into smali!")
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
