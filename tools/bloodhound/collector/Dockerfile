# Container collector for BloodHound CE: dirkjanm/bloodhound.py (PyPI package bloodhound-ce), pinned.
# Runs read-only LDAP queries against the domain and writes a zip of JSON files to /out. Nothing is installed on a domain machine.
#
# Domains that require LDAP signing (the Windows Server 2025 default) refuse bloodhound.py's plain NTLM bind, and its
# fallback, LDAPS, only works when the domain controller has a certificate. So the image swaps ldap3 for its fork
# ldap3-bleeding-edge (the one bloodhound.py itself points to for channel binding), which can sign and seal NTLM, and turns
# sealing on for the plain LDAP bind. The build fails if that change no longer applies.
FROM python:3.12-slim
RUN pip install --no-cache-dir bloodhound-ce==1.9.1 \
 && pip uninstall -y ldap3 \
 && pip install --no-cache-dir --no-deps ldap3-bleeding-edge==2.10.1.1338 \
 && f=/usr/local/lib/python3.12/site-packages/bloodhound/ad/authentication.py \
 && sed -i 's/authentication=NTLM, receive_timeout=60, auto_range=True)/authentication=NTLM, receive_timeout=60, auto_range=True, session_security="ENCRYPT")/g' "$f" \
 && test "$(grep -c 'session_security="ENCRYPT"' "$f")" = 2 \
 && useradd --create-home --uid 10001 collector \
 && mkdir /out && chown collector /out
USER collector
WORKDIR /out
ENTRYPOINT ["bloodhound-ce-python"]

