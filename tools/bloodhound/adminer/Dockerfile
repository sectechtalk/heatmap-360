# AD Miner for HeatMap 360's Attack paths page: turns the graph BloodHound CE already holds into a scored HTML risk report.
#
# AD Miner is GPL-3.0 (github.com/AD-Security/AD_Miner). It runs here as its own program in its own container; none of
# its code is part of HeatMap 360, and this image is built locally, never published.
#
# Pinned to the commit of the v1.9.0 release. AD Miner pins its own direct dependencies; constraints.txt pins the rest
# (what "pip freeze" showed for this image), so a rebuild installs the same versions.
#
# Keep Python 3.12 and the neo4j driver 5.x: AD Miner's worker processes rely on "fork" (the default start method up to
# 3.12) and on how driver 5 handles transactions. AD Miner 1.9.0 also only accepts a Neo4j 4.4 server.
#
# Run it with tools/bloodhound/Invoke-ADMinerReport.ps1, never against BloodHound's own database: AD Miner changes and
# deletes data in the database it analyses, so the script gives it a throwaway copy on a network with no way out.
FROM python:3.12-slim
ARG ADMINER_COMMIT=ac3d47319213566e268bee16ae33335705c1b89d
COPY constraints.txt /tmp/constraints.txt
# The build stops when what pip installed is not exactly what constraints.txt pins.
RUN pip install --no-cache-dir -c /tmp/constraints.txt "https://github.com/AD-Security/AD_Miner/archive/${ADMINER_COMMIT}.tar.gz" \
 && pip freeze --exclude AD_Miner | sort > /tmp/installed.txt \
 && grep -v '^#' /tmp/constraints.txt | tr -d '\r' | grep . | sort > /tmp/pinned.txt \
 && diff /tmp/pinned.txt /tmp/installed.txt \
 && useradd --create-home --uid 10001 adminer \
 && mkdir /out && chown adminer /out
USER adminer
WORKDIR /out
ENTRYPOINT ["AD-miner"]
