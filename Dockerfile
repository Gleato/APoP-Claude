# AGENT COOKIE CRUMB: Production container for CLNP verification server.
# Node 20 slim (no dev tools). Non-root user (clnp). Persistent volume
# at /data for session JSONL. Health check hits /api/health every 30s.
# Zero external dependencies — just copies the JS/HTML files directly.

FROM node:20-slim

# Create non-root user for security
RUN groupadd -r clnp && useradd -r -g clnp -m clnp

WORKDIR /app

# Copy only what the server needs — no dev files, no .git
COPY server.js analysis.js clnp-embed.js clnp-probe.html clnp-embed-demo.html clnp-admin.html ./

# Data directory for persistent volume (Fly.io mounts here)
RUN mkdir -p /data && chown clnp:clnp /data

USER clnp

ENV PORT=8080 HOST=0.0.0.0 CLNP_DATA_DIR=/data

EXPOSE 8080

# Health check: verify server responds with { ok: true }
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "const h=require('http');h.get('http://localhost:8080/api/health',r=>{let d='';r.on('data',c=>d+=c);r.on('end',()=>process.exit(JSON.parse(d).ok?0:1))}).on('error',()=>process.exit(1))"

CMD ["node", "server.js"]
