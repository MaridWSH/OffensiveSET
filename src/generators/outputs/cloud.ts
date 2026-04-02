// Cloud-related tool output generators

import type { OutputContext, TargetProfile } from "./helpers.js";

export function generateS3Output(ctx: OutputContext, domain: string, targetProfile: TargetProfile): string {
  const bucketName = domain.replace(/\./g, "-") + ctx.rng.pick(["-assets", "-uploads", "-static", "-backup", "-data", "-public"]);

  if (ctx.rng.bool(0.25)) {
    return `<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>`;
  }

  const files = ctx.rng.pickN([
    "config/app.env", ".env", "backup/db-dump.sql.gz", "uploads/", "logs/",
    "config/settings.json", ".git/config", "backup/users.csv", "terraform/",
    "docker-compose.yml", "config/database.yml", ".aws/credentials",
    "private/keys/", "ssl/server.key", "config/secrets.json",
  ], ctx.rng.int(3, 10));

  let output = `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">\n  <Name>${bucketName}</Name>\n  <Contents>\n`;
  for (const file of files) {
    output += `    <Key>${file}</Key>\n    <Size>${ctx.rng.int(100, 50000000)}</Size>\n    <LastModified>${ctx.generateDate()}</LastModified>\n`;
  }
  output += `  </Contents>\n</ListBucketResult>`;
  return output;
}

export function generateEnvFileOutput(ctx: OutputContext, targetProfile: TargetProfile): string {
  const vars: string[] = [];
  if (ctx.rng.bool(0.7)) vars.push(`DB_HOST=${ctx.rng.pick(["rds-prod", "db-master", "psql-01", "mysql-primary"])}.${ctx.rng.pick(["internal", "corp.local", "us-east-1.rds.amazonaws.com"])}`);
  if (ctx.rng.bool(0.7)) vars.push(`DB_PASSWORD=${ctx.rng.pick(["Pr0d_DB_P@ss!", "dbpass_2024!", "Ch@ng3M3N0w", "r00tdb#secure", ctx.generateHex(16)])}`);
  if (ctx.rng.bool(0.6)) vars.push(`AWS_ACCESS_KEY_ID=AKIA${ctx.generateAlphanumeric(16).toUpperCase()}`);
  if (ctx.rng.bool(0.6)) vars.push(`AWS_SECRET_ACCESS_KEY=${ctx.generateBase64(30)}`);
  if (ctx.rng.bool(0.5)) vars.push(`JWT_SECRET=${ctx.rng.pick(["super-secret-jwt-2024", ctx.generateHex(32), "changeme123", "jwt_s3cr3t_k3y!"])}`);
  if (ctx.rng.bool(0.5)) vars.push(`STRIPE_SECRET_KEY=sk_live_${ctx.generateAlphanumeric(24)}`);
  if (ctx.rng.bool(0.4)) vars.push(`REDIS_URL=redis://:${ctx.rng.pick(["r3d1s_pass", ctx.generateHex(12)])}@${ctx.rng.pick(["cache.internal", "redis-01.corp.local"])}:6379/0`);
  if (ctx.rng.bool(0.3)) vars.push(`SMTP_PASSWORD=${ctx.rng.pick(["mailpass123", ctx.generateAlphanumeric(12)])}`);
  if (ctx.rng.bool(0.3)) vars.push(`API_KEY=${ctx.generateHex(32)}`);
  if (ctx.rng.bool(0.3)) vars.push(`SENTRY_DSN=https://${ctx.generateHex(16)}@sentry.io/${ctx.rng.int(100000, 999999)}`);
  return vars.join("\n");
}
