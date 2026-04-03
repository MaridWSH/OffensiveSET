#!/usr/bin/env node
// Parse all smart contract audit reports and generate a structured catalog
// Usage: node parse-reports.js

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const REPORTS_DIR = path.join(__dirname, '../SmartContract-Reports/Past-Audit-Competitions');
const OUTPUT_FILE = path.join(__dirname, '../SmartContract-Reports/catalog.json');
const SUMMARY_FILE = path.join(__dirname, '../SmartContract-Reports/catalog-summary.md');

// Find all markdown files (excluding README.md and SUMMARY.md)
function findAllReportFiles(dir) {
  const results = [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...findAllReportFiles(fullPath));
    } else if (entry.isFile() && entry.name.endsWith('.md') && 
               entry.name !== 'README.md' && entry.name !== 'SUMMARY.md') {
      results.push(fullPath);
    }
  }
  return results;
}

// Extract the competition name from the directory
function getCompetitionName(filePath) {
  const relative = path.relative(REPORTS_DIR, filePath);
  const parts = relative.split(path.sep);
  return parts[0] || 'unknown';
}

// Parse severity from filename patterns like: 37285-sc-critical-..., 28912 - [SC - Critical]
function parseSeverity(filename) {
  const base = path.basename(filename).toLowerCase();
  if (base.includes('critical') || base.includes('[sc - critical]')) return 'Critical';
  if (base.includes('high') || base.includes('[sc - high]')) return 'High';
  if (base.includes('medium') || base.includes('[sc - medium]')) return 'Medium';
  if (base.includes('low') || base.includes('[sc - low]')) return 'Low';
  if (base.includes('insight') || base.includes('[sc - insight]')) return 'Insight';
  
  // Try parsing from content
  return 'Unknown';
}

// Parse report type from filename (sc, blockchain_dlt, etc.)
function parseReportType(filename) {
  const base = path.basename(filename).toLowerCase();
  if (base.includes('blockchain_dlt') || base.includes('blockchain')) return 'Blockchain/DLT';
  if (base.includes('websites and applications') || base.includes('web')) return 'Web/Application';
  if (base.includes('smart contract') || base.includes('[sc')) return 'Smart Contract';
  return 'Smart Contract'; // default
}

// Extract report ID from filename
function parseReportId(filename) {
  const base = path.basename(filename);
  // Pattern: 37285-sc-critical-... or 28912 - [SC - Critical]
  const match = base.match(/^(\d+)/);
  return match ? match[1] : null;
}

// Extract a short title from filename
function parseTitle(filename) {
  const base = path.basename(filename);
  // Remove ID prefix
  let title = base.replace(/^\d+[-\s]+/, '');
  // Remove severity bracket
  title = title.replace(/\[.*?\]\s*/i, '');
  // Remove .md
  title = title.replace(/\.md$/, '');
  // Convert dashes/hyphens to spaces and clean up
  title = title.replace(/[-_]/g, ' ');
  // Remove extra spaces
  title = title.replace(/\s+/g, ' ').trim();
  // Title case
  title = title.charAt(0).toUpperCase() + title.slice(1);
  return title;
}

// Check if file contains Solidity code or PoC
function hasPocCode(content) {
  const hasSolidity = content.includes('```solidity') || content.includes('```sol');
  const hasForgeTest = content.includes('forge test') || content.includes('function test');
  const hasCodeBlock = content.includes('```') && (hasSolidity || hasForgeTest);
  return hasCodeBlock;
}

// Extract vulnerability category from content
function parseVulnCategory(content, title) {
  const lower = content.toLowerCase();
  const titleLower = title.toLowerCase();
  const combined = titleLower + ' ' + lower;
  
  const categories = [];
  
  // DeFi specific
  if (combined.includes('reentranc')) categories.push('Reentrancy');
  if (combined.includes('oracle') || combined.includes('price manipulat')) categories.push('Oracle Manipulation');
  if (combined.includes('flash loan')) categories.push('Flash Loan Exploit');
  if (combined.includes('governance') || combined.includes('voting') || combined.includes('vote')) categories.push('Governance Attack');
  if (combined.includes('access control') || combined.includes('privilege') || combined.includes('onlyowner') || combined.includes('permission')) categories.push('Access Control');
  if (combined.includes('integer overflow') || combined.includes('underflow') || combined.includes('overflow')) categories.push('Integer Overflow/Underflow');
  if (combined.includes('rounding') || combined.includes('precision') || combined.includes('truncat')) categories.push('Rounding/Precision');
  if (combined.includes('dos') || combined.includes('denial of service') || combined.includes('griefing')) categories.push('DoS/Griefing');
  if (combined.includes('signature') || combined.includes('ecdsa') || combined.includes('malleab')) categories.push('Signature Verification');
  if (combined.includes('cross-chain') || combined.includes('bridge') || combined.includes('message')) categories.push('Cross-Chain/Bridge');
  if (combined.includes('storage collision') || combined.includes('storage overwrite')) categories.push('Storage Collision');
  if (combined.includes('initialization') || combined.includes('initializer') || combined.includes('constructor')) categories.push('Initialization');
  if (combined.includes('proxy') || combined.includes('upgrade') || combined.includes('delegatecall')) categories.push('Proxy/Upgrade');
  if (combined.includes('logic error') || combined.includes('incorrect') || combined.includes('wrong check') || combined.includes('tautolog')) categories.push('Logic Error');
  if (combined.includes('reward') || combined.includes('yield') || combined.includes('incentive') || combined.includes('distribution')) categories.push('Reward/Yield Distribution');
  if (combined.includes('staking') || combined.includes('lock') || combined.includes('vesting')) categories.push('Staking/Locking');
  if (combined.includes('nft') || combined.includes('erc721') || combined.includes('erc1155')) categories.push('NFT');
  if (combined.includes('token') || combined.includes('erc20') || combined.includes('mint') || combined.includes('burn')) categories.push('Token/ERC-20');
  if (combined.includes('lib') || combined.includes('library') || combined.includes('math') || combined.includes('arithmetic')) categories.push('Math Library');
  if (combined.includes('compiler') || combined.includes('optimization') || combined.includes('dead code')) categories.push('Compiler/Optimization');
  if (combined.includes('state') || combined.includes('inconsistent') || combined.includes('transition')) categories.push('State Management');
  if (combined.includes('fee') || combined.includes('slippage')) categories.push('Fee/Slippage');
  if (combined.includes('front-run') || combined.includes('frontrun') || combined.includes('mev') || combined.includes('sandwich')) categories.push('MEV/Front-running');
  if (combined.includes('zero check') || combined.includes('zero address') || combined.includes('validation')) categories.push('Input Validation');
  
  if (categories.length === 0) categories.push('Other');
  
  return categories;
}

// Extract impacts from content
function parseImpacts(content) {
  const lower = content.toLowerCase();
  const impacts = [];
  
  if (lower.includes('loss of fund') || lower.includes('theft') || lower.includes('drain')) impacts.push('Loss of Funds');
  if (lower.includes('governance') || lower.includes('voting result')) impacts.push('Governance Manipulation');
  if (lower.includes('denial of service') || lower.includes('dos') || lower.includes('freeze')) impacts.push('DoS');
  if (lower.includes('data exposure') || lower.includes('information leak')) impacts.push('Information Disclosure');
  if (lower.includes('permanent loss') || lower.includes('locking') || lower.includes('stuck')) impacts.push('Permanent Fund Lock');
  if (lower.includes('manipulat') || lower.includes('control')) impacts.push('Manipulation');
  if (lower.includes('bypass')) impacts.push('Security Bypass');
  
  if (impacts.length === 0) impacts.push('Unspecified');
  
  return impacts;
}

// Parse a single report file
function parseReport(filePath) {
  const content = fs.readFileSync(filePath, 'utf-8');
  const competition = getCompetitionName(filePath);
  const severity = parseSeverity(filePath);
  const reportType = parseReportType(filePath);
  const reportId = parseReportId(filePath);
  const title = parseTitle(filePath);
  const pocPresent = hasPocCode(content);
  const vulnCategories = parseVulnCategory(content, title);
  const impacts = parseImpacts(content);
  
  // Extract brief/intro if present
  let description = '';
  const briefMatch = content.match(/## Brief\/Intro\s*\n([\s\S]*?)(?=##|\n\n##|$)/i);
  if (briefMatch) {
    description = briefMatch[1].trim().slice(0, 500);
  } else {
    // Try to get first paragraph after Description header
    const descMatch = content.match(/## Description\s*\n([\s\S]*?)(?=##|\n\n##|$)/i);
    if (descMatch) {
      description = descMatch[1].trim().slice(0, 500);
    }
  }
  
  // Extract target URL if present
  let target = '';
  const targetMatch = content.match(/\*\*Target\*\*:\s*(.+)/i);
  if (targetMatch) {
    target = targetMatch[1].trim();
  }
  
  return {
    id: reportId,
    title,
    competition,
    severity,
    reportType,
    vulnCategories,
    impacts,
    hasPoc: pocPresent,
    target,
    description: description.slice(0, 300),
    file: path.relative(REPORTS_DIR, filePath),
  };
}

// Main
function main() {
  console.log('Finding report files...');
  const reportFiles = findAllReportFiles(REPORTS_DIR);
  console.log(`Found ${reportFiles.length} report files`);
  
  console.log('Parsing reports...');
  const reports = reportFiles.map(f => parseReport(f));
  
  // Filter out non-smart-contract reports if desired
  const scReports = reports.filter(r => r.reportType === 'Smart Contract');
  const blockchainReports = reports.filter(r => r.reportType === 'Blockchain/DLT');
  const webReports = reports.filter(r => r.reportType === 'Web/Application');
  
  console.log(`\nBreakdown by report type:`);
  console.log(`  Smart Contract: ${scReports.length}`);
  console.log(`  Blockchain/DLT: ${blockchainReports.length}`);
  console.log(`  Web/Application: ${webReports.length}`);
  console.log(`  Unknown: ${reports.filter(r => r.reportType === 'Smart Contract').length}`);
  
  // Write full catalog
  fs.writeFileSync(OUTPUT_FILE, JSON.stringify(reports, null, 2));
  console.log(`\nFull catalog written to: ${OUTPUT_FILE}`);
  
  // Generate summary statistics
  const severityCounts = {};
  const categoryCounts = {};
  const competitionCounts = {};
  const impactCounts = {};
  let pocCount = 0;
  
  for (const r of reports) {
    severityCounts[r.severity] = (severityCounts[r.severity] || 0) + 1;
    competitionCounts[r.competition] = (competitionCounts[r.competition] || 0) + 1;
    if (r.hasPoc) pocCount++;
    
    for (const impact of r.impacts) {
      impactCounts[impact] = (impactCounts[impact] || 0) + 1;
    }
    for (const cat of r.vulnCategories) {
      categoryCounts[cat] = (categoryCounts[cat] || 0) + 1;
    }
  }
  
  // Sort functions
  const sortByCount = (obj) => Object.entries(obj).sort((a, b) => b[1] - a[1]);
  
  const summary = `# Smart Contract Security Report Catalog

## Overview

| Metric | Value |
|--------|-------|
| **Total Reports** | ${reports.length} |
| **Smart Contract Reports** | ${scReports.length} |
| **Blockchain/DLT Reports** | ${blockchainReports.length} |
| **Web/Application Reports** | ${webReports.length} |
| **Reports with PoC Code** | ${pocCount} |
| **Audit Competitions** | ${Object.keys(competitionCounts).length} |

## Severity Distribution

| Severity | Count | Percentage |
|----------|-------|------------|
${sortByCount(severityCounts).map(([sev, count]) => `| ${sev} | ${count} | ${((count/reports.length)*100).toFixed(1)}%`).join('\n')}

## Top Vulnerability Categories

| Category | Count |
|----------|-------|
${sortByCount(categoryCounts).slice(0, 30).map(([cat, count]) => `| ${cat} | ${count}`).join('\n')}

## Top Impact Types

| Impact | Count |
|--------|-------|
${sortByCount(impactCounts).map(([imp, count]) => `| ${imp} | ${count}`).join('\n')}

## Reports per Competition

| Competition | Count |
|-------------|-------|
${sortByCount(competitionCounts).map(([comp, count]) => `| ${comp} | ${count}`).join('\n')}

## Key Insights for Dataset Generation

### Most Common Vulnerability Types
${sortByCount(categoryCounts).slice(0, 10).map(([cat, count]) => `- **${cat}** (${count} instances) — prime candidate for scenario templates`).join('\n')}

### High-Severity Patterns (Critical + High)
${(() => {
  const highSev = reports.filter(r => r.severity === 'Critical' || r.severity === 'High');
  const highCats = {};
  for (const r of highSev) {
    for (const cat of r.vulnCategories) {
      highCats[cat] = (highCats[cat] || 0) + 1;
    }
  }
  return sortByCount(highCats).slice(0, 15).map(([cat, count]) => `- **${cat}** (${count} high-severity instances)`).join('\n');
})()}

### Protocols with Most Findings
${sortByCount(competitionCounts).slice(0, 10).map(([comp, count]) => `- **${comp}** (${count} findings) — rich source for multi-phase audit scenarios`).join('\n')}
`;

  fs.writeFileSync(SUMMARY_FILE, summary);
  console.log(`Summary written to: ${SUMMARY_FILE}`);
  
  console.log('\n=== SUMMARY ===');
  console.log(summary);
}

main();
