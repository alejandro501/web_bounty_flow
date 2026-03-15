function escapeCSVCell(value) {
  const text = String(value ?? "");
  if (text.includes(",") || text.includes("\"") || text.includes("\n")) {
    return `"${text.replace(/\"/g, "\"\"")}"`;
  }
  return text;
}

export function rowsToCSV(rows, columns, normalizeValue) {
  const header = columns.map((col) => escapeCSVCell(col)).join(",");
  const body = rows.map((row) => columns.map((col) => escapeCSVCell(normalizeValue(row[col]))).join(","));
  return [header, ...body].join("\n");
}

export function rowsToMarkdown(rows, columns, title = "Export", normalizeValue = (value) => String(value ?? "")) {
  const safeColumns = Array.isArray(columns) ? columns : [];
  const lines = [`# ${title}`, ""];
  if (!safeColumns.length) {
    lines.push("_No rows available._");
    lines.push("");
    return lines.join("\n");
  }
  lines.push(`Generated: ${new Date().toISOString()}`);
  lines.push("");
  lines.push(`| ${safeColumns.map((col) => String(col || "").replace(/\|/g, "\\|")).join(" | ")} |`);
  lines.push(`| ${safeColumns.map(() => "---").join(" | ")} |`);
  for (const row of rows || []) {
    lines.push(`| ${safeColumns.map((col) => normalizeValue(row?.[col]).replace(/\|/g, "\\|").replace(/\n/g, "<br>")).join(" | ")} |`);
  }
  lines.push("");
  return lines.join("\n");
}

export function linesToMarkdown(lines, title = "Export") {
  const body = Array.isArray(lines) && lines.length ? lines.join("\n") : "_No entries available._";
  return `# ${title}\n\nGenerated: ${new Date().toISOString()}\n\n\`\`\`text\n${body}\n\`\`\`\n`;
}

export function downloadTextExport(payload, mime, filename) {
  const blob = new Blob([payload], { type: mime });
  const objectURL = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = objectURL;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(objectURL);
}

export function exportStructuredRows(rows, columns, baseName, requestedFormat, title, normalizeValue = (value) => String(value ?? "")) {
  const format = String(requestedFormat || "csv").trim().toLowerCase();
  let payload = "";
  let mime = "text/plain;charset=utf-8";
  let ext = "txt";
  if (format === "csv") {
    payload = rowsToCSV(rows, columns, normalizeValue);
    mime = "text/csv;charset=utf-8";
    ext = "csv";
  } else if (format === "json") {
    payload = `${JSON.stringify(rows, null, 2)}\n`;
    mime = "application/json;charset=utf-8";
    ext = "json";
  } else if (format === "md") {
    payload = rowsToMarkdown(rows, columns, title, normalizeValue);
    mime = "text/markdown;charset=utf-8";
    ext = "md";
  } else {
    payload = linesToMarkdown(rows.map((row) => columns.map((col) => `${col}: ${normalizeValue(row?.[col])}`).join(" | ")), title);
    mime = "text/markdown;charset=utf-8";
    ext = "md";
  }
  downloadTextExport(payload, mime, `${baseName}.${ext}`);
}
