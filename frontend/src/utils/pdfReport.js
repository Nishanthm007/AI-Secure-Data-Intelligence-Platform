import jsPDF from 'jspdf'
import autoTable from 'jspdf-autotable'

const RISK_RGB = {
  critical: [248, 81, 73],
  high:     [240, 136, 62],
  medium:   [210, 153, 34],
  low:      [63, 185, 80],
}

function riskColor(level) {
  return RISK_RGB[level] || [150, 150, 150]
}

export function downloadReportPDF(result) {
  const {
    summary,
    content_type,
    findings = [],
    risk_score,
    risk_level,
    action,
    insights = [],
  } = result

  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' })
  const pageW = doc.internal.pageSize.getWidth()
  const margin = 15
  let y = margin

  // ── Header bar ──────────────────────────────────────────────────────────────
  doc.setFillColor(13, 17, 23)
  doc.rect(0, 0, pageW, 28, 'F')

  doc.setTextColor(255, 255, 255)
  doc.setFontSize(16)
  doc.setFont('helvetica', 'bold')
  doc.text('AI Secure Data Intelligence Platform', margin, 12)

  doc.setFontSize(9)
  doc.setFont('helvetica', 'normal')
  doc.setTextColor(139, 148, 158)
  doc.text('Security Analysis Report', margin, 20)

  const now = new Date().toLocaleString()
  doc.text(`Generated: ${now}`, pageW - margin, 20, { align: 'right' })

  y = 36

  // ── Risk summary row ─────────────────────────────────────────────────────────
  doc.setFillColor(22, 27, 34)
  doc.roundedRect(margin, y, pageW - margin * 2, 22, 3, 3, 'F')

  // Risk score circle
  const [r, g, b] = riskColor(risk_level)
  doc.setFillColor(r, g, b)
  doc.circle(margin + 14, y + 11, 9, 'F')
  doc.setTextColor(255, 255, 255)
  doc.setFontSize(11)
  doc.setFont('helvetica', 'bold')
  doc.text(String(risk_score), margin + 14, y + 13, { align: 'center' })

  doc.setTextColor(255, 255, 255)
  doc.setFontSize(10)
  doc.setFont('helvetica', 'bold')
  doc.text(risk_level.toUpperCase(), margin + 27, y + 9)

  doc.setFontSize(8)
  doc.setFont('helvetica', 'normal')
  doc.setTextColor(139, 148, 158)
  doc.text(`${findings.length} finding${findings.length !== 1 ? 's' : ''}  ·  ${content_type} input  ·  action: ${action}`, margin + 27, y + 16)

  y += 30

  // ── Summary ──────────────────────────────────────────────────────────────────
  doc.setFontSize(11)
  doc.setFont('helvetica', 'bold')
  doc.setTextColor(201, 209, 217)
  doc.text('Summary', margin, y)
  y += 5

  doc.setFontSize(9)
  doc.setFont('helvetica', 'normal')
  doc.setTextColor(139, 148, 158)
  const summaryLines = doc.splitTextToSize(summary || 'No summary available.', pageW - margin * 2)
  doc.text(summaryLines, margin, y)
  y += summaryLines.length * 5 + 6

  // ── Findings table ───────────────────────────────────────────────────────────
  doc.setFontSize(11)
  doc.setFont('helvetica', 'bold')
  doc.setTextColor(201, 209, 217)
  doc.text('Findings', margin, y)
  y += 4

  if (findings.length === 0) {
    doc.setFontSize(9)
    doc.setFont('helvetica', 'normal')
    doc.setTextColor(139, 148, 158)
    doc.text('No findings detected.', margin, y + 5)
    y += 12
  } else {
    autoTable(doc, {
      startY: y,
      margin: { left: margin, right: margin },
      head: [['#', 'Type', 'Risk', 'Line', 'Context']],
      body: findings.map((f, i) => [
        i + 1,
        f.type.replace(/_/g, ' '),
        f.risk.toUpperCase(),
        f.line || '—',
        f.context ? f.context.slice(0, 60) + (f.context.length > 60 ? '…' : '') : '—',
      ]),
      styles: {
        fontSize: 8,
        cellPadding: 3,
        textColor: [201, 209, 217],
        fillColor: [22, 27, 34],
        lineColor: [48, 54, 61],
        lineWidth: 0.2,
      },
      headStyles: {
        fillColor: [33, 38, 45],
        textColor: [139, 148, 158],
        fontStyle: 'bold',
        fontSize: 8,
      },
      alternateRowStyles: { fillColor: [13, 17, 23] },
      didParseCell(data) {
        if (data.column.index === 2 && data.section === 'body') {
          const val = String(data.cell.raw).toLowerCase()
          const [cr, cg, cb] = riskColor(val)
          data.cell.styles.textColor = [cr, cg, cb]
          data.cell.styles.fontStyle = 'bold'
        }
      },
      columnStyles: {
        0: { cellWidth: 8 },
        1: { cellWidth: 32 },
        2: { cellWidth: 22 },
        3: { cellWidth: 14 },
        4: { cellWidth: 'auto' },
      },
    })
    y = doc.lastAutoTable.finalY + 8
  }

  // ── AI Insights ──────────────────────────────────────────────────────────────
  if (insights.length > 0) {
    // Check if we need a new page
    if (y > 240) { doc.addPage(); y = margin }

    doc.setFontSize(11)
    doc.setFont('helvetica', 'bold')
    doc.setTextColor(201, 209, 217)
    doc.text('AI-Powered Security Insights', margin, y)
    y += 6

    insights.forEach((insight, idx) => {
      if (y > 270) { doc.addPage(); y = margin }
      const bullet = `${idx + 1}.`
      doc.setFontSize(8)
      doc.setFont('helvetica', 'bold')
      doc.setTextColor(88, 166, 255)
      doc.text(bullet, margin, y)

      doc.setFont('helvetica', 'normal')
      doc.setTextColor(139, 148, 158)
      const lines = doc.splitTextToSize(insight, pageW - margin * 2 - 8)
      doc.text(lines, margin + 6, y)
      y += lines.length * 5 + 2
    })
  }

  // ── Footer ───────────────────────────────────────────────────────────────────
  const totalPages = doc.internal.getNumberOfPages()
  for (let p = 1; p <= totalPages; p++) {
    doc.setPage(p)
    doc.setFontSize(7)
    doc.setTextColor(48, 54, 61)
    doc.text(
      `AI Secure Data Intelligence Platform  ·  Page ${p} of ${totalPages}`,
      pageW / 2,
      doc.internal.pageSize.getHeight() - 8,
      { align: 'center' }
    )
  }

  const filename = `security-report-${new Date().toISOString().slice(0, 10)}.pdf`
  doc.save(filename)
}
