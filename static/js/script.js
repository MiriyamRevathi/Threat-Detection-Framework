/* ==========================================================================
   AI Cyber Threat Detection Framework — Frontend Interactions
   ========================================================================== */

/* ----------------------------- Upload Page ----------------------------- */

(function initUpload() {
  const fileInput = document.getElementById('fileInput');
  const dropzone = document.getElementById('dropzone');
  const filenameEl = document.getElementById('filename');
  const uploadForm = document.getElementById('uploadForm');
  const analyzeBtn = document.getElementById('analyzeBtn');

  if (!fileInput || !dropzone) return;

  function showFile(file) {
    if (file) {
      filenameEl.textContent = file.name;
      filenameEl.style.color = 'var(--cyan)';
    } else {
      filenameEl.textContent = 'No file selected';
      filenameEl.style.color = '';
    }
  }

  fileInput.addEventListener('change', () => showFile(fileInput.files[0]));

  ['dragenter', 'dragover'].forEach((evt) => {
    dropzone.addEventListener(evt, (e) => {
      e.preventDefault();
      dropzone.classList.add('drag-over');
    });
  });

  ['dragleave', 'drop'].forEach((evt) => {
    dropzone.addEventListener(evt, (e) => {
      e.preventDefault();
      dropzone.classList.remove('drag-over');
    });
  });

  dropzone.addEventListener('drop', (e) => {
    const dropped = e.dataTransfer.files;
    if (dropped && dropped.length) {
      fileInput.files = dropped;
      showFile(dropped[0]);
    }
  });

  if (uploadForm) {
    uploadForm.addEventListener('submit', () => {
      if (fileInput.files.length && analyzeBtn) {
        analyzeBtn.classList.add('loading');
      }
    });
  }
})();

/* --------------------------- Number Counters ---------------------------- */

function animateCounter(el, target, opts = {}) {
  const duration = opts.duration || 1100;
  const decimals = opts.decimals || 0;
  const suffix = opts.suffix || '';
  const start = performance.now();
  const from = 0;

  function tick(now) {
    const progress = Math.min((now - start) / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3);
    const value = from + (target - from) * eased;
    el.textContent = value.toFixed(decimals).replace(/\B(?=(\d{3})+(?!\d))/g, ',') + suffix;
    if (progress < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

document.querySelectorAll('[data-counter]').forEach((el) => {
  const target = parseFloat(el.getAttribute('data-counter'));
  const decimals = parseInt(el.getAttribute('data-decimals') || '0', 10);
  const suffix = el.getAttribute('data-suffix') || '';
  animateCounter(el, target, { decimals, suffix });
});

/* -------------------------------- Gauge ---------------------------------- */

(function initGauge() {
  const arc = document.getElementById('gaugeArc');
  if (!arc) return;
  const radius = parseFloat(arc.getAttribute('r'));
  const circumference = 2 * Math.PI * radius;
  const pct = parseFloat(arc.getAttribute('data-pct')) / 100;

  arc.style.strokeDasharray = `${circumference}`;
  arc.style.strokeDashoffset = `${circumference}`;

  requestAnimationFrame(() => {
    setTimeout(() => {
      arc.style.strokeDashoffset = `${circumference - pct * circumference}`;
    }, 150);
  });
})();

/* --------------------------- Table Search -------------------------------- */

(function initTableSearch() {
  const input = document.getElementById('tableSearch');
  const rows = document.querySelectorAll('.threat-table tbody tr');
  if (!input) return;

  input.addEventListener('input', () => {
    const q = input.value.trim().toLowerCase();
    rows.forEach((row) => {
      const text = row.getAttribute('data-search') || row.textContent.toLowerCase();
      row.style.display = text.toLowerCase().includes(q) ? '' : 'none';
    });
  });
})();

/* ------------------------------ Report Download --------------------------- */

function downloadReport() {
  const data = window.__reportData;
  if (!data) return;

  const lines = [
    'AI CYBER THREAT DETECTION FRAMEWORK — ANALYSIS REPORT',
    '='.repeat(56),
    `File analyzed      : ${data.filename}`,
    `Prediction time     : ${data.prediction_time}s`,
    `Model               : ${data.model_name}`,
    `Model accuracy      : ${data.accuracy}`,
    '',
    `Total records       : ${data.total_records}`,
    `Normal records      : ${data.normal_records}`,
    `Threat records      : ${data.threat_records}`,
    `Threat score        : ${data.threat_score}%`,
    `Risk level          : ${data.risk_level}`,
    '',
    'ATTACK BREAKDOWN',
    '-'.repeat(56),
    ...Object.entries(data.attack_counts).map(
      ([type, count]) => `${type.padEnd(28)} : ${count}`
    ),
  ];

  const blob = new Blob([lines.join('\n')], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `threat_report_${(data.filename || 'scan').replace(/\.[^/.]+$/, '')}.txt`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

/* -------------------------------- Charts ---------------------------------- */

const THREAT_COLOR_MAP = {
  'Normal Traffic': '#22d3a0',
  'DDoS': '#ff4d6a',
  'DoS': '#f2a93b',
  'Port Scanning': '#2e7dff',
  'Bots': '#c084fc',
  'Brute Force': '#ff8a4d',
  'Web Attacks': '#21d4d4',
};
const FALLBACK_PALETTE = ['#2e7dff', '#ff4d6a', '#f2a93b', '#21d4d4', '#22d3a0', '#6ea2ff', '#c084fc'];

function colorForLabel(label, i) {
  return THREAT_COLOR_MAP[label] || FALLBACK_PALETTE[i % FALLBACK_PALETTE.length];
}

function renderCharts(attackCounts) {
  const labels = Object.keys(attackCounts);
  const values = Object.values(attackCounts);
  const colors = labels.map((label, i) => colorForLabel(label, i));

  const gridColor = 'rgba(255,255,255,0.06)';
  const textColor = '#8993ac';

  Chart.defaults.font.family = "'Inter', sans-serif";
  Chart.defaults.color = textColor;

  const doughnutEl = document.getElementById('doughnutChart');
  if (doughnutEl) {
    new Chart(doughnutEl, {
      type: 'doughnut',
      data: {
        labels,
        datasets: [{
          data: values,
          backgroundColor: colors,
          borderColor: '#0a0f1a',
          borderWidth: 3,
          hoverOffset: 6,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '68%',
        plugins: {
          legend: {
            position: 'bottom',
            labels: { boxWidth: 9, boxHeight: 9, usePointStyle: true, padding: 14, font: { size: 11.5 } },
          },
        },
      },
    });
  }

  const barEl = document.getElementById('barChart');
  if (barEl) {
    new Chart(barEl, {
      type: 'bar',
      data: {
        labels,
        datasets: [{
          data: values,
          backgroundColor: colors,
          borderRadius: 6,
          maxBarThickness: 36,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { display: false }, ticks: { font: { size: 10.5 } } },
          y: { grid: { color: gridColor }, ticks: { font: { size: 10.5 } }, beginAtZero: true },
        },
      },
    });
  }
}
